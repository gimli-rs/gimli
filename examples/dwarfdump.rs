extern crate gimli;
extern crate getopts;
extern crate memmap;
extern crate object;

use object::Object;
use std::cell::Cell;
use std::env;
use std::io;
use std::io::Write;
use std::fs;
use std::process;

#[derive(Default)]
struct Flags {
    info: bool,
    line: bool,
    aranges: bool,
}

fn print_usage(opts: &getopts::Options) -> ! {
    let brief = format!("Usage: {} <options> <file>", env::args().next().unwrap());
    write!(&mut io::stderr(), "{}", opts.usage(&brief)).ok();
    process::exit(1);
}

fn main() {
    let mut opts = getopts::Options::new();
    opts.optflag("i", "", "print .debug_info and .debug_types sections");
    opts.optflag("l", "", "print .debug_line section");
    opts.optflag("r", "", "print .debug_aranges section");

    let matches = match opts.parse(env::args().skip(1)) {
        Ok(m) => m,
        Err(e) => {
            writeln!(&mut io::stderr(), "{:?}\n", e).ok();
            print_usage(&opts);
        }
    };
    if matches.free.is_empty() {
        print_usage(&opts);
    }

    let mut all = true;
    let mut flags = Flags::default();
    if matches.opt_present("i") {
        flags.info = true;
        all = false;
    }
    if matches.opt_present("l") {
        flags.line = true;
        all = false;
    }
    if matches.opt_present("r") {
        flags.aranges = true;
        all = false;
    }
    if all {
        flags.info = true;
        flags.line = true;
        flags.aranges = true;
    }

    for file_path in matches.free {
        println!("{}", file_path);
        println!("");

        let file = fs::File::open(&file_path).expect("Should open file");
        let file = memmap::Mmap::open(&file, memmap::Protection::Read)
            .expect("Should create a mmap for file");
        let file = object::File::parse(unsafe { file.as_slice() });

        if file.is_little_endian() {
            dump_file::<gimli::LittleEndian>(file, &flags);
        } else {
            dump_file::<gimli::BigEndian>(file, &flags);
        }
    }
}

fn dump_file<Endian>(file: object::File, flags: &Flags)
    where Endian: gimli::Endianity
{
    let debug_abbrev = file.get_section(".debug_abbrev").unwrap_or(&[]);
    let debug_abbrev = gimli::DebugAbbrev::<Endian>::new(debug_abbrev);
    let debug_str = file.get_section(".debug_str").unwrap_or(&[]);
    let debug_str = gimli::DebugStr::<Endian>::new(debug_str);

    if flags.info {
        dump_info(&file, debug_abbrev, debug_str);
        dump_types(&file, debug_abbrev, debug_str);
    }
    if flags.line {
        dump_line(&file, debug_abbrev);
    }
    if flags.aranges {
        dump_aranges::<Endian>(&file);
    }
}

fn dump_info<Endian>(file: &object::File,
                     debug_abbrev: gimli::DebugAbbrev<Endian>,
                     debug_str: gimli::DebugStr<Endian>)
    where Endian: gimli::Endianity
{
    if let Some(debug_info) = file.get_section(".debug_info") {
        println!(".debug_info");
        println!("");

        let debug_info = gimli::DebugInfo::<Endian>::new(&debug_info);

        let mut iter = debug_info.units();
        while let Some(unit) = iter.next().expect("Should parse compilation unit") {
            let abbrevs = unit.abbreviations(debug_abbrev)
                .expect("Error parsing abbreviations");

            dump_entries(unit.entries(&abbrevs), debug_str);
        }
    }
}

fn dump_types<Endian>(file: &object::File,
                      debug_abbrev: gimli::DebugAbbrev<Endian>,
                      debug_str: gimli::DebugStr<Endian>)
    where Endian: gimli::Endianity
{
    if let Some(debug_types) = file.get_section(".debug_types") {
        println!(".debug_types");
        println!("");

        let debug_types = gimli::DebugTypes::<Endian>::new(&debug_types);

        let mut iter = debug_types.units();
        while let Some(unit) = iter.next().expect("Should parse the unit OK") {
            let abbrevs = unit.abbreviations(debug_abbrev)
                .expect("Error parsing abbreviations");

            dump_entries(unit.entries(&abbrevs), debug_str);
        }
    }
}

fn dump_entries<Endian>(mut entries: gimli::EntriesCursor<Endian>,
                        debug_str: gimli::DebugStr<Endian>)
    where Endian: gimli::Endianity
{
    let depth = Cell::new(0);
    while let Some((delta_depth, entry)) = entries.next_dfs().expect("Should parse next dfs") {
        depth.set(depth.get() + delta_depth);
        let indent = || {
            for _ in 0..(depth.get() as usize) {
                print!("        ");
            }
        };

        indent();
        println!("<{}> <{}>", entry.offset(), entry.tag());

        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next().expect("Should parse attribute OK") {
            indent();
            let mut value = attr.value();
            if let gimli::AttributeValue::DebugStrRef(o) = value {
                let s = debug_str.get_str(o).expect("Should have valid str offset");
                value = gimli::AttributeValue::String(s)
            }
            println!("    {} = {:?}", attr.name(), value);
        }
    }
}

fn dump_line<Endian>(file: &object::File, debug_abbrev: gimli::DebugAbbrev<Endian>)
    where Endian: gimli::Endianity
{
    let debug_line = file.get_section(".debug_line");
    let debug_info = file.get_section(".debug_info");

    if let (Some(debug_line), Some(debug_info)) = (debug_line, debug_info) {
        println!(".debug_line");
        println!("");

        let debug_line = gimli::DebugLine::<Endian>::new(&debug_line);
        let debug_info = gimli::DebugInfo::<Endian>::new(&debug_info);

        let mut iter = debug_info.units();
        while let Some(unit) = iter.next().expect("Should parse unit header OK") {
            let abbrevs = unit.abbreviations(debug_abbrev)
                .expect("Error parsing abbreviations");

            let mut cursor = unit.entries(&abbrevs);
            cursor.next_dfs().expect("Should parse next dfs");

            let root = cursor.current().expect("Should have a root DIE");
            let offset = match root.attr_value(gimli::DW_AT_stmt_list) {
                Some(gimli::AttributeValue::DebugLineRef(offset)) => offset,
                _ => continue,
            };

            let header =
                gimli::LineNumberProgramHeader::new(debug_line, offset, unit.address_size());
            if let Ok(header) = header {
                println!("");
                println!("Offset:                             0x{:x}", offset.0);
                println!("Length:                             {}",
                         header.unit_length());
                println!("DWARF version:                      {}", header.version());
                println!("Prologue length:                    {}",
                         header.header_length());
                println!("Minimum instruction length:         {}",
                         header.minimum_instruction_length());
                println!("Maximum operations per instruction: {}",
                         header.maximum_operations_per_instruction());
                println!("Default is_stmt:                    {}",
                         header.default_is_stmt());
                println!("Line base:                          {}", header.line_base());
                println!("Line range:                         {}",
                         header.line_range());
                println!("Opcode base:                        {}",
                         header.opcode_base());

                println!("");
                println!("Opcodes:");
                for (i, length) in header.standard_opcode_lengths().iter().enumerate() {
                    println!("  Opcode {} as {} args", i + 1, length);
                }

                println!("");
                println!("The Directory Table:");
                for (i, dir) in header.include_directories().iter().enumerate() {
                    println!("  {} {}", i + 1, dir.to_string_lossy());
                }

                println!("");
                println!("The File Name Table");
                println!("  Entry\tDir\tTime\tSize\tName");
                for (i, file) in header.file_names().iter().enumerate() {
                    println!("  {}\t{}\t{}\t{}\t{}",
                             i + 1,
                             file.directory_index(),
                             file.last_modification(),
                             file.length(),
                             file.path_name().to_string_lossy());
                }

                println!("");
                println!("Line Number Statements:");
                let mut opcodes = header.opcodes();
                while let Some(opcode) = opcodes.next_opcode(&header)
                    .expect("Should parse opcode OK") {
                    println!("  {}", opcode);
                }

                println!("");
                println!("Line Number Rows:");
                println!("<pc>        [lno,col]");
                let mut state_machine = gimli::StateMachine::new(header);
                let mut file_index = 0;
                while let Some(row) = state_machine.next_row()
                    .expect("Should parse row OK") {
                    let line = row.line().unwrap_or(0);
                    let column = match row.column() {
                        gimli::ColumnType::Column(column) => column,
                        gimli::ColumnType::LeftEdge => 0,
                    };
                    print!("0x{:08x}  [{:4},{:2}]", row.address(), line, column);
                    if row.is_stmt() {
                        print!(" NS");
                    }
                    if row.basic_block() {
                        print!(" BB");
                    }
                    if row.end_sequence() {
                        print!(" ET");
                    }
                    if row.prologue_end() {
                        print!(" PE");
                    }
                    if row.epilogue_begin() {
                        print!(" EB");
                    }
                    if row.isa() != 0 {
                        print!(" IS={}", row.isa());
                    }
                    if row.discriminator() != 0 {
                        print!(" DI={}", row.discriminator());
                    }
                    if file_index != row.file_index() {
                        file_index = row.file_index();
                        if let Ok(file) = row.file() {
                            if let Some(directory) = file.directory(row.header()) {
                                print!(" uri: \"{}/{}\"",
                                       directory.to_string_lossy(),
                                       file.path_name().to_string_lossy());
                            } else {
                                print!(" uri: \"{}\"", file.path_name().to_string_lossy());
                            }
                        }
                    }
                    println!("");
                }
            }
        }
    }
}

fn dump_aranges<Endian>(file: &object::File)
    where Endian: gimli::Endianity
{
    let debug_aranges = file.get_section(".debug_aranges");
    let debug_info = file.get_section(".debug_info");

    if let (Some(debug_aranges), Some(debug_info)) = (debug_aranges, debug_info) {
        println!(".debug_aranges");
        println!("");

        let debug_aranges = gimli::DebugAranges::<Endian>::new(debug_aranges);
        let debug_info = gimli::DebugInfo::<Endian>::new(debug_info);

        let mut cu_die_offset = gimli::DebugInfoOffset(0);
        let mut prev_cu_offset = None;
        let mut aranges = debug_aranges.items();
        while let Some(arange) = aranges.next().expect("Should parse arange OK") {
            let cu_offset = arange.debug_info_offset();
            if Some(cu_offset) != prev_cu_offset {
                let cu = debug_info.header_from_offset(cu_offset)
                    .expect("Should parse unit header OK");
                cu_die_offset = gimli::DebugInfoOffset(cu_offset.0 + cu.header_size() as u64);
                prev_cu_offset = Some(cu_offset);
            }
            if let Some(segment) = arange.segment() {
                print!("arange starts at seg,off 0x{:08x},0x{:08x}, ",
                       segment,
                       arange.address());
            } else {
                print!("arange starts at 0x{:08x}, ", arange.address());
            }
            println!("length of 0x{:08x}, cu_die_offset = 0x{:08x}",
                     arange.length(),
                     cu_die_offset.0);
        }
    }
}
