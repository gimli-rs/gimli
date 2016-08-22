extern crate gimli;
extern crate memmap;
extern crate object;

use object::Object;
use std::cell::Cell;
use std::env;
use std::fs;

fn main() {
    for file_path in env::args().skip(1) {
        println!("{}", file_path);
        println!("");

        let file = fs::File::open(&file_path).expect("Should open file");
        let file = memmap::Mmap::open(&file, memmap::Protection::Read)
            .expect("Should create a mmap for file");
        let file = object::File::parse(unsafe { file.as_slice() });

        if file.is_little_endian() {
            dump_file::<gimli::LittleEndian>(file);
        } else {
            dump_file::<gimli::BigEndian>(file);
        }
    }
}

fn dump_file<Endian>(file: object::File)
    where Endian: gimli::Endianity
{
    let debug_abbrev = file.get_section(".debug_abbrev").unwrap_or(&[]);
    let debug_abbrev = gimli::DebugAbbrev::<Endian>::new(debug_abbrev);
    let debug_str = file.get_section(".debug_str").unwrap_or(&[]);
    let debug_str = gimli::DebugStr::<Endian>::new(debug_str);

    dump_info(&file, debug_abbrev, debug_str);
    dump_types(&file, debug_abbrev, debug_str);
    dump_line(&file, debug_abbrev);
    dump_aranges::<Endian>(&file);
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

        for unit in debug_info.units() {
            let unit = unit.expect("Should parse the unit OK");

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

        for unit in debug_types.units() {
            let unit = unit.expect("Should parse the unit OK");

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

        for unit in debug_info.units() {
            let unit = unit.expect("Should parse unit header OK");

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
            }
        }
    }
}

fn dump_aranges<Endian>(file: &object::File)
    where Endian: gimli::Endianity
{
    if let Some(debug_aranges) = file.get_section(".debug_aranges") {
        println!(".debug_aranges");
        let debug_aranges = gimli::DebugAranges::<Endian>::new(debug_aranges);

        let mut aranges = debug_aranges.items();
        while let Some(arange) = aranges.next_entry().expect("Should parse arange OK") {
            println!("arange starts at {}, length of {}, cu_die_offset = {:?}",
                     arange.start(),
                     arange.len(),
                     arange.debug_info_offset());
        }
    }
}
