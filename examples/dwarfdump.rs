extern crate fallible_iterator;
extern crate gimli;
extern crate getopts;
extern crate memmap;
extern crate object;

use fallible_iterator::FallibleIterator;
use object::Object;
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
    raw: bool,
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
    opts.optflag("", "raw", "print raw data values");

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
    if matches.opt_present("raw") {
        flags.raw = true;
    }
    if all {
        flags.info = true;
        flags.line = true;
        flags.aranges = true;
    }

    for file_path in &matches.free {
        if matches.free.len() != 1 {
            println!("{}", file_path);
            println!("");
        }

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
    let debug_line = file.get_section(".debug_line").unwrap_or(&[]);
    let debug_line = gimli::DebugLine::<Endian>::new(debug_line);
    let debug_loc = file.get_section(".debug_loc").unwrap_or(&[]);
    let debug_loc = gimli::DebugLoc::<Endian>::new(debug_loc);
    let debug_ranges = file.get_section(".debug_ranges").unwrap_or(&[]);
    let debug_ranges = gimli::DebugRanges::<Endian>::new(debug_ranges);
    let debug_str = file.get_section(".debug_str").unwrap_or(&[]);
    let debug_str = gimli::DebugStr::<Endian>::new(debug_str);

    if flags.info {
        dump_info(&file,
                  debug_abbrev,
                  debug_line,
                  debug_loc,
                  debug_ranges,
                  debug_str,
                  flags);
        dump_types(&file,
                   debug_abbrev,
                   debug_line,
                   debug_loc,
                   debug_ranges,
                   debug_str,
                   flags);
        println!("");
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
                     debug_line: gimli::DebugLine<Endian>,
                     debug_loc: gimli::DebugLoc<Endian>,
                     debug_ranges: gimli::DebugRanges<Endian>,
                     debug_str: gimli::DebugStr<Endian>,
                     flags: &Flags)
    where Endian: gimli::Endianity
{
    println!("\n.debug_info");

    if let Some(debug_info) = file.get_section(".debug_info") {
        let debug_info = gimli::DebugInfo::<Endian>::new(&debug_info);

        let mut iter = debug_info.units();
        while let Some(unit) = iter.next().expect("Should parse compilation unit") {
            let abbrevs = unit.abbreviations(debug_abbrev)
                .expect("Error parsing abbreviations");

            dump_entries(unit.offset().0,
                         unit.entries(&abbrevs),
                         unit.address_size(),
                         unit.format(),
                         debug_line,
                         debug_loc,
                         debug_ranges,
                         debug_str,
                         flags);
        }
    }
}

fn dump_types<Endian>(file: &object::File,
                      debug_abbrev: gimli::DebugAbbrev<Endian>,
                      debug_line: gimli::DebugLine<Endian>,
                      debug_loc: gimli::DebugLoc<Endian>,
                      debug_ranges: gimli::DebugRanges<Endian>,
                      debug_str: gimli::DebugStr<Endian>,
                      flags: &Flags)
    where Endian: gimli::Endianity
{
    if let Some(debug_types) = file.get_section(".debug_types") {
        println!("\n.debug_types");

        let debug_types = gimli::DebugTypes::<Endian>::new(&debug_types);

        let mut iter = debug_types.units();
        while let Some(unit) = iter.next().expect("Should parse the unit OK") {
            let abbrevs = unit.abbreviations(debug_abbrev)
                .expect("Error parsing abbreviations");

            println!("\nCU_HEADER:");
            print!("  signature        = ");
            dump_type_signature::<Endian>(unit.type_signature());
            println!("");
            println!("  typeoffset       = 0x{:08x} {}",
                     unit.type_offset().0,
                     unit.type_offset().0);

            dump_entries(unit.offset().0,
                         unit.entries(&abbrevs),
                         unit.address_size(),
                         unit.format(),
                         debug_line,
                         debug_loc,
                         debug_ranges,
                         debug_str,
                         flags);
        }
    }
}

// TODO: most of this should be moved to the main library.
struct Unit<'input, Endian>
    where Endian: gimli::Endianity
{
    format: gimli::Format,
    address_size: u8,
    base_address: u64,
    line_header: Option<gimli::LineNumberProgramHeader<'input, Endian>>,
    comp_dir: Option<&'input std::ffi::CStr>,
    comp_name: Option<&'input std::ffi::CStr>,
}

fn dump_entries<Endian>(offset: usize,
                        mut entries: gimli::EntriesCursor<Endian>,
                        address_size: u8,
                        format: gimli::Format,
                        debug_line: gimli::DebugLine<Endian>,
                        debug_loc: gimli::DebugLoc<Endian>,
                        debug_ranges: gimli::DebugRanges<Endian>,
                        debug_str: gimli::DebugStr<Endian>,
                        flags: &Flags)
    where Endian: gimli::Endianity
{
    let mut unit = Unit {
        format: format,
        address_size: address_size,
        base_address: 0,
        line_header: None,
        comp_dir: None,
        comp_name: None,
    };

    let mut print_local = true;
    let mut depth = 0;
    while let Some((delta_depth, entry)) = entries.next_dfs().expect("Should parse next dfs") {
        depth += delta_depth;
        assert!(depth >= 0);
        let indent = depth as usize * 2 + 2;
        if depth == 0 {
            println!("\nCOMPILE_UNIT<header overall offset = 0x{:08x}>:", offset);
            print_local = true;
        } else if print_local {
            println!("\nLOCAL_SYMBOLS:");
            print_local = false;
        }
        println!("<{:2}><0x{:08x}>{:indent$}{}",
                 depth,
                 entry.offset().0,
                 "",
                 entry.tag(),
                 indent = indent);

        if entry.tag() == gimli::DW_TAG_compile_unit || entry.tag() == gimli::DW_TAG_type_unit {
            unit.base_address = match entry.attr_value(gimli::DW_AT_low_pc) {
                Some(gimli::AttributeValue::Addr(address)) => address,
                _ => 0,
            };
            unit.comp_dir = entry.attr(gimli::DW_AT_comp_dir)
                .and_then(|attr| attr.string_value(&debug_str));
            unit.comp_name = entry.attr(gimli::DW_AT_name)
                .and_then(|attr| attr.string_value(&debug_str));
            unit.line_header = match entry.attr_value(gimli::DW_AT_stmt_list) {
                Some(gimli::AttributeValue::DebugLineRef(offset)) => {
                    debug_line.header(offset, unit.address_size, unit.comp_dir, unit.comp_name).ok()
                }
                _ => None,
            }
        }

        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next().expect("Should parse attribute OK") {
            print!("{:indent$}{:27} ", "", attr.name(), indent = indent + 18);
            if flags.raw {
                println!("{:?}", attr.raw_value());
            } else {
                dump_attr_value(attr, &unit, debug_loc, debug_ranges, debug_str);
            }
        }
    }
}

fn dump_attr_value<Endian>(attr: gimli::Attribute<Endian>,
                           unit: &Unit<Endian>,
                           debug_loc: gimli::DebugLoc<Endian>,
                           debug_ranges: gimli::DebugRanges<Endian>,
                           debug_str: gimli::DebugStr<Endian>)
    where Endian: gimli::Endianity
{
    let value = attr.value();
    match value {
        gimli::AttributeValue::Addr(address) => {
            println!("0x{:08x}", address);
        }
        gimli::AttributeValue::Block(data) => {
            for byte in data.0 {
                print!("{:02x}", byte);
            }
            println!("");
        }
        gimli::AttributeValue::Data(_) => {
            if let (Some(udata), Some(sdata)) = (attr.udata_value(), attr.sdata_value()) {
                if sdata >= 0 {
                    println!("{}", udata);
                } else {
                    println!("{} ({})", udata, sdata);
                }
            } else {
                println!("{:?}", value);
            }
        }
        gimli::AttributeValue::Sdata(data) => {
            match attr.name() {
                gimli::DW_AT_data_member_location => {
                    println!("{}", data);
                }
                _ => {
                    if data >= 0 {
                        println!("0x{:08x}", data);
                    } else {
                        println!("0x{:08x} ({})", data, data);
                    }
                }
            };
        }
        gimli::AttributeValue::Udata(data) => {
            match attr.name() {
                gimli::DW_AT_high_pc => {
                    println!("<offset-from-lowpc>{}", data);
                }
                gimli::DW_AT_data_member_location => {
                    if let Some(sdata) = attr.sdata_value() {
                        // This is a DW_FORM_data* value.
                        // libdwarf-dwarfdump displays this as signed too.
                        if sdata >= 0 {
                            println!("{}", data);
                        } else {
                            println!("{} ({})", data, sdata);
                        }
                    } else {
                        println!("{}", data);
                    }
                }
                gimli::DW_AT_lower_bound |
                gimli::DW_AT_upper_bound => {
                    println!("{}", data);
                }
                _ => {
                    println!("0x{:08x}", data);
                }
            };
        }
        gimli::AttributeValue::Exprloc(data) => {
            if let gimli::AttributeValue::Exprloc(_) = attr.raw_value() {
                print!("len 0x{:04x}: ", data.len());
                for byte in data.0 {
                    print!("{:02x}", byte);
                }
                print!(": ");
            }
            dump_exprloc(data, unit);
            println!("");
        }
        gimli::AttributeValue::Flag(true) => {
            // We don't record what the value was, so assume 1.
            println!("yes(1)");
        }
        gimli::AttributeValue::Flag(false) => {
            println!("no");
        }
        gimli::AttributeValue::SecOffset(offset) => {
            println!("0x{:08x}", offset);
        }
        gimli::AttributeValue::UnitRef(gimli::UnitOffset(offset)) => {
            println!("<0x{:08x}>", offset);
        }
        gimli::AttributeValue::DebugInfoRef(gimli::DebugInfoOffset(offset)) => {
            println!("<GOFF=0x{:08x}>", offset);
        }
        gimli::AttributeValue::DebugLineRef(gimli::DebugLineOffset(offset)) => {
            println!("0x{:08x}", offset);
        }
        gimli::AttributeValue::DebugLocRef(offset) => {
            dump_loc_list(debug_loc, offset, unit);
        }
        gimli::AttributeValue::DebugMacinfoRef(gimli::DebugMacinfoOffset(offset)) => {
            println!("{}", offset);
        }
        gimli::AttributeValue::DebugRangesRef(offset) => {
            println!("0x{:08x}", offset.0);
            dump_range_list(debug_ranges, offset, unit);
        }
        gimli::AttributeValue::DebugTypesRef(signature) => {
            dump_type_signature::<Endian>(signature);
            println!(" <type signature>");
        }
        gimli::AttributeValue::DebugStrRef(offset) => {
            if let Ok(s) = debug_str.get_str(offset) {
                println!("{}", s.to_string_lossy());
            } else {
                println!("{:?}", value);
            }
        }
        gimli::AttributeValue::String(s) => {
            println!("{}", s.to_string_lossy());
        }
        gimli::AttributeValue::Encoding(value) => {
            println!("{}", value);
        }
        gimli::AttributeValue::DecimalSign(value) => {
            println!("{}", value);
        }
        gimli::AttributeValue::Endianity(value) => {
            println!("{}", value);
        }
        gimli::AttributeValue::Accessibility(value) => {
            println!("{}", value);
        }
        gimli::AttributeValue::Visibility(value) => {
            println!("{}", value);
        }
        gimli::AttributeValue::Virtuality(value) => {
            println!("{}", value);
        }
        gimli::AttributeValue::Language(value) => {
            println!("{}", value);
        }
        gimli::AttributeValue::AddressClass(value) => {
            println!("{}", value);
        }
        gimli::AttributeValue::IdentifierCase(value) => {
            println!("{}", value);
        }
        gimli::AttributeValue::CallingConvention(value) => {
            println!("{}", value);
        }
        gimli::AttributeValue::Inline(value) => {
            println!("{}", value);
        }
        gimli::AttributeValue::Ordering(value) => {
            println!("{}", value);
        }
        gimli::AttributeValue::FileIndex(value) => {
            print!("0x{:08x}", value);
            dump_file_index(value, unit);
            println!("");
        }
    }
}

fn dump_type_signature<Endian>(signature: gimli::DebugTypeSignature)
    where Endian: gimli::Endianity
{
    // Convert back to bytes so we can match libdwarf-dwarfdump output.
    let mut buf = [0; 8];
    Endian::write_u64(&mut buf, signature.0);
    print!("0x");
    for byte in &buf {
        print!("{:02x}", byte);
    }
}

fn dump_file_index<Endian>(file: u64, unit: &Unit<Endian>)
    where Endian: gimli::Endianity
{
    if file == 0 {
        return;
    }
    let header = match unit.line_header {
        Some(ref header) => header,
        None => return,
    };
    let file = header.file(file).expect("File index should be valid");
    print!(" ");
    if let Some(directory) = file.directory(header) {
        let directory = directory.to_string_lossy();
        if !directory.starts_with("/") {
            if let Some(ref comp_dir) = unit.comp_dir {
                print!("{}/", comp_dir.to_string_lossy());
            }
        }
        print!("{}/", directory);
    }
    print!("{}", file.path_name().to_string_lossy());
}

fn dump_exprloc<Endian>(data: gimli::EndianBuf<Endian>, unit: &Unit<Endian>)
    where Endian: gimli::Endianity
{
    let mut pc = data;
    let mut space = false;
    while pc.len() != 0 {
        let dwop = gimli::DwOp(pc[0]);
        match gimli::Operation::parse(pc, data.0, unit.address_size, unit.format) {
            Ok((newpc, op)) => {
                if space {
                    print!(" ");
                } else {
                    space = true;
                }
                dump_op(dwop, op, newpc.0);
                pc = newpc;
            }
            Err(gimli::Error::InvalidExpression(op)) => {
                writeln!(&mut std::io::stderr(),
                         "WARNING: unsupported operation 0x{:02x}",
                         op.0)
                    .unwrap();
                return;
            }
            otherwise => panic!("Unexpected Operation::parse result: {:?}", otherwise),
        }
    }
}

fn dump_op<Endian>(dwop: gimli::DwOp, op: gimli::Operation<Endian>, newpc: &[u8])
    where Endian: gimli::Endianity
{
    print!("{}", dwop);
    match op {
        gimli::Operation::Deref { size, space: _ } => {
            if dwop == gimli::DW_OP_deref_size || dwop == gimli::DW_OP_xderef_size {
                print!(" {}", size);
            }
        }
        gimli::Operation::Pick { index } => {
            if dwop == gimli::DW_OP_pick {
                print!(" {}", index);
            }
        }
        gimli::Operation::PlusConstant { value } => {
            print!(" {}", value as i64);
        }
        gimli::Operation::Bra { target } => {
            let offset = newpc.len() as isize - target.len() as isize;
            print!(" {}", offset);
        }
        gimli::Operation::Skip { target } => {
            let offset = newpc.len() as isize - target.len() as isize;
            print!(" {}", offset);
        }
        gimli::Operation::Literal { value } => {
            match dwop {
                gimli::DW_OP_addr => {
                    print!(" 0x{:08x}", value);
                }
                gimli::DW_OP_const1s |
                gimli::DW_OP_const2s |
                gimli::DW_OP_const4s |
                gimli::DW_OP_const8s |
                gimli::DW_OP_consts => {
                    print!(" {}", value as i64);
                }
                gimli::DW_OP_const1u |
                gimli::DW_OP_const2u |
                gimli::DW_OP_const4u |
                gimli::DW_OP_const8u |
                gimli::DW_OP_constu => {
                    print!(" {}", value);
                }
                _ => {}
            }
        }
        gimli::Operation::Register { register } => {
            if dwop == gimli::DW_OP_regx {
                print!(" {}", register);
            }
        }
        gimli::Operation::RegisterOffset { register: _, offset } => {
            print!("{:+}", offset);
        }
        gimli::Operation::FrameOffset { offset } => {
            print!(" {}", offset);
        }
        gimli::Operation::Call { offset } => {
            match offset {
                gimli::DieReference::UnitRef(gimli::UnitOffset(offset)) => {
                    print!(" 0x{:08x}", offset);
                }
                gimli::DieReference::DebugInfoRef(gimli::DebugInfoOffset(offset)) => {
                    print!(" 0x{:08x}", offset);
                }
            }
        }
        gimli::Operation::Piece { size_in_bits, bit_offset: None } => {
            print!(" {}", size_in_bits / 8);
        }
        gimli::Operation::Piece { size_in_bits, bit_offset: Some(bit_offset) } => {
            print!(" 0x{:08x} offset 0x{:08x}", size_in_bits, bit_offset);
        }
        gimli::Operation::ImplicitValue { data } => {
            print!(" 0x{:08x} contents 0x", data.len());
            for byte in data {
                print!("{:02x}", byte);
            }
        }
        gimli::Operation::ImplicitPointer { value, byte_offset } => {
            print!(" 0x{:08x} {}", value.0, byte_offset);
        }
        gimli::Operation::EntryValue { expression } => {
            print!(" 0x{:08x} contents 0x", expression.len());
            for byte in expression.0 {
                print!("{:02x}", byte);
            }
        }
        _ => {}
    }
}

fn dump_loc_list<Endian>(debug_loc: gimli::DebugLoc<Endian>,
                         offset: gimli::DebugLocOffset,
                         unit: &Unit<Endian>)
    where Endian: gimli::Endianity
{
    let locations = debug_loc.raw_locations(offset, unit.address_size)
        .expect("Should have valid loc offset");
    let mut locations: Vec<_> = locations.collect().expect("Should parse locations");

    // libdwarf-dwarfdump doesn't include the end entry.
    let has_end = if let Some(location) = locations.last() {
        location.range.is_end()
    } else {
        false
    };
    if has_end {
        locations.pop();
    }
    if locations.len() == 0 {
        println!("");
        return;
    }

    println!("<loclist at offset 0x{:08x} with {} entries follows>",
             offset.0,
             locations.len());
    let mut base_address = unit.base_address;
    for (i, location) in locations.iter().enumerate() {
        print!("\t\t\t[{:2}]", i);
        if location.range.is_end() {
            println!("<end-of-list>");
        } else if location.range.is_base_address(unit.address_size) {
            println!("<new base address 0x{:08x}>", location.range.end);
            base_address = location.range.end;
        } else {
            let mut range = location.range;
            range.add_base_address(base_address, unit.address_size);
            // This messed up formatting matches libdwarf-dwarfdump.
            print!("< offset pair \
                    low-off : 0x{:08x} addr  0x{:08x} \
                    high-off  0x{:08x} addr 0x{:08x}>",
                   location.range.begin,
                   range.begin,
                   location.range.end,
                   range.end);
            dump_exprloc(location.data, unit);
            println!("");
        }
    }
}

fn dump_range_list<Endian>(debug_ranges: gimli::DebugRanges<Endian>,
                           offset: gimli::DebugRangesOffset,
                           unit: &Unit<Endian>)
    where Endian: gimli::Endianity
{
    let ranges = debug_ranges.raw_ranges(offset, unit.address_size)
        .expect("Should have valid range offset");
    let ranges: Vec<_> = ranges.collect().expect("Should parse ranges");
    println!("\t\tranges: {} at .debug_ranges offset {} (0x{:08x}) ({} bytes)",
             ranges.len(),
             offset.0,
             offset.0,
             ranges.len() * unit.address_size as usize * 2);
    for (i, range) in ranges.iter().enumerate() {
        print!("\t\t\t[{:2}] ", i);
        if range.is_end() {
            print!("range end     ");
        } else if range.is_base_address(unit.address_size) {
            print!("addr selection");
        } else {
            print!("range entry   ");
        }
        println!(" 0x{:08x} 0x{:08x}", range.begin, range.end);
    }
}

fn dump_line<Endian>(file: &object::File, debug_abbrev: gimli::DebugAbbrev<Endian>)
    where Endian: gimli::Endianity
{
    let debug_line = file.get_section(".debug_line");
    let debug_info = file.get_section(".debug_info");
    let debug_str = file.get_section(".debug_str").unwrap_or(&[]);

    if let (Some(debug_line), Some(debug_info)) = (debug_line, debug_info) {
        println!(".debug_line");
        println!("");

        let debug_line = gimli::DebugLine::<Endian>::new(&debug_line);
        let debug_info = gimli::DebugInfo::<Endian>::new(&debug_info);
        let debug_str = gimli::DebugStr::<Endian>::new(&debug_str);

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
            let comp_dir = root.attr(gimli::DW_AT_comp_dir)
                .and_then(|attr| attr.string_value(&debug_str));
            let comp_name = root.attr(gimli::DW_AT_name)
                .and_then(|attr| attr.string_value(&debug_str));

            let header = debug_line.header(offset, unit.address_size(), comp_dir, comp_name);
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
                let mut rows = header.rows();
                let mut file_index = 0;
                while let Some((header, row)) = rows.next_row()
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
                        if let Some(file) = row.file(header) {
                            if let Some(directory) = file.directory(header) {
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
                cu_die_offset = gimli::DebugInfoOffset(cu_offset.0 + cu.header_size());
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
