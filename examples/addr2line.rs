extern crate fallible_iterator;
extern crate gimli;
extern crate getopts;
extern crate memmap;
extern crate object;

use fallible_iterator::FallibleIterator;
use object::Object;
use std::env;
use std::fs;

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut opts = getopts::Options::new();
    opts.optopt("e",
                "exe",
                "Set the input file name (default is a.out)",
                "<executable>");

    let matches = opts.parse(&args[1..]).unwrap();

    let file_path = matches.opt_str("e").unwrap_or("a.out".to_string());
    let file = fs::File::open(&file_path).expect("Should open file");
    let file = memmap::Mmap::open(&file, memmap::Protection::Read)
        .expect("Should create a mmap for file");
    let file = object::File::parse(unsafe { file.as_slice() });

    let addrs = matches.free.iter().map(|x| parse_uint_from_hex_string(x)).collect();

    if file.is_little_endian() {
        symbolicate::<gimli::LittleEndian>(&file, addrs);
    } else {
        symbolicate::<gimli::BigEndian>(&file, addrs);
    }
}

fn parse_uint_from_hex_string(string: &str) -> u64 {
    if string.len() > 2 && string.starts_with("0x") {
        u64::from_str_radix(&string[2..], 16).expect("Failed to parse address")
    } else {
        u64::from_str_radix(string, 16).expect("Failed to parse address")
    }
}

fn display_file<Endian>(row: gimli::LineNumberRow<Endian>)
    where Endian: gimli::Endianity
{
    let file = row.file().unwrap();
    if let Some(directory) = file.directory(row.header()) {
        println!("{}/{}:{}",
                 directory.to_string_lossy(),
                 file.path_name().to_string_lossy(),
                 row.line().unwrap());
    } else {
        println!("{}:{}",
                 file.path_name().to_string_lossy(),
                 row.line().unwrap());
    }
}

fn symbolicate<Endian>(file: &object::File, addrs: Vec<u64>)
    where Endian: gimli::Endianity
{
    let debug_info = file.get_section(".debug_info")
        .expect("Can't addr2line without .debug_info");
    let debug_info = gimli::DebugInfo::<Endian>::new(debug_info);
    let debug_abbrev = file.get_section(".debug_abbrev")
        .expect("Can't addr2line without .debug_abbrev");
    let debug_abbrev = gimli::DebugAbbrev::<Endian>::new(debug_abbrev);
    let debug_line = file.get_section(".debug_line")
        .expect("Can't addr2line without .debug_line");
    let debug_line = gimli::DebugLine::<Endian>::new(debug_line);
    let debug_ranges = file.get_section(".debug_ranges").unwrap_or(&[]);
    let debug_ranges = gimli::DebugRanges::<Endian>::new(debug_ranges);

    let mut units = Vec::new();
    let mut headers = debug_info.units();
    while let Some(header) = headers.next().expect("Couldn't get DIE header") {
        if let Some(unit) = Unit::parse(&debug_abbrev, &debug_ranges, &header) {
            units.push(unit);
        }
    }

    for addr in addrs {
        find_address(debug_line, &units, addr);
    }
}

fn find_address<Endian>(debug_line: gimli::DebugLine<Endian>, units: &[Unit], addr: u64)
    where Endian: gimli::Endianity
{
    for unit in units {
        if unit.contains_address(addr) {
            if let Ok(mut lines) = unit.lines(debug_line) {
                if let Ok(Some(row)) = lines.run_to_address(&addr) {
                    display_file(row);
                    return;
                };
            }
        }
    }
    println!("Failed to find matching line for {}", addr);
}

// TODO: most of this should be moved to the main library.
struct Unit {
    address_size: u8,
    ranges: Vec<gimli::Range>,
    line_offset: gimli::DebugLineOffset,
}

impl Unit {
    fn parse<Endian>(debug_abbrev: &gimli::DebugAbbrev<Endian>,
                     debug_ranges: &gimli::DebugRanges<Endian>,
                     header: &gimli::UnitHeader<Endian>)
                     -> Option<Unit>
        where Endian: gimli::Endianity
    {
        let abbrev = debug_abbrev.abbreviations(header.debug_abbrev_offset()).expect("Fail");
        let mut entries = header.entries(&abbrev);
        let (_, entry) = entries.next_dfs()
            .expect("Should parse first entry OK")
            .expect("And first entry should exist!");
        assert_eq!(entry.tag(), gimli::DW_TAG_compile_unit);

        let ranges = if let Some(ranges) =
                            Self::parse_noncontiguous_ranges(entry,
                                                             debug_ranges,
                                                             header.address_size()) {
            ranges
        } else if let Some(range) = Self::parse_contiguous_range(entry) {
            vec![range]
        } else {
            return None;
        };

        let line_offset = match entry.attr_value(gimli::DW_AT_stmt_list) {
            Some(gimli::AttributeValue::DebugLineRef(offset)) => offset,
            _ => return None,
        };

        Some(Unit {
            address_size: header.address_size(),
            ranges: ranges,
            line_offset: line_offset,
        })
    }

    // This must be checked before `parse_contiguous_range`.
    fn parse_noncontiguous_ranges<Endian>(entry: &gimli::DebuggingInformationEntry<Endian>,
                                          debug_ranges: &gimli::DebugRanges<Endian>,
                                          address_size: u8)
                                          -> Option<Vec<gimli::Range>>
        where Endian: gimli::Endianity
    {
        let offset = match entry.attr_value(gimli::DW_AT_ranges) {
            Some(gimli::AttributeValue::DebugRangesRef(offset)) => offset,
            _ => return None,
        };
        let base_address = match entry.attr_value(gimli::DW_AT_low_pc) {
            Some(gimli::AttributeValue::Addr(addr)) => addr,
            _ => 0,
        };
        let ranges = debug_ranges.ranges(offset, address_size, base_address)
            .expect("Range offset should be valid");
        Some(ranges.collect().expect("Should parse ranges"))
    }

    fn parse_contiguous_range<Endian>(entry: &gimli::DebuggingInformationEntry<Endian>)
                                      -> Option<gimli::Range>
        where Endian: gimli::Endianity
    {
        debug_assert!(entry.attr_value(gimli::DW_AT_ranges).is_none());

        let low_pc = match entry.attr_value(gimli::DW_AT_low_pc) {
            Some(gimli::AttributeValue::Addr(addr)) => addr,
            _ => return None,
        };

        let high_pc = match entry.attr_value(gimli::DW_AT_high_pc) {
            Some(gimli::AttributeValue::Addr(addr)) => addr,
            Some(gimli::AttributeValue::Udata(size)) => low_pc.wrapping_add(size),
            None => low_pc.wrapping_add(1),
            _ => return None,
        };

        // TODO: convert to error
        assert!(low_pc < high_pc);
        Some(gimli::Range {
            begin: low_pc,
            end: high_pc,
        })
    }

    fn contains_address(&self, address: u64) -> bool {
        self.ranges.iter().any(|range| address >= range.begin && address < range.end)
    }

    fn lines<'a, Endian>(&self,
                         debug_line: gimli::DebugLine<'a, Endian>)
                         -> gimli::Result<gimli::StateMachine<'a, Endian>>
        where Endian: gimli::Endianity
    {
        let header = try!(gimli::LineNumberProgramHeader::new(debug_line,
                                                              self.line_offset,
                                                              self.address_size));
        Ok(gimli::StateMachine::new(header))
    }
}
