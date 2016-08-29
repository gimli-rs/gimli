extern crate gimli;
extern crate getopts;
extern crate memmap;
extern crate object;

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
    let debug_line = gimli::DebugLine::<Endian>::new(&debug_line);

    let mut units = Vec::new();
    let mut headers = debug_info.units();
    while let Some(header) = headers.next().expect("Couldn't get DIE header") {
        if let Some(unit) = Unit::parse(&debug_abbrev, &header) {
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

struct Unit {
    address_size: u8,
    low_pc: u64,
    high_pc: u64,
    line_offset: gimli::DebugLineOffset,
}

impl Unit {
    fn parse<Endian>(abbrevs: &gimli::DebugAbbrev<Endian>,
                     header: &gimli::UnitHeader<Endian>)
                     -> Option<Unit>
        where Endian: gimli::Endianity
    {
        let abbrev = abbrevs.abbreviations(header.debug_abbrev_offset()).expect("Fail");
        let mut entries = header.entries(&abbrev);
        let (_, entry) = entries.next_dfs()
            .expect("Should parse first entry OK")
            .expect("And first entry should exist!");

        let low_pc = match entry.attr_value(gimli::DW_AT_low_pc) {
            Some(gimli::AttributeValue::Addr(addr)) => addr,
            _ => 0,
        };
        let high_pc = match entry.attr_value(gimli::DW_AT_high_pc) {
            Some(gimli::AttributeValue::Addr(addr)) => addr,
            _ => 0,
        };
        // TODO: handle DW_AT_ranges
        let line_offset = match entry.attr_value(gimli::DW_AT_stmt_list) {
            Some(gimli::AttributeValue::DebugLineRef(offset)) => offset,
            _ => return None,
        };
        Some(Unit {
            address_size: header.address_size(),
            low_pc: low_pc,
            high_pc: high_pc,
            line_offset: line_offset,
        })
    }

    fn contains_address(&self, address: u64) -> bool {
        self.high_pc == 0 || address >= self.low_pc && address <= self.high_pc
    }

    fn lines<'a, Endian>(&self,
                         debug_line: gimli::DebugLine<'a, Endian>)
                         -> gimli::ParseResult<gimli::StateMachine<'a, Endian>>
        where Endian: gimli::Endianity
    {
        let header = try!(gimli::LineNumberProgramHeader::new(debug_line,
                                                              self.line_offset,
                                                              self.address_size));
        Ok(gimli::StateMachine::new(header))
    }
}
