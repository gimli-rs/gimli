extern crate gimli;
extern crate getopts;
extern crate object;

use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut opts = getopts::Options::new();
    opts.optopt("e",
                "exe",
                "Set the input file name (default is a.out)",
                "<executable>");

    let matches = opts.parse(&args[1..]).unwrap();
    let file_path = matches.opt_str("e").unwrap_or("a.out".to_string());
    let file = object::open(&file_path);
    if object::is_little_endian(&file) {
        symbolicate::<gimli::LittleEndian>(&file, &matches);
    } else {
        symbolicate::<gimli::BigEndian>(&file, &matches);
    }
}

fn parse_uint_from_hex_string(string: &str) -> u64 {
    if string.len() > 2 && string.starts_with("0x") {
        u64::from_str_radix(&string[2..], 16).expect("Failed to parse address")
    } else {
        u64::from_str_radix(string, 16).expect("Failed to parse address")
    }
}

fn entry_offsets_for_addresses<Endian>(file: &object::File,
                                       addrs: &Vec<u64>)
                                       -> Vec<Option<gimli::DebugInfoOffset>>
    where Endian: gimli::Endianity
{
    let aranges = object::get_section(file, ".debug_aranges")
        .expect("Can't addr2line with no aranges");
    let aranges = gimli::DebugAranges::<Endian>::new(aranges);
    let mut aranges = aranges.aranges();

    let mut dies: Vec<Option<gimli::DebugInfoOffset>> = (0..addrs.len()).map(|_| None).collect();
    while let Some(arange) = aranges.next_arange().expect("Should parse arange OK") {
        let start = arange.start();
        let end = start + arange.len();

        for (i, addr) in addrs.iter().enumerate() {
            if *addr >= start && *addr < end {
                dies[i] = Some(arange.debug_info_offset());
            }
        }
    }

    dies
}

fn line_offset_for_entry<Endian>(abbrevs: &gimli::DebugAbbrev<Endian>,
                                 header: &gimli::UnitHeader<Endian>)
                                 -> Option<gimli::DebugLineOffset>
    where Endian: gimli::Endianity
{
    let abbrev = abbrevs.abbreviations(header.debug_abbrev_offset()).expect("Fail");
    let mut entries = header.entries(&abbrev);
    let (_, entry) = entries.next_dfs()
        .expect("Should parse first entry OK")
        .expect("And first entry should exist!");
    match entry.attr_value(gimli::DW_AT_stmt_list) {
        Some(gimli::AttributeValue::DebugLineRef(offset)) => Some(offset),
        _ => None,
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

fn symbolicate<Endian>(file: &object::File, matches: &getopts::Matches)
    where Endian: gimli::Endianity
{
    let addrs: Vec<u64> = matches.free.iter().map(|x| parse_uint_from_hex_string(x)).collect();

    let offsets = entry_offsets_for_addresses::<Endian>(&file, &addrs);
    let debug_info = object::get_section(file, ".debug_info")
        .expect("Can't addr2line without .debug_info");
    let debug_info = gimli::DebugInfo::<Endian>::new(debug_info);
    let debug_abbrev = object::get_section(&file, ".debug_abbrev")
        .expect("Can't addr2line without .debug_abbrev");
    let debug_abbrev = gimli::DebugAbbrev::<Endian>::new(debug_abbrev);
    let debug_line = object::get_section(file, ".debug_line")
        .expect("Can't addr2line without .debug_line");
    let debug_line = gimli::DebugLine::<Endian>::new(&debug_line);

    for (info_offset, addr) in offsets.iter().zip(addrs.iter()) {
        match *info_offset {
            None => println!("Found nothing"),
            Some(d) => {
                match debug_info.header_from_offset(d) {
                    Err(_) => println!("Couldn't get DIE header"),
                    Ok(h) => {
                        let line_offset = line_offset_for_entry(&debug_abbrev, &h)
                            .expect("No offset into .debug_lines!?");
                        let header = gimli::LineNumberProgramHeader::new(debug_line,
                                                                         line_offset,
                                                                         h.address_size());
                        if let Ok(header) = header {
                            let mut state_machine = gimli::StateMachine::new(header);
                            match state_machine.run_to_address(addr) {
                                Err(_) => println!("Failed to run line number program!"),
                                Ok(None) => println!("Failed to find matching line for {}", *addr),
                                Ok(Some(row)) => display_file(row),
                            };
                        }
                    }
                }
            }
        }
    }
}
