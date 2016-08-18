extern crate gimli;
extern crate getopts;

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
    let file = obj::open(&file_path);
    if obj::is_little_endian(&file) {
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

fn entry_offsets_for_addresses<Endian>(file: &obj::File,
                                       addrs: &Vec<u64>)
                                       -> Vec<Option<gimli::DebugInfoOffset>>
    where Endian: gimli::Endianity
{
    let aranges = obj::get_section(file, ".debug_aranges")
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

fn display_file<Endian>(header: &gimli::LineNumberProgramHeader<Endian>,
                        row: &gimli::LineNumberRow<Endian>)
    where Endian: gimli::Endianity
{
    let file = row.file().unwrap();
    let directory_index = file.directory_index();
    if directory_index > 0 {
        println!("{}/{}:{}",
                 header.include_directories()[directory_index as usize - 1].to_string_lossy(),
                 file.path_name().to_string_lossy(),
                 row.line().unwrap());
    } else {
        println!("{}:{}",
                 file.path_name().to_string_lossy(),
                 row.line().unwrap());
    }
}

fn symbolicate<Endian>(file: &obj::File, matches: &getopts::Matches)
    where Endian: gimli::Endianity
{
    let addrs: Vec<u64> = matches.free.iter().map(|x| parse_uint_from_hex_string(x)).collect();

    let offsets = entry_offsets_for_addresses::<Endian>(&file, &addrs);
    let debug_info = obj::get_section(file, ".debug_info")
        .expect("Can't addr2line without .debug_info");
    let debug_info = gimli::DebugInfo::<Endian>::new(debug_info);
    let debug_abbrev = obj::get_section(&file, ".debug_abbrev")
        .expect("Can't addr2line without .debug_abbrev");
    let debug_abbrev = gimli::DebugAbbrev::<Endian>::new(debug_abbrev);
    let debug_line = obj::get_section(file, ".debug_line")
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
                            let mut state_machine = gimli::StateMachine::new(&header);
                            match state_machine.run_to_address(addr) {
                                Err(_) => println!("Failed to run line number program!"),
                                Ok(None) => println!("Failed to find matching line for {}", *addr),
                                Ok(Some(row)) => display_file(&header, &row),
                            }
                        }
                    }
                }
            }
        }
    }
}

// All cross platform / object file format compatibility stuff should
// be contained in the `obj` module. Each supported platform / object
// file format should implement the `obj` module with an identical
// interface, but with the `pub type File` changing as needed. Hooray
// duck typing!

#[cfg(target_os="linux")]
mod obj {
    extern crate elf;
    use std::path::Path;

    /// The parsed object file type.
    pub type File = elf::File;

    /// Open and parse the object file at the given path.
    pub fn open<P>(path: P) -> File
        where P: AsRef<Path>
    {
        let path = path.as_ref();
        elf::File::open_path(path).expect("Could not open file")
    }

    /// Get the contents of the section named `section_name`, if such
    /// a section exists.
    pub fn get_section<'a>(file: &'a File, section_name: &str) -> Option<&'a [u8]> {
        file.sections
            .iter()
            .find(|s| s.shdr.name == section_name)
            .map(|s| &s.data[..])
    }

    /// Return true if the file is little endian, false if it is big endian.
    pub fn is_little_endian(file: &File) -> bool {
        match file.ehdr.data {
            elf::types::ELFDATA2LSB => true,
            elf::types::ELFDATA2MSB => false,
            otherwise => panic!("Unknown endianity: {}", otherwise),
        }
    }
}

#[cfg(target_os="macos")]
mod obj {
    extern crate mach_o;

    use std::ffi::CString;
    use std::fs;
    use std::io::Read;
    use std::mem;
    use std::path::Path;

    pub type File = Vec<u8>;

    pub fn open<P>(path: P) -> File
        where P: AsRef<Path>
    {
        let mut file = fs::File::open(path).expect("Could not open file");
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).expect("Could not read file");
        buf
    }

    // Translate the "." prefix to the "__" prefix used by OSX/Mach-O, eg
    // ".debug_info" to "__debug_info".
    fn translate_section_name(section_name: &str) -> CString {
        let mut name = Vec::with_capacity(section_name.len() + 1);
        name.push(b'_');
        name.push(b'_');
        for ch in &section_name.as_bytes()[1..] {
            name.push(*ch);
        }
        unsafe { CString::from_vec_unchecked(name) }
    }

    pub fn get_section<'a>(file: &'a File, section_name: &str) -> Option<&'a [u8]> {
        let parsed = mach_o::Header::new(&file[..]).expect("Could not parse macho-o file");

        let segment_name = CString::new("__DWARF").unwrap();
        let section_name = translate_section_name(section_name);
        parsed.get_section(&segment_name, &section_name).map(|s| s.data())
    }

    pub fn is_little_endian(file: &File) -> bool {
        let parsed = mach_o::Header::new(&file[..]).expect("Could not parse macho-o file");

        let bytes = [1, 0, 0, 0u8];
        let int: u32 = unsafe { mem::transmute(bytes) };
        let native_byteorder_is_little = int == 1;

        match (native_byteorder_is_little, parsed.is_native_byteorder()) {
            (true, b) => b,
            (false, b) => !b,
        }
    }
}
