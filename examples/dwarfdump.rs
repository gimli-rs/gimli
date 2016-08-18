extern crate gimli;

use std::cell::Cell;
use std::env;

fn main() {
    for file_path in env::args().skip(1) {
        println!("{}", file_path);
        println!("");

        let file = obj::open(&file_path);
        if obj::is_little_endian(&file) {
            dump_file::<gimli::LittleEndian>(file);
        } else {
            dump_file::<gimli::BigEndian>(file);
        }
    }
}

fn dump_file<Endian>(file: obj::File)
    where Endian: gimli::Endianity
{
    let debug_abbrev = obj::get_section(&file, ".debug_abbrev")
        .expect("Does not have .debug_abbrev section");
    let debug_abbrev = gimli::DebugAbbrev::<Endian>::new(debug_abbrev);
    let debug_str = obj::get_section(&file, ".debug_str")
        .expect("Does not have .debug_str section");
    let debug_str = gimli::DebugStr::<Endian>::new(debug_str);

    dump_info(&file, debug_abbrev, debug_str);
    dump_types(&file, debug_abbrev, debug_str);
    dump_line(&file, debug_abbrev);
    dump_aranges::<Endian>(&file);
}

fn dump_info<Endian>(file: &obj::File,
                     debug_abbrev: gimli::DebugAbbrev<Endian>,
                     debug_str: gimli::DebugStr<Endian>)
    where Endian: gimli::Endianity
{
    if let Some(debug_info) = obj::get_section(file, ".debug_info") {
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

fn dump_types<Endian>(file: &obj::File,
                      debug_abbrev: gimli::DebugAbbrev<Endian>,
                      debug_str: gimli::DebugStr<Endian>)
    where Endian: gimli::Endianity
{
    if let Some(debug_types) = obj::get_section(file, ".debug_types") {
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

fn dump_line<Endian>(file: &obj::File, debug_abbrev: gimli::DebugAbbrev<Endian>)
    where Endian: gimli::Endianity
{
    let debug_line = obj::get_section(file, ".debug_line");
    let debug_info = obj::get_section(file, ".debug_info");

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
            let value = root.attr_value(gimli::DW_AT_stmt_list);
            let offset = gimli::DebugLineOffset(match value {
                Some(gimli::AttributeValue::Data(data)) if data.len() == 4 => {
                    Endian::read_u32(data) as u64
                }
                Some(gimli::AttributeValue::Data(data)) if data.len() == 8 => {
                    Endian::read_u64(data)
                }
                Some(gimli::AttributeValue::SecOffset(offset)) => offset,
                _ => continue,
            });

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

fn dump_aranges<Endian>(file: &obj::File)
    where Endian: gimli::Endianity
{
    if let Some(debug_aranges) = obj::get_section(file, ".debug_aranges") {
        println!(".debug_aranges");
        let debug_aranges = gimli::DebugAranges::<Endian>::new(debug_aranges);

        let mut aranges = debug_aranges.aranges();
        while let Some(arange) = aranges.next_arange().expect("Should parse arange OK") {
            println!("arange starts at {}, length of {}, cu_die_offset = {:?}",
                     arange.start(),
                     arange.len(),
                     arange.debug_info_offset());
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
