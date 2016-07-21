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

    dump_info(&file, debug_abbrev);
    dump_types(&file, debug_abbrev);
}

fn dump_info<Endian>(file: &obj::File, debug_abbrev: gimli::DebugAbbrev<Endian>)
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

            dump_entries(unit.entries(&abbrevs));
        }
    }
}

fn dump_types<Endian>(file: &obj::File, debug_abbrev: gimli::DebugAbbrev<Endian>)
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

            dump_entries(unit.entries(&abbrevs));
        }
    }
}

fn dump_entries<Endian>(mut entries: gimli::EntriesCursor<Endian>)
    where Endian: gimli::Endianity
{
    let depth = Cell::new(0);
    while let Some(entry) = entries.current() {
        let entry = entry.expect("Should parse the entry OK");

        let  indent = || {
            for _ in 0..(depth.get() as usize) {
                print!("        ");
            }
        };

        indent();
        println!("<{}> <{}>", entry.code(), entry.tag());

        for attr in entry.attrs() {
            let attr = attr.expect("Should parse attribute OK");

            indent();
            println!("    {} = {:?}", attr.name(), attr.value());
        }

        if let Some(delta_depth) = entries.next_dfs() {
            depth.set(depth.get() + delta_depth);
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
        file.sections.iter()
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
