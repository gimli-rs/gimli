//! A simple example of using `gimli::write::Dwarf::from`.
//!
//! This example demonstrates how to load DWARF data from the sections of a file,
//! convert the DWARF data into a `gimli::write::Dwarf`, and write it out to a
//! new file.

use gimli::write::Writer as _;
use object::{Object, ObjectSection};
use std::{borrow, env, error, fs, io};

fn main() -> Result<(), Box<dyn error::Error>> {
    let mut args = env::args();
    if args.len() != 3 {
        return Err(format!("Usage: {} <input-file> <output-file>", args.next().unwrap()).into());
    }
    args.next().unwrap();
    let read_path = args.next().unwrap();
    let write_path = args.next().unwrap();

    // Load the input file.
    let read_file = fs::File::open(read_path)?;
    // SAFETY: This is not safe. `gimli` does not mitigate against modifications to the
    // file while it is being read. See the `memmap2` documentation and take your own
    // precautions. `fs::read` could be used instead if you don't mind loading the entire
    // file into memory.
    let mmap = unsafe { memmap2::Mmap::map(&read_file)? };
    let object = object::File::parse(&*mmap)?;
    let e_machine = match &object {
        object::File::Elf32(elf) => elf.elf_header().e_machine.get(elf.endian()),
        object::File::Elf64(elf) => elf.elf_header().e_machine.get(elf.endian()),
        _ => {
            return Err("unsupported file format".into());
        }
    };
    let endian = if object.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };

    // Load a section that may own its data.
    fn load_section<'data>(
        object: &object::File<'data>,
        name: &str,
    ) -> Result<borrow::Cow<'data, [u8]>, Box<dyn error::Error>> {
        Ok(match object.section_by_name(name) {
            Some(section) => section.uncompressed_data()?,
            None => Default::default(),
        })
    }

    // Borrow a section to create a `Reader`.
    fn borrow_section<'data>(
        section: &'data borrow::Cow<'data, [u8]>,
        endian: gimli::RunTimeEndian,
    ) -> gimli::EndianSlice<'data, gimli::RunTimeEndian> {
        gimli::EndianSlice::new(borrow::Cow::as_ref(section), endian)
    }

    // Load and borrow all of the DWARF sections.
    let read_dwarf_sections = gimli::DwarfSections::load(|id| load_section(&object, id.name()))?;
    let read_dwarf = read_dwarf_sections.borrow(|section| borrow_section(section, endian));

    // Read and convert the DWARF data into a `write::Dwarf`.
    let mut write_dwarf = gimli::write::Dwarf::from(&read_dwarf, &|address| {
        Some(gimli::write::Address::Constant(address))
    })?;

    // At this point you could modify `write_dwarf` as desired.

    // Write the converted DWARF data to new section buffers.
    let mut write_dwarf_sections =
        gimli::write::Sections::new(gimli::write::EndianVec::new(endian));
    write_dwarf.write(&mut write_dwarf_sections)?;

    // Start building a new ELF file.
    let mut write_elf = object::build::elf::Builder::new(object.endianness(), object.is_64());
    write_elf.header.e_machine = e_machine;
    let shstrtab = write_elf.sections.add();
    shstrtab.name = ".shstrtab".into();
    shstrtab.data = object::build::elf::SectionData::SectionString;

    // Add the DWARF section data to the ELF builder.
    write_dwarf_sections.for_each_mut(|id, section| -> object::build::Result<()> {
        if section.len() == 0 {
            return Ok(());
        }
        let write_section = write_elf.sections.add();
        write_section.name = id.name().into();
        write_section.sh_type = object::elf::SHT_PROGBITS;
        write_section.sh_flags = if id.is_string() {
            (object::elf::SHF_STRINGS | object::elf::SHF_MERGE).into()
        } else {
            0
        };
        write_section.sh_addralign = 1;
        write_section.data = object::build::elf::SectionData::Data(section.take().into());
        Ok(())
    })?;

    // Write the ELF file to disk.
    let write_file = fs::File::create(write_path)?;
    let mut write_buffer = object::write::StreamingBuffer::new(io::BufWriter::new(write_file));
    write_elf.write(&mut write_buffer)?;

    Ok(())
}
