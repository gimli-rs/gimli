//! An example of using [`gimli::write::Dwarf::convert_with_filter`].
//!
//! This example demonstrates how to load DWARF data from the sections of a file,
//! convert the DWARF data into a [`gimli::write::Dwarf`], and write it out to a
//! new file.
//!
//! It also modifies the converted DWARF by filtering out DIEs for dead code.

use gimli::write::Writer;
use object::{Object, ObjectSection};
use std::{borrow, env, error, fs, io};

fn main() -> Result<(), Box<dyn error::Error>> {
    let mut args = env::args_os();
    if args.len() != 3 {
        return Err("Usage: convert <input-file> <output-file>".into());
    }
    args.next().unwrap();
    let read_path = args.next().unwrap();
    let write_path = args.next().unwrap();

    // Load the input file.
    let read_file = fs::File::open(&read_path)?;
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

    // Try to load a .dwp file.
    let mut dwp_path = read_path.clone();
    dwp_path.push(".dwp");
    let dwp_file = fs::File::open(&dwp_path).ok();
    let dwp_mmap = dwp_file
        .as_ref()
        .and_then(|f| unsafe { memmap2::Mmap::map(f).ok() });
    let dwp_object = dwp_mmap
        .as_ref()
        .and_then(|mmap| object::File::parse(&**mmap).ok());

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

    let dwp_sections = dwp_object.as_ref().and_then(|object| {
        gimli::DwarfPackageSections::load(|id| load_section(object, id.dwo_name().unwrap())).ok()
    });
    let dwp = dwp_sections.as_ref().and_then(|s| {
        s.borrow(
            |section| borrow_section(section, endian),
            gimli::EndianSlice::new(&[], endian),
        )
        .ok()
    });

    // Read and convert the DWARF data into a `write::Dwarf`.
    let mut write_dwarf = convert_dwarf(&read_dwarf, dwp.as_ref())?;

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

fn convert_dwarf<R: gimli::Reader<Offset = usize>>(
    read_dwarf: &gimli::Dwarf<R>,
    dwp: Option<&gimli::DwarfPackage<R>>,
) -> gimli::write::ConvertResult<gimli::write::Dwarf> {
    let filter = filter_dwarf(read_dwarf)?;

    // The container for the converted DWARF. It is possible to use this for the
    // conversion of multiple input DWARF sections, combining them into a single output.
    let mut dwarf = gimli::write::Dwarf::default();

    // Start a conversion that reserves the DIEs identified above.
    let mut convert = dwarf.convert_with_filter(filter)?;

    // Alternatively, start a conversion that reserves all DIEs.
    //let mut convert = dwarf.read_units(read_dwarf, None)?;

    while let Some((mut unit, root_entry)) = convert.read_unit()? {
        if let Some(dwo_id) = unit.from_unit.dwo_id {
            let Some(dwp) = dwp else {
                // TODO: try to load the .dwo
                continue;
            };
            let Some(split_dwarf) = dwp.find_cu(dwo_id, unit.from_unit.dwarf)? else {
                continue;
            };
            let filter = filter_dwarf(&split_dwarf)?;
            let mut convert_split = unit.convert_split_with_filter(filter)?;
            let (mut split_unit, split_root_entry) = convert_split.read_unit()?;
            convert_unit(&mut split_unit, &split_root_entry, Some(&root_entry))?;
        } else {
            convert_unit(&mut unit, &root_entry, None)?;
        }
    }
    Ok(dwarf)
}

fn convert_unit<R: gimli::Reader<Offset = usize>>(
    unit: &mut gimli::write::ConvertUnit<'_, R>,
    root_entry: &gimli::write::ConvertUnitEntry<'_, R>,
    skeleton_root_entry: Option<&gimli::write::ConvertUnitEntry<'_, R>>,
) -> gimli::write::ConvertResult<()> {
    // The line program needs to be converted before file indices in DIE attributes.
    if let Some(mut convert_program) = unit.read_line_program(None, None)? {
        while let Some(sequence) = convert_program.read_sequence()? {
            if let Some(start) = sequence.start {
                convert_program.set_address(gimli::write::Address::Constant(start));
            }
            for row in sequence.rows {
                convert_program.generate_row(row);
            }
            if let gimli::write::ConvertLineSequenceEnd::Length(length) = sequence.end {
                convert_program.end_sequence(length);
            }
        }
        let (program, files) = convert_program.program();
        unit.set_line_program(program, files);
    }

    let root_id = unit.unit.root();
    convert_attributes(unit, root_id, root_entry);
    if let Some(skeleton_root_entry) = skeleton_root_entry {
        convert_attributes(unit, root_id, skeleton_root_entry);
    }
    while let Some((id, entry)) = unit.read_entry()? {
        // `id` is `None` for DIEs that were filtered out and thus don't need converting.
        if id.is_none() {
            continue;
        }
        let id = unit.add_entry(id, &entry);
        convert_attributes(unit, id, &entry);
    }
    Ok(())
}

fn convert_attributes<R: gimli::Reader<Offset = usize>>(
    unit: &mut gimli::write::ConvertUnit<'_, R>,
    id: gimli::write::UnitEntryId,
    entry: &gimli::write::ConvertUnitEntry<'_, R>,
) {
    for attr in &entry.attrs {
        match unit.convert_attribute_value(entry.from_unit, attr.name(), attr.value(), &|address| {
            Some(gimli::write::Address::Constant(address))
        }) {
            Ok(value) => unit.unit.get_mut(id).set(attr.name(), value),
            Err(e) => {
                // Invalid input DWARF has most often been seen for expressions.
                let unit_offset = match unit.from_unit.header.offset() {
                    gimli::UnitSectionOffset::DebugInfoOffset(o) => o.0,
                    gimli::UnitSectionOffset::DebugTypesOffset(o) => o.0,
                };
                eprintln!(
                    "Warning: failed to convert attribute for DIE {:x}: {} = {:?}: {}",
                    unit_offset + entry.offset.0,
                    attr.name(),
                    attr.raw_value(),
                    e
                );
            }
        }
    }
}

fn filter_dwarf<R: gimli::Reader<Offset = usize>>(
    dwarf: &gimli::read::Dwarf<R>,
) -> gimli::write::ConvertResult<gimli::write::FilterUnitSection<'_, R>> {
    // Walk the DIE tree. This will automatically record relationships between DIEs based
    // on the tree structure, and DIE references in attributes.
    //
    // We also call `require_entry` for DIEs that we are interested in converting. This
    // will use the tree structure and DIE references to automatically determine further
    // DIEs that must also be converted.
    let mut filter = gimli::write::FilterUnitSection::new(dwarf)?;
    while let Some(mut unit) = filter.read_unit()? {
        while let Some(entry) = unit.read_entry()? {
            if need_entry(&entry)? {
                unit.require_entry(entry.offset);
            }
        }
    }
    Ok(filter)
}

/// Use heuristics to determine if an entry is dead code.
fn need_entry<R: gimli::Reader<Offset = usize>>(
    entry: &gimli::write::FilterUnitEntry<'_, R>,
) -> gimli::write::ConvertResult<bool> {
    match entry.parent_tag {
        None | Some(gimli::DW_TAG_namespace) => {}
        _ => return Ok(false),
    }
    if let Some(attr) = entry.attr_value(gimli::DW_AT_low_pc) {
        if let Some(address) = entry.unit.attr_address(attr)? {
            return Ok(!is_tombstone_address(entry, address));
        }
    } else if let Some(attr) = entry.attr_value(gimli::DW_AT_location) {
        let gimli::read::AttributeValue::Exprloc(expression) = attr else {
            panic!(
                "Unexpected DW_AT_location for global at {:x?}",
                entry.offset.to_unit_section_offset(&entry.unit)
            );
        };
        // Check for a tombstone address in the location.
        // TODO: haven't seen this happen in practice
        let mut ops = expression.operations(entry.unit.encoding());
        while let Some(op) = ops.next()? {
            match op {
                gimli::read::Operation::Address { address } => {
                    if is_tombstone_address(entry, address) {
                        return Ok(false);
                    }
                }
                gimli::read::Operation::AddressIndex { index } => {
                    let address = entry.unit.address(index)?;
                    if is_tombstone_address(entry, address) {
                        return Ok(false);
                    }
                }
                gimli::read::Operation::UnsignedConstant { .. } | gimli::read::Operation::TLS => {}
                _ => {
                    panic!(
                        "Unexpected DW_AT_location operation for static variable at {:x?}",
                        entry.offset.to_unit_section_offset(&entry.unit)
                    );
                }
            }
        }
        return Ok(true);
    }
    Ok(false)
}

fn is_tombstone_address<R: gimli::Reader<Offset = usize>>(
    entry: &gimli::write::FilterUnitEntry<'_, R>,
    address: u64,
) -> bool {
    address == 0 || entry.unit.header.is_tombstone_address(address)
}
