//! A simple example of parsing `.debug_info`.
//!
//! This example demonstrates how to parse the `.debug_info` section of a
//! DWARF object file and iterate over the compilation units and their DIEs.
//! It also demonstrates how to find the DWO unit for each CU in a DWP file.
//!
//! Most of the complexity is due to loading the sections from the object
//! file and DWP file, which is not something that is provided by gimli itself.

use object::{Object, ObjectSection};
use std::{borrow, env, error, fs};

fn main() {
    let mut args = env::args();
    if args.len() != 2 && args.len() != 3 {
        println!("Usage: {} <file> [dwp]", args.next().unwrap());
        return;
    }
    args.next().unwrap();
    let path = args.next().unwrap();
    let dwp_path = args.next();

    let file = fs::File::open(path).unwrap();
    let mmap = unsafe { memmap2::Mmap::map(&file).unwrap() };
    let object = object::File::parse(&*mmap).unwrap();
    let endian = if object.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };

    if let Some(dwp_path) = dwp_path {
        let dwp_file = fs::File::open(dwp_path).unwrap();
        let dwp_mmap = unsafe { memmap2::Mmap::map(&dwp_file).unwrap() };
        let dwp_object = object::File::parse(&*dwp_mmap).unwrap();
        assert_eq!(dwp_object.is_little_endian(), object.is_little_endian());

        dump_file(&object, Some(&dwp_object), endian).unwrap();
    } else {
        dump_file(&object, None, endian).unwrap();
    }
}

fn dump_file(
    object: &object::File,
    dwp_object: Option<&object::File>,
    endian: gimli::RunTimeEndian,
) -> Result<(), Box<dyn error::Error>> {
    // Load a section and return as `Cow<[u8]>`.
    fn load_section<'a>(
        object: &'a object::File,
        name: &str,
    ) -> Result<borrow::Cow<'a, [u8]>, Box<dyn error::Error>> {
        Ok(match object.section_by_name(name) {
            Some(section) => section.uncompressed_data()?,
            None => borrow::Cow::Borrowed(&[]),
        })
    }

    // Borrow a `Cow<[u8]>` to create an `EndianSlice`.
    let borrow_section = |section| gimli::EndianSlice::new(borrow::Cow::as_ref(section), endian);

    // Load all of the sections.
    let dwarf_sections = gimli::DwarfSections::load(|id| load_section(object, id.name()))?;
    let dwp_sections = dwp_object
        .map(|dwp_object| {
            gimli::DwarfPackageSections::load(|id| load_section(dwp_object, id.dwo_name().unwrap()))
        })
        .transpose()?;

    // Create `EndianSlice`s for all of the sections and do preliminary parsing.
    // Alternatively, we could have used `Dwarf::load` with an owned type such as `EndianRcSlice`.
    let dwarf = dwarf_sections.borrow(borrow_section);
    let dwp = dwp_sections
        .as_ref()
        .map(|dwp_sections| {
            dwp_sections.borrow(borrow_section, gimli::EndianSlice::new(&[], endian))
        })
        .transpose()?;

    // Iterate over the compilation units.
    let mut iter = dwarf.units();
    while let Some(header) = iter.next()? {
        println!(
            "Unit at <.debug_info+0x{:x}>",
            header.offset().as_debug_info_offset().unwrap().0
        );
        let unit = dwarf.unit(header)?;
        dump_unit(&unit)?;

        // Check for a DWO unit.
        let Some(dwp) = &dwp else { continue };
        let Some(dwo_id) = unit.dwo_id else { continue };
        println!("DWO Unit ID {:x}", dwo_id.0);
        let Some(dwo) = dwp.find_cu(dwo_id, &dwarf)? else {
            continue;
        };
        let Some(header) = dwo.units().next()? else {
            continue;
        };
        let unit = dwo.unit(header)?;
        dump_unit(&unit)?;
    }

    Ok(())
}

fn dump_unit(
    unit: &gimli::Unit<gimli::EndianSlice<gimli::RunTimeEndian>>,
) -> Result<(), gimli::Error> {
    // Iterate over the Debugging Information Entries (DIEs) in the unit.
    let mut depth = 0;
    let mut entries = unit.entries();
    while let Some((delta_depth, entry)) = entries.next_dfs()? {
        depth += delta_depth;
        println!("<{}><{:x}> {}", depth, entry.offset().0, entry.tag());

        // Iterate over the attributes in the DIE.
        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            println!("   {}: {:?}", attr.name(), attr.value());
        }
    }
    Ok(())
}
