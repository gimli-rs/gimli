//! A simple example of parsing `.debug_info`.
//!
//! This example demonstrates how to parse the `.debug_info` section of a
//! DWARF object file and iterate over the compilation units and their DIEs.
//! It also demonstrates how to find the DWO unit for each CU in a DWP file.
//!
//! Most of the complexity is due to loading the sections from the object
//! file and DWP file, which is not something that is provided by gimli itself.

// style: allow verbose lifetimes
#![allow(clippy::needless_lifetimes)]

use gimli::Reader as _;
use object::{Object, ObjectSection};
use std::{borrow, env, error, fs};

// This is a simple wrapper around `object::read::RelocationMap` that implements
// `gimli::read::Relocate` for use with `gimli::RelocateReader`.
// You only need this if you are parsing relocatable object files.
#[derive(Debug, Default)]
struct RelocationMap(object::read::RelocationMap);

impl<'a> gimli::read::Relocate for &'a RelocationMap {
    fn relocate_address(&self, offset: usize, value: u64) -> gimli::Result<u64> {
        Ok(self.0.relocate(offset as u64, value))
    }

    fn relocate_offset(&self, offset: usize, value: usize) -> gimli::Result<usize> {
        <usize as gimli::ReaderOffset>::from_u64(self.0.relocate(offset as u64, value as u64))
    }
}

// The section data that will be stored in `DwarfSections` and `DwarfPackageSections`.
#[derive(Default)]
struct Section<'data> {
    data: borrow::Cow<'data, [u8]>,
    relocations: RelocationMap,
}

// The reader type that will be stored in `Dwarf` and `DwarfPackage`.
// If you don't need relocations, you can use `gimli::EndianSlice` directly.
type Reader<'data> =
    gimli::RelocateReader<gimli::EndianSlice<'data, gimli::RunTimeEndian>, &'data RelocationMap>;

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
    // SAFETY: This is not safe. `gimli` does not mitigate against modifications to the
    // file while it is being read. See the `memmap2` documentation and take your own
    // precautions. `fs::read` could be used instead if you don't mind loading the entire
    // file into memory.
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
    // Load a `Section` that may own its data.
    fn load_section<'data>(
        object: &object::File<'data>,
        name: &str,
    ) -> Result<Section<'data>, Box<dyn error::Error>> {
        Ok(match object.section_by_name(name) {
            Some(section) => Section {
                data: section.uncompressed_data()?,
                relocations: section.relocation_map().map(RelocationMap)?,
            },
            None => Default::default(),
        })
    }

    // Borrow a `Section` to create a `Reader`.
    fn borrow_section<'data>(
        section: &'data Section<'data>,
        endian: gimli::RunTimeEndian,
    ) -> Reader<'data> {
        let slice = gimli::EndianSlice::new(borrow::Cow::as_ref(&section.data), endian);
        gimli::RelocateReader::new(slice, &section.relocations)
    }

    // Load all of the sections.
    let dwarf_sections = gimli::DwarfSections::load(|id| load_section(object, id.name()))?;
    let dwp_sections = dwp_object
        .map(|dwp_object| {
            gimli::DwarfPackageSections::load(|id| load_section(dwp_object, id.dwo_name().unwrap()))
        })
        .transpose()?;

    let empty_relocations = RelocationMap::default();
    let empty_section =
        gimli::RelocateReader::new(gimli::EndianSlice::new(&[], endian), &empty_relocations);

    // Create `Reader`s for all of the sections and do preliminary parsing.
    // Alternatively, we could have used `Dwarf::load` with an owned type such as `EndianRcSlice`.
    let dwarf = dwarf_sections.borrow(|section| borrow_section(section, endian));
    let dwp = dwp_sections
        .as_ref()
        .map(|dwp_sections| {
            dwp_sections.borrow(|section| borrow_section(section, endian), empty_section)
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
        let unit_ref = unit.unit_ref(&dwarf);
        dump_unit(unit_ref)?;

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
        let unit_ref = unit.unit_ref(&dwo);
        dump_unit(unit_ref)?;
    }

    Ok(())
}

fn dump_unit(unit: gimli::UnitRef<Reader>) -> Result<(), gimli::Error> {
    // Iterate over the Debugging Information Entries (DIEs) in the unit.
    let mut depth = 0;
    let mut entries = unit.entries();
    while let Some((delta_depth, entry)) = entries.next_dfs()? {
        depth += delta_depth;
        println!("<{}><{:x}> {}", depth, entry.offset().0, entry.tag());

        // Iterate over the attributes in the DIE.
        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            print!("   {}: {:?}", attr.name(), attr.value());
            if let Ok(s) = unit.attr_string(attr.value()) {
                print!(" '{}'", s.to_string_lossy()?);
            }
            println!();
        }
    }
    Ok(())
}
