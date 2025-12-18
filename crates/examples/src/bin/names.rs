//! A simple example of parsing `.debug_names`.
//!
//! This example demonstrates how to parse the `.debug_names` section of a
//! DWARF object file and lookup a name in the hash table.

// style: allow verbose lifetimes
#![allow(clippy::needless_lifetimes)]

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

fn main() -> Result<(), Box<dyn error::Error>> {
    let mut args = env::args();
    if args.len() != 3 {
        println!("Usage: {} <file> <name>", args.next().unwrap());
        return Ok(());
    }
    args.next().unwrap();
    let path = args.next().unwrap();
    let name = args.next().unwrap();

    let file = fs::File::open(path)?;
    // SAFETY: This is not safe. `gimli` does not mitigate against modifications to the
    // file while it is being read. See the `memmap2` documentation and take your own
    // precautions. `fs::read` could be used instead if you don't mind loading the entire
    // file into memory.
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let object = object::File::parse(&*mmap)?;
    let endian = if object.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };

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
    let dwarf_sections = gimli::DwarfSections::load(|id| load_section(&object, id.name()))?;

    // Create `Reader`s for all of the sections and do preliminary parsing.
    // Alternatively, we could have used `Dwarf::load` with an owned type such as `EndianRcSlice`.
    let dwarf = dwarf_sections.borrow(|section| borrow_section(section, endian));

    // Calculate the hash once only.
    let hash = gimli::case_folding_djb_hash(&name);

    // The name may appear in more than one name index.
    for header in dwarf.debug_names.headers() {
        let name_index = header?.index()?;
        let default_compile_unit = name_index.default_compile_unit()?;

        // Find all names that match the hash.
        for name_table_index in name_index.find_by_hash(hash)? {
            let name_table_index = name_table_index?;
            let candidate_name = name_index
                .name_string(name_table_index, &dwarf.debug_str)?
                .inner()
                .to_string()?;

            // A name comparison is required for hash lookups due to hash collisions or
            // case folding.
            //
            // Depending on the source language, this may need to be case insensitive,
            // but for this example we do an exact match.
            if name != candidate_name {
                continue;
            }

            // There may be multiple entries associated with the name.
            for entry in name_index.name_entries(name_table_index)? {
                let entry = entry?;
                print!("Tag={}", entry.tag);
                let mut use_default_cu = true;
                for attr in &entry.attrs {
                    print!(" {}=", attr.name());
                    match attr.name() {
                        gimli::DW_IDX_compile_unit => {
                            use_default_cu = false;
                            print!("{:x}", attr.compile_unit(&name_index)?.0);
                        }
                        gimli::DW_IDX_type_unit => {
                            use_default_cu = false;
                            print!("{:x?}", attr.type_unit(&name_index)?);
                        }
                        gimli::DW_IDX_die_offset => print!("{:x}", attr.die_offset()?.0),
                        gimli::DW_IDX_parent => print!("{:?}", attr.parent()?),
                        gimli::DW_IDX_type_hash => print!("{:08x}", attr.type_hash()?),
                        _ => print!("{:?}", attr.value()),
                    }
                }
                if use_default_cu {
                    print!(" CU(default)={:x?}", default_compile_unit);
                }
                println!();
            }
        }
    }

    Ok(())
}
