//! A small example for writing an object file containing DWARF sections.
//!
//! The resulting object file can be linked with a C runtime to create a complete executable:
//! ```sh
//! $ cargo run --bin simple_write
//! $ gcc -o hello hello.o -z noexecstack
//! $ ./hello
//! Hello, world!
//! ```
use gimli::write::{
    Address, AttributeValue, DwarfUnit, EndianVec, LineProgram, LineString, Range, RangeList,
    RelocateWriter, Relocation, RelocationTarget, Sections, Writer,
};
use gimli::{Encoding, Format, LineEncoding, LittleEndian};

/// Record information needed to write a section.
#[derive(Clone)]
struct Section {
    data: EndianVec<LittleEndian>,
    relocations: Vec<Relocation>,
    id: Option<object::write::SectionId>,
}

impl Section {
    fn new() -> Self {
        Self {
            data: EndianVec::new(LittleEndian),
            relocations: Vec::new(),
            id: None,
        }
    }
}

impl RelocateWriter for Section {
    type Writer = EndianVec<LittleEndian>;

    fn writer(&self) -> &Self::Writer {
        &self.data
    }

    fn writer_mut(&mut self) -> &mut Self::Writer {
        &mut self.data
    }

    fn relocate(&mut self, relocation: Relocation) {
        self.relocations.push(relocation);
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let binary_format = object::BinaryFormat::native_object();
    let mut obj = object::write::Object::new(
        binary_format,
        object::Architecture::X86_64,
        object::Endianness::Little,
    );

    let comp_dir = *b"/tmp";
    let file_name = *b"hello.c";
    let main_name = *b"main";

    let (main_symbol, main_size) = define_main(&mut obj)?;
    let main_address = Address::Symbol {
        // This is a user defined identifier for the symbol.
        // In this case, we will use 0 to mean the main function.
        symbol: 0,
        addend: 0,
    };

    // Choose the encoding parameters.
    let encoding = Encoding {
        format: Format::Dwarf32,
        version: if binary_format == object::BinaryFormat::Coff {
            // The COFF toolchain I used didn't work with DWARF version 5.
            4
        } else {
            5
        },
        address_size: 8,
    };

    // Create a container for a single compilation unit.
    let mut dwarf = DwarfUnit::new(encoding);

    // Set attributes on the root DIE.
    let range_list_id = dwarf.unit.ranges.add(RangeList(vec![Range::StartLength {
        begin: main_address,
        length: obj.symbol(main_symbol).size,
    }]));
    let root = dwarf.unit.root();
    let entry = dwarf.unit.get_mut(root);
    entry.set(
        gimli::DW_AT_producer,
        AttributeValue::String((*b"gimli example").into()),
    );
    entry.set(
        gimli::DW_AT_language,
        AttributeValue::Language(gimli::DW_LANG_C11),
    );
    entry.set(gimli::DW_AT_name, AttributeValue::String(file_name.into()));
    entry.set(
        gimli::DW_AT_comp_dir,
        AttributeValue::String(comp_dir.into()),
    );
    entry.set(gimli::DW_AT_low_pc, AttributeValue::Address(main_address));
    entry.set(
        gimli::DW_AT_ranges,
        AttributeValue::RangeListRef(range_list_id),
    );
    // DW_AT_stmt_list will be set automatically.

    // Add a line program for the main function.
    // For this example, we will only have one line in the line program.
    let line_strings = &mut dwarf.line_strings;
    let mut line_program = LineProgram::new(
        encoding,
        LineEncoding::default(),
        LineString::new(comp_dir, encoding, line_strings),
        LineString::new(file_name, encoding, line_strings),
        None,
    );
    let dir_id = line_program.default_directory();
    let file_string = LineString::new(file_name, encoding, line_strings);
    let file_id = line_program.add_file(file_string, dir_id, None);
    line_program.begin_sequence(Some(main_address));
    line_program.row().file = file_id;
    line_program.row().line = 2;
    line_program.generate_row();
    line_program.end_sequence(main_size);
    dwarf.unit.line_program = line_program;

    // Add a subprogram DIE for the main function.
    // Note that this example does not include all attributes.
    let subprogram = dwarf.unit.add(root, gimli::DW_TAG_subprogram);
    let entry = dwarf.unit.get_mut(subprogram);
    entry.set(gimli::DW_AT_external, AttributeValue::Flag(true));
    entry.set(gimli::DW_AT_name, AttributeValue::String(main_name.into()));
    entry.set(
        gimli::DW_AT_decl_file,
        AttributeValue::FileIndex(Some(file_id)),
    );
    entry.set(gimli::DW_AT_decl_line, AttributeValue::Udata(2));
    entry.set(gimli::DW_AT_decl_column, AttributeValue::Udata(5));
    entry.set(gimli::DW_AT_low_pc, AttributeValue::Address(main_address));
    entry.set(gimli::DW_AT_high_pc, AttributeValue::Udata(main_size));

    // Build the DWARF sections.
    // This will populate the sections with the DWARF data and relocations.
    let mut sections = Sections::new(Section::new());
    dwarf.write(&mut sections)?;

    // Add the DWARF section data to the object file.
    sections.for_each_mut(|id, section| -> object::write::Result<()> {
        if section.data.len() == 0 {
            return Ok(());
        }
        let kind = if id.is_string() {
            object::SectionKind::DebugString
        } else {
            object::SectionKind::Debug
        };
        let section_id = obj.add_section(Vec::new(), id.name().into(), kind);
        obj.set_section_data(section_id, section.data.take(), 1);

        // Record the section ID so that it can be used for relocations.
        section.id = Some(section_id);
        Ok(())
    })?;

    // Add the relocations to the object file.
    sections.for_each(|_, section| -> object::write::Result<()> {
        let Some(section_id) = section.id else {
            debug_assert!(section.relocations.is_empty());
            return Ok(());
        };
        for reloc in &section.relocations {
            // The `eh_pe` field is not used in this example because we are not writing
            // unwind information.
            debug_assert!(reloc.eh_pe.is_none());
            let (symbol, kind) = match reloc.target {
                RelocationTarget::Section(id) => {
                    let kind = if binary_format == object::BinaryFormat::Coff {
                        object::RelocationKind::SectionOffset
                    } else {
                        object::RelocationKind::Absolute
                    };
                    let symbol = obj.section_symbol(sections.get(id).unwrap().id.unwrap());
                    (symbol, kind)
                }
                RelocationTarget::Symbol(id) => {
                    // The main function is the only symbol we have defined.
                    debug_assert_eq!(id, 0);
                    (main_symbol, object::RelocationKind::Absolute)
                }
            };
            obj.add_relocation(
                section_id,
                object::write::Relocation {
                    offset: reloc.offset as u64,
                    symbol,
                    addend: reloc.addend,
                    flags: object::RelocationFlags::Generic {
                        kind,
                        encoding: object::RelocationEncoding::Generic,
                        size: reloc.size * 8,
                    },
                },
            )?;
        }
        Ok(())
    })?;

    // Finally, write the object file.
    let file = std::fs::File::create("hello.o")?;
    obj.write_stream(file)?;
    Ok(())
}

/// Define the data and symbol for the main function.
///
/// This function is unrelated to gimli. It's a copy of the `simple_write` example
/// from the `object` crate.
fn define_main(
    obj: &mut object::write::Object,
) -> Result<(object::write::SymbolId, u64), Box<dyn std::error::Error>> {
    // Add a file symbol (STT_FILE or equivalent).
    obj.add_file_symbol((*b"hello.c").into());

    // Generate code for the equivalent of this C function:
    //     int main() {
    //         puts("Hello, world!");
    //         return 0;
    //     }
    let mut main_data = Vec::new();
    // sub $0x28, %rsp
    main_data.extend_from_slice(&[0x48, 0x83, 0xec, 0x28]);
    // Handle different calling convention on Windows.
    if cfg!(target_os = "windows") {
        // lea 0x0(%rip), %rcx
        main_data.extend_from_slice(&[0x48, 0x8d, 0x0d, 0x00, 0x00, 0x00, 0x00]);
    } else {
        // lea 0x0(%rip), %rdi
        main_data.extend_from_slice(&[0x48, 0x8d, 0x3d, 0x00, 0x00, 0x00, 0x00]);
    }
    // R_X86_64_PC32 .rodata-0x4
    let s_reloc_offset = main_data.len() - 4;
    let s_reloc_addend = -4;
    let s_reloc_flags = object::RelocationFlags::Generic {
        kind: object::RelocationKind::Relative,
        encoding: object::RelocationEncoding::Generic,
        size: 32,
    };
    // call 14 <main+0x14>
    main_data.extend_from_slice(&[0xe8, 0x00, 0x00, 0x00, 0x00]);
    // R_X86_64_PLT32 puts-0x4
    let puts_reloc_offset = main_data.len() - 4;
    let puts_reloc_addend = -4;
    let puts_reloc_flags = object::RelocationFlags::Generic {
        kind: object::RelocationKind::PltRelative,
        encoding: object::RelocationEncoding::X86Branch,
        size: 32,
    };
    // xor %eax, %eax
    main_data.extend_from_slice(&[0x31, 0xc0]);
    // add $0x28, %rsp
    main_data.extend_from_slice(&[0x48, 0x83, 0xc4, 0x28]);
    // ret
    main_data.extend_from_slice(&[0xc3]);

    // Add a globally visible symbol for the main function.
    let main_symbol = obj.add_symbol(object::write::Symbol {
        name: (*b"main").into(),
        value: 0,
        size: 0,
        kind: object::SymbolKind::Text,
        scope: object::SymbolScope::Linkage,
        weak: false,
        section: object::write::SymbolSection::Undefined,
        flags: object::SymbolFlags::None,
    });
    // Add the main function in its own subsection (equivalent to -ffunction-sections).
    let main_section = obj.add_subsection(object::write::StandardSection::Text, b"main");
    let main_offset = obj.add_symbol_data(main_symbol, main_section, &main_data, 1);

    // Add a read only string constant for the puts argument.
    // We don't create a symbol for the constant, but instead refer to it by
    // the section symbol and section offset.
    let rodata_section = obj.section_id(object::write::StandardSection::ReadOnlyData);
    let rodata_symbol = obj.section_symbol(rodata_section);
    let s_offset = obj.append_section_data(rodata_section, b"Hello, world!\0", 1);

    // Relocation for the string constant.
    obj.add_relocation(
        main_section,
        object::write::Relocation {
            offset: main_offset + s_reloc_offset as u64,
            symbol: rodata_symbol,
            addend: s_offset as i64 + s_reloc_addend,
            flags: s_reloc_flags,
        },
    )?;

    // External symbol for puts.
    let puts_symbol = obj.add_symbol(object::write::Symbol {
        name: (*b"puts").into(),
        value: 0,
        size: 0,
        kind: object::SymbolKind::Text,
        scope: object::SymbolScope::Dynamic,
        weak: false,
        section: object::write::SymbolSection::Undefined,
        flags: object::SymbolFlags::None,
    });

    // Relocation for the call to puts.
    obj.add_relocation(
        main_section,
        object::write::Relocation {
            offset: puts_reloc_offset as u64,
            symbol: puts_symbol,
            addend: puts_reloc_addend,
            flags: puts_reloc_flags,
        },
    )?;

    Ok((main_symbol, main_data.len() as u64))
}
