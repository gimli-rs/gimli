// Allow clippy lints when building without clippy.
#![allow(unknown_lints)]

extern crate fallible_iterator;
extern crate gimli;
extern crate getopts;
extern crate memmap;
extern crate object;

use fallible_iterator::FallibleIterator;
use gimli::UnwindSection;
use object::Object;
use std::collections::HashMap;
use std::env;
use std::io;
use std::io::Write;
use std::fs;
use std::process;
use std::error;
use std::result;
use std::fmt::{self, Debug};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    GimliError(gimli::Error),
    IoError,
    MissingDIE,
}

impl fmt::Display for Error {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> ::std::result::Result<(), fmt::Error> {
        Debug::fmt(self, f)
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::GimliError(ref err) => err.description(),
            Error::IoError => "An I/O error occurred while reading.",
            Error::MissingDIE => "Expected a DIE but none was found",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::GimliError(ref err) => Some(err),
            _ => None,
        }
    }
}

impl From<gimli::Error> for Error {
    fn from(err: gimli::Error) -> Self {
        Error::GimliError(err)
    }
}

impl From<io::Error> for Error {
    fn from(_: io::Error) -> Self {
        Error::IoError
    }
}

pub type Result<T> = result::Result<T, Error>;

trait Reader: gimli::Reader<Offset = usize> {}

impl<'input, Endian> Reader for gimli::EndianBuf<'input, Endian>
where
    Endian: gimli::Endianity,
{
}

#[derive(Default)]
struct Flags {
    eh_frame: bool,
    info: bool,
    line: bool,
    pubnames: bool,
    pubtypes: bool,
    aranges: bool,
    raw: bool,
}

fn print_usage(opts: &getopts::Options) -> ! {
    let brief = format!("Usage: {} <options> <file>", env::args().next().unwrap());
    write!(&mut io::stderr(), "{}", opts.usage(&brief)).ok();
    process::exit(1);
}

fn main() {
    let mut opts = getopts::Options::new();
    opts.optflag(
        "",
        "eh-frame",
        "print .eh-frame exception handling frame information",
    );
    opts.optflag("i", "", "print .debug_info and .debug_types sections");
    opts.optflag("l", "", "print .debug_line section");
    opts.optflag("p", "", "print .debug_pubnames section");
    opts.optflag("r", "", "print .debug_aranges section");
    opts.optflag("y", "", "print .debug_pubtypes section");
    opts.optflag("", "raw", "print raw data values");

    let matches = match opts.parse(env::args().skip(1)) {
        Ok(m) => m,
        Err(e) => {
            writeln!(&mut io::stderr(), "{:?}\n", e).ok();
            print_usage(&opts);
        }
    };
    if matches.free.is_empty() {
        print_usage(&opts);
    }

    let mut all = true;
    let mut flags = Flags::default();
    if matches.opt_present("eh-frame") {
        flags.eh_frame = true;
        all = false;
    }
    if matches.opt_present("i") {
        flags.info = true;
        all = false;
    }
    if matches.opt_present("l") {
        flags.line = true;
        all = false;
    }
    if matches.opt_present("p") {
        flags.pubnames = true;
        all = false;
    }
    if matches.opt_present("y") {
        flags.pubtypes = true;
        all = false;
    }
    if matches.opt_present("r") {
        flags.aranges = true;
        all = false;
    }
    if matches.opt_present("raw") {
        flags.raw = true;
    }
    if all {
        // .eh_frame is excluded even when printing all information.
        flags.info = true;
        flags.line = true;
        flags.pubnames = true;
        flags.pubtypes = true;
        flags.aranges = true;
    }

    for file_path in &matches.free {
        if matches.free.len() != 1 {
            println!("{}", file_path);
            println!("");
        }

        let file = match fs::File::open(&file_path) {
            Ok(file) => file,
            Err(err) => {
                println!(
                    "Failed to open file '{}': {}",
                    file_path,
                    error::Error::description(&err)
                );
                continue;
            }
        };
        let file = match unsafe { memmap::Mmap::map(&file) } {
            Ok(mmap) => mmap,
            Err(err) => {
                println!(
                    "Failed to map file '{}': {}",
                    file_path,
                    error::Error::description(&err)
                );
                continue;
            }
        };
        let file = match object::File::parse(&*file) {
            Ok(file) => file,
            Err(err) => {
                println!("Failed to parse file '{}': {}", file_path, err);
                continue;
            }
        };

        let endian = if file.is_little_endian() {
            gimli::RunTimeEndian::Little
        } else {
            gimli::RunTimeEndian::Big
        };
        match dump_file(&file, endian, &flags) {
            Ok(_) => (),
            Err(err) => println!(
                "Failed to dump '{}': {}",
                file_path,
                error::Error::description(&err)
            ),
        }
    }
}

fn dump_file<Endian>(file: &object::File, endian: Endian, flags: &Flags) -> Result<()>
where
    Endian: gimli::Endianity,
{
    fn load_section<'input, 'file, S, Endian>(
        file: &'file object::File<'input>,
        endian: Endian,
    ) -> S
    where
        S: gimli::Section<gimli::EndianBuf<'input, Endian>>,
        Endian: gimli::Endianity,
        'file: 'input,
    {
        let data = file.section_data_by_name(S::section_name()).unwrap_or(&[]);
        S::from(gimli::EndianBuf::new(data, endian))
    }

    // Variables representing sections of the file. The type of each is inferred from its use in the
    // dump_* functions below.
    let eh_frame = &load_section(file, endian);
    let debug_abbrev = &load_section(file, endian);
    let debug_aranges = &load_section(file, endian);
    let debug_info = &load_section(file, endian);
    let debug_line = &load_section(file, endian);
    let debug_loc = &load_section(file, endian);
    let debug_loclists = &load_section(file, endian);
    let debug_pubnames = &load_section(file, endian);
    let debug_pubtypes = &load_section(file, endian);
    let debug_ranges = &load_section(file, endian);
    let debug_rnglists = &load_section(file, endian);
    let debug_str = &load_section(file, endian);
    let debug_types = &load_section(file, endian);

    if flags.eh_frame {
        dump_eh_frame(eh_frame)?;
    }
    if flags.info {
        dump_info(
            debug_info,
            debug_abbrev,
            debug_line,
            debug_loc,
            debug_loclists,
            debug_ranges,
            debug_rnglists,
            debug_str,
            endian,
            flags,
        )?;
        dump_types(
            debug_types,
            debug_abbrev,
            debug_line,
            debug_loc,
            debug_loclists,
            debug_ranges,
            debug_rnglists,
            debug_str,
            endian,
            flags,
        )?;
        println!("");
    }
    if flags.line {
        dump_line(debug_line, debug_info, debug_abbrev, debug_str)?;
    }
    if flags.pubnames {
        dump_pubnames(debug_pubnames, debug_info)?;
    }
    if flags.aranges {
        dump_aranges(debug_aranges, debug_info)?;
    }
    if flags.pubtypes {
        dump_pubtypes(debug_pubtypes, debug_info)?;
    }
    Ok(())
}

fn dump_eh_frame<R: Reader>(eh_frame: &gimli::EhFrame<R>) -> Result<()> {
    // TODO: Print "__eh_frame" here on macOS, and more generally use the
    // section that we're actually looking at, which is what the canonical
    // dwarfdump does.
    println!("Exception handling frame information for section .eh_frame");

    // TODO: when grabbing section contents in `dump_file`, we should also grab
    // these addresses.
    let bases = gimli::BaseAddresses::default()
        .set_cfi(0)
        .set_text(0)
        .set_data(0);

    let mut cies = HashMap::new();

    let mut entries = eh_frame.entries(&bases);
    loop {
        match entries.next()? {
            None => return Ok(()),
            Some(gimli::CieOrFde::Cie(cie)) => {
                println!();
                println!("{:#010x}: CIE", cie.offset());
                println!("        length: {:#010x}", cie.entry_len());
                // TODO: CIE_id
                println!("       version: {:#04x}", cie.version());
                // TODO: augmentation
                println!("    code_align: {}", cie.code_alignment_factor());
                println!("    data_align: {}", cie.data_alignment_factor());
                println!("   ra_register: {:#x}", cie.return_address_register());
                // TODO: aug_arg
                dump_cfi_instructions(cie.instructions(), true);
                println!();
            }
            Some(gimli::CieOrFde::Fde(partial)) => {
                let mut offset = None;
                let fde = partial.parse(|o| {
                    offset = Some(o);
                    cies.entry(o)
                        .or_insert_with(|| eh_frame.cie_from_offset(&bases, o))
                        .clone()
                })?;

                println!();
                println!("{:#010x}: FDE", fde.offset());
                println!("        length: {:#010x}", fde.entry_len());
                println!("   CIE_pointer: {:#010x}", offset.unwrap().0);
                // TODO: symbolicate the start address like the canonical dwarfdump does.
                println!("    start_addr: {:#018x}", fde.initial_address());
                println!(
                    "    range_size: {:#018x} (end_addr = {:#018x})",
                    fde.len(),
                    fde.initial_address() + fde.len()
                );
                dump_cfi_instructions(fde.instructions(), false);
                println!();
            }
        }
    }
}

fn dump_cfi_instructions<R: Reader>(
    mut insns: gimli::CallFrameInstructionIter<R>,
    is_initial: bool,
) {
    use gimli::CallFrameInstruction::*;

    // TODO: we need to actually evaluate these instructions as we iterate them
    // so we can print the initialized state for CIEs, and each unwind row's
    // registers for FDEs.
    //
    // TODO: We should turn register numbers into register names (eg "7" ->
    // "rsp" on x86_64).
    //
    // TODO: We should print DWARF expressions for the CFI instructions that
    // embed DWARF expressions within themselves.

    if !is_initial {
        println!("  Instructions:");
    }

    loop {
        match insns.next() {
            Err(e) => {
                println!("Failed to decode CFI instruction: {}", e);
                return;
            }
            Ok(None) => {
                if is_initial {
                    println!("  Instructions: Init State:");
                }
                return;
            }
            Ok(Some(op)) => match op {
                SetLoc { address } => {
                    println!("                DW_CFA_set_loc ({:#x})", address);
                }
                AdvanceLoc { delta } => {
                    println!("                DW_CFA_advance_loc ({})", delta);
                }
                DefCfa { register, offset } => {
                    println!("                DW_CFA_def_cfa ({}, {})", register, offset);
                }
                DefCfaSf {
                    register,
                    factored_offset,
                } => {
                    println!(
                        "                DW_CFA_def_cfa_sf ({}, {})",
                        register,
                        factored_offset
                    );
                }
                DefCfaRegister { register } => {
                    println!("                DW_CFA_def_cfa_register ({})", register);
                }
                DefCfaOffset { offset } => {
                    println!("                DW_CFA_def_cfa_offset ({})", offset);
                }
                DefCfaOffsetSf { factored_offset } => {
                    println!(
                        "                DW_CFA_def_cfa_offset_sf ({})",
                        factored_offset
                    );
                }
                DefCfaExpression { expression: _ } => {
                    println!("                DW_CFA_def_cfa_expression (...)");
                }
                Undefined { register } => {
                    println!("                DW_CFA_undefined ({})", register);
                }
                SameValue { register } => {
                    println!("                DW_CFA_same_value ({})", register);
                }
                Offset {
                    register,
                    factored_offset,
                } => {
                    println!(
                        "                DW_CFA_offset ({}, {})",
                        register,
                        factored_offset
                    );
                }
                OffsetExtendedSf {
                    register,
                    factored_offset,
                } => {
                    println!(
                        "                DW_CFA_offset_extended_sf ({}, {})",
                        register,
                        factored_offset
                    );
                }
                ValOffset {
                    register,
                    factored_offset,
                } => {
                    println!(
                        "                DW_CFA_val_offset ({}, {})",
                        register,
                        factored_offset
                    );
                }
                ValOffsetSf {
                    register,
                    factored_offset,
                } => {
                    println!(
                        "                DW_CFA_val_offset_sf ({}, {})",
                        register,
                        factored_offset
                    );
                }
                Register {
                    dest_register,
                    src_register,
                } => {
                    println!(
                        "                DW_CFA_register ({}, {})",
                        dest_register,
                        src_register
                    );
                }
                Expression {
                    register,
                    expression: _,
                } => {
                    println!("                DW_CFA_expression ({}, ...)", register);
                }
                ValExpression {
                    register,
                    expression: _,
                } => {
                    println!("                DW_CFA_val_expression ({}, ...)", register);
                }
                Restore { register } => {
                    println!("                DW_CFA_restore ({})", register);
                }
                RememberState => {
                    println!("                DW_CFA_remember_state");
                }
                RestoreState => {
                    println!("                DW_CFA_restore_state");
                }
                Nop => {
                    println!("                DW_CFA_nop");
                }
            },
        }
    }
}

#[allow(too_many_arguments)]
fn dump_info<R: Reader>(
    debug_info: &gimli::DebugInfo<R>,
    debug_abbrev: &gimli::DebugAbbrev<R>,
    debug_line: &gimli::DebugLine<R>,
    debug_loc: &gimli::DebugLoc<R>,
    debug_loclists: &gimli::DebugLocLists<R>,
    debug_ranges: &gimli::DebugRanges<R>,
    debug_rnglists: &gimli::DebugRngLists<R>,
    debug_str: &gimli::DebugStr<R>,
    endian: R::Endian,
    flags: &Flags,
) -> Result<()> {
    println!("\n.debug_info");

    let mut iter = debug_info.units();
    while let Some(unit) = iter.next()? {
        let abbrevs = match unit.abbreviations(debug_abbrev) {
            Ok(abbrevs) => abbrevs,
            Err(err) => {
                println!(
                    "Failed to parse abbreviations: {}",
                    error::Error::description(&err)
                );
                continue;
            }
        };

        let entries_result = dump_entries(
            unit.offset().0,
            unit.entries(&abbrevs),
            unit.address_size(),
            unit.version(),
            unit.format(),
            debug_line,
            debug_loc,
            debug_loclists,
            debug_ranges,
            debug_rnglists,
            debug_str,
            endian,
            flags,
        );
        if let Err(err) = entries_result {
            println!(
                "Failed to dump entries: {}",
                error::Error::description(&err)
            );
        };
    }
    Ok(())
}

#[allow(too_many_arguments)]
fn dump_types<R: Reader>(
    debug_types: &gimli::DebugTypes<R>,
    debug_abbrev: &gimli::DebugAbbrev<R>,
    debug_line: &gimli::DebugLine<R>,
    debug_loc: &gimli::DebugLoc<R>,
    debug_loclists: &gimli::DebugLocLists<R>,
    debug_ranges: &gimli::DebugRanges<R>,
    debug_rnglists: &gimli::DebugRngLists<R>,
    debug_str: &gimli::DebugStr<R>,
    endian: R::Endian,
    flags: &Flags,
) -> Result<()> {
    println!("\n.debug_types");

    let mut iter = debug_types.units();
    while let Some(unit) = iter.next()? {
        let abbrevs = match unit.abbreviations(debug_abbrev) {
            Ok(abbrevs) => abbrevs,
            Err(err) => {
                println!(
                    "Failed to parse abbreviations: {}",
                    error::Error::description(&err)
                );
                continue;
            }
        };

        println!("\nCU_HEADER:");
        print!("  signature        = ");
        dump_type_signature(unit.type_signature(), endian);
        println!("");
        println!(
            "  typeoffset       = 0x{:08x} {}",
            unit.type_offset().0,
            unit.type_offset().0
        );

        let entries_result = dump_entries(
            unit.offset().0,
            unit.entries(&abbrevs),
            unit.address_size(),
            unit.version(),
            unit.format(),
            debug_line,
            debug_loc,
            debug_loclists,
            debug_ranges,
            debug_rnglists,
            debug_str,
            endian,
            flags,
        );
        if let Err(err) = entries_result {
            println!(
                "Failed to dump entries: {}",
                error::Error::description(&err)
            )
        }
    }
    Ok(())
}

// TODO: most of this should be moved to the main library.
struct Unit<R: Reader> {
    endian: R::Endian,
    format: gimli::Format,
    address_size: u8,
    version: u16,
    base_address: u64,
    line_program: Option<gimli::IncompleteLineNumberProgram<R>>,
    comp_dir: Option<R>,
    comp_name: Option<R>,
}

#[allow(too_many_arguments)]
fn dump_entries<R: Reader>(
    offset: R::Offset,
    mut entries: gimli::EntriesCursor<R>,
    address_size: u8,
    version: u16,
    format: gimli::Format,
    debug_line: &gimli::DebugLine<R>,
    debug_loc: &gimli::DebugLoc<R>,
    debug_loclists: &gimli::DebugLocLists<R>,
    debug_ranges: &gimli::DebugRanges<R>,
    debug_rnglists: &gimli::DebugRngLists<R>,
    debug_str: &gimli::DebugStr<R>,
    endian: R::Endian,
    flags: &Flags,
) -> Result<()> {
    let mut unit = Unit {
        endian: endian,
        format: format,
        address_size: address_size,
        version: version,
        base_address: 0,
        line_program: None,
        comp_dir: None,
        comp_name: None,
    };

    let mut print_local = true;
    let mut depth = 0;
    while let Some((delta_depth, entry)) = entries.next_dfs()? {
        depth += delta_depth;
        assert!(depth >= 0);
        let indent = depth as usize * 2 + 2;
        if depth == 0 {
            println!("\nCOMPILE_UNIT<header overall offset = 0x{:08x}>:", offset);
            print_local = true;
        } else if print_local {
            println!("\nLOCAL_SYMBOLS:");
            print_local = false;
        }
        println!(
            "<{:2}><0x{:08x}>{:indent$}{}",
            depth,
            entry.offset().0,
            "",
            entry.tag(),
            indent = indent
        );

        if entry.tag() == gimli::DW_TAG_compile_unit || entry.tag() == gimli::DW_TAG_type_unit {
            unit.base_address = match entry.attr_value(gimli::DW_AT_low_pc)? {
                Some(gimli::AttributeValue::Addr(address)) => address,
                _ => 0,
            };
            unit.comp_dir = entry
                .attr(gimli::DW_AT_comp_dir)?
                .and_then(|attr| attr.string_value(debug_str));
            unit.comp_name = entry
                .attr(gimli::DW_AT_name)?
                .and_then(|attr| attr.string_value(debug_str));
            unit.line_program = match entry.attr_value(gimli::DW_AT_stmt_list)? {
                Some(gimli::AttributeValue::DebugLineRef(offset)) => debug_line
                    .program(
                        offset,
                        unit.address_size,
                        unit.comp_dir.clone(),
                        unit.comp_name.clone(),
                    )
                    .ok(),
                _ => None,
            }
        }

        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            print!("{:indent$}{:27} ", "", attr.name(), indent = indent + 18);
            if flags.raw {
                println!("{:?}", attr.raw_value());
            } else {
                match dump_attr_value(&attr, &unit, debug_loc, debug_loclists, debug_ranges, debug_rnglists, debug_str) {
                    Ok(_) => (),
                    Err(ref err) => println!(
                        "Failed to dump attribute value: {}",
                        error::Error::description(err)
                    ),
                };
            }
        }
    }
    Ok(())
}

fn dump_attr_value<R: Reader>(
    attr: &gimli::Attribute<R>,
    unit: &Unit<R>,
    debug_loc: &gimli::DebugLoc<R>,
    debug_loclists: &gimli::DebugLocLists<R>,
    debug_ranges: &gimli::DebugRanges<R>,
    debug_rnglists: &gimli::DebugRngLists<R>,
    debug_str: &gimli::DebugStr<R>,
) -> Result<()> {
    let value = attr.value();
    match value {
        gimli::AttributeValue::Addr(address) => {
            println!("0x{:08x}", address);
        }
        gimli::AttributeValue::Block(data) => {
            for byte in data.to_slice()?.iter() {
                print!("{:02x}", byte);
            }
            println!("");
        }
        gimli::AttributeValue::Data1(_) |
        gimli::AttributeValue::Data2(_) |
        gimli::AttributeValue::Data4(_) |
        gimli::AttributeValue::Data8(_) => {
            if let (Some(udata), Some(sdata)) = (attr.udata_value(), attr.sdata_value()) {
                if sdata >= 0 {
                    println!("{}", udata);
                } else {
                    println!("{} ({})", udata, sdata);
                }
            } else {
                println!("{:?}", value);
            }
        }
        gimli::AttributeValue::Sdata(data) => {
            match attr.name() {
                gimli::DW_AT_data_member_location => {
                    println!("{}", data);
                }
                _ => if data >= 0 {
                    println!("0x{:08x}", data);
                } else {
                    println!("0x{:08x} ({})", data, data);
                },
            };
        }
        gimli::AttributeValue::Udata(data) => {
            match attr.name() {
                gimli::DW_AT_high_pc => {
                    println!("<offset-from-lowpc>{}", data);
                }
                gimli::DW_AT_data_member_location => {
                    if let Some(sdata) = attr.sdata_value() {
                        // This is a DW_FORM_data* value.
                        // libdwarf-dwarfdump displays this as signed too.
                        if sdata >= 0 {
                            println!("{}", data);
                        } else {
                            println!("{} ({})", data, sdata);
                        }
                    } else {
                        println!("{}", data);
                    }
                }
                gimli::DW_AT_lower_bound | gimli::DW_AT_upper_bound => {
                    println!("{}", data);
                }
                _ => {
                    println!("0x{:08x}", data);
                }
            };
        }
        gimli::AttributeValue::Exprloc(ref data) => {
            if let gimli::AttributeValue::Exprloc(_) = attr.raw_value() {
                print!("len 0x{:04x}: ", data.0.len());
                for byte in data.0.to_slice()?.iter() {
                    print!("{:02x}", byte);
                }
                print!(": ");
            }
            dump_exprloc(data, unit)?;
            println!("");
        }
        gimli::AttributeValue::Flag(true) => {
            // We don't record what the value was, so assume 1.
            println!("yes(1)");
        }
        gimli::AttributeValue::Flag(false) => {
            println!("no");
        }
        gimli::AttributeValue::SecOffset(offset) => {
            println!("0x{:08x}", offset);
        }
        gimli::AttributeValue::UnitRef(gimli::UnitOffset(offset)) => {
            println!("<0x{:08x}>", offset);
        }
        gimli::AttributeValue::DebugInfoRef(gimli::DebugInfoOffset(offset)) => {
            println!("<GOFF=0x{:08x}>", offset);
        }
        gimli::AttributeValue::DebugLineRef(gimli::DebugLineOffset(offset)) => {
            println!("0x{:08x}", offset);
        }
        gimli::AttributeValue::DebugLocRef(offset) => {
            dump_loc_list(debug_loc, debug_loclists, offset, unit)?;
        }
        gimli::AttributeValue::DebugMacinfoRef(gimli::DebugMacinfoOffset(offset)) => {
            println!("{}", offset);
        }
        gimli::AttributeValue::DebugRangesRef(offset) => {
            println!("0x{:08x}", offset.0);
            dump_range_list(debug_ranges, debug_rnglists, offset, unit)?;
        }
        gimli::AttributeValue::DebugTypesRef(signature) => {
            dump_type_signature(signature, unit.endian);
            println!(" <type signature>");
        }
        gimli::AttributeValue::DebugStrRef(offset) => if let Ok(s) = debug_str.get_str(offset) {
            println!("{}", s.to_string_lossy()?);
        } else {
            println!("{:?}", value);
        },
        gimli::AttributeValue::String(s) => {
            println!("{}", s.to_string_lossy()?);
        }
        gimli::AttributeValue::Encoding(value) => {
            println!("{}", value);
        }
        gimli::AttributeValue::DecimalSign(value) => {
            println!("{}", value);
        }
        gimli::AttributeValue::Endianity(value) => {
            println!("{}", value);
        }
        gimli::AttributeValue::Accessibility(value) => {
            println!("{}", value);
        }
        gimli::AttributeValue::Visibility(value) => {
            println!("{}", value);
        }
        gimli::AttributeValue::Virtuality(value) => {
            println!("{}", value);
        }
        gimli::AttributeValue::Language(value) => {
            println!("{}", value);
        }
        gimli::AttributeValue::AddressClass(value) => {
            println!("{}", value);
        }
        gimli::AttributeValue::IdentifierCase(value) => {
            println!("{}", value);
        }
        gimli::AttributeValue::CallingConvention(value) => {
            println!("{}", value);
        }
        gimli::AttributeValue::Inline(value) => {
            println!("{}", value);
        }
        gimli::AttributeValue::Ordering(value) => {
            println!("{}", value);
        }
        gimli::AttributeValue::FileIndex(value) => {
            print!("0x{:08x}", value);
            dump_file_index(value, unit)?;
            println!("");
        }
    }

    Ok(())
}

fn dump_type_signature<Endian>(signature: gimli::DebugTypeSignature, endian: Endian)
where
    Endian: gimli::Endianity,
{
    // Convert back to bytes so we can match libdwarf-dwarfdump output.
    let mut buf = [0; 8];
    endian.write_u64(&mut buf, signature.0);
    print!("0x");
    for byte in &buf {
        print!("{:02x}", byte);
    }
}

fn dump_file_index<R: Reader>(file: u64, unit: &Unit<R>) -> Result<()> {
    if file == 0 {
        return Ok(());
    }
    let header = match unit.line_program {
        Some(ref program) => program.header(),
        None => return Ok(()),
    };
    let file = match header.file(file) {
        Some(header) => header,
        None => {
            println!("Unable to get header for file {}", file);
            return Ok(());
        }
    };
    print!(" ");
    if let Some(directory) = file.directory(header) {
        let directory = directory.to_string_lossy()?;
        if !directory.starts_with('/') {
            if let Some(ref comp_dir) = unit.comp_dir {
                print!("{}/", comp_dir.to_string_lossy()?);
            }
        }
        print!("{}/", directory);
    }
    print!("{}", file.path_name().to_string_lossy()?);
    Ok(())
}

fn dump_exprloc<R: Reader>(data: &gimli::Expression<R>, unit: &Unit<R>) -> Result<()> {
    let mut pc = data.0.clone();
    let mut space = false;
    while pc.len() != 0 {
        let mut op_pc = pc.clone();
        let dwop = gimli::DwOp(op_pc.read_u8()?);
        match gimli::Operation::parse(&mut pc, &data.0, unit.address_size, unit.format) {
            Ok(op) => {
                if space {
                    print!(" ");
                } else {
                    space = true;
                }
                dump_op(dwop, op, &pc)?;
            }
            Err(gimli::Error::InvalidExpression(op)) => {
                writeln!(
                    &mut std::io::stderr(),
                    "WARNING: unsupported operation 0x{:02x}",
                    op.0
                )?;
                return Ok(());
            }
            otherwise => panic!("Unexpected Operation::parse result: {:?}", otherwise),
        }
    }
    Ok(())
}

fn dump_op<R: Reader>(
    dwop: gimli::DwOp,
    op: gimli::Operation<R, R::Offset>,
    newpc: &R,
) -> Result<()> {
    print!("{}", dwop);
    match op {
        gimli::Operation::Deref { size, .. } => {
            if dwop == gimli::DW_OP_deref_size || dwop == gimli::DW_OP_xderef_size {
                print!(" {}", size);
            }
        }
        gimli::Operation::Pick { index } => if dwop == gimli::DW_OP_pick {
            print!(" {}", index);
        },
        gimli::Operation::PlusConstant { value } => {
            print!(" {}", value as i64);
        }
        gimli::Operation::Bra { target } => {
            let offset = newpc.len() as isize - target.len() as isize;
            print!(" {}", offset);
        }
        gimli::Operation::Skip { target } => {
            let offset = newpc.len() as isize - target.len() as isize;
            print!(" {}", offset);
        }
        gimli::Operation::Literal { value } => match dwop {
            gimli::DW_OP_const1s |
            gimli::DW_OP_const2s |
            gimli::DW_OP_const4s |
            gimli::DW_OP_const8s |
            gimli::DW_OP_consts => {
                print!(" {}", value as i64);
            }
            gimli::DW_OP_const1u |
            gimli::DW_OP_const2u |
            gimli::DW_OP_const4u |
            gimli::DW_OP_const8u |
            gimli::DW_OP_constu => {
                print!(" {}", value);
            }
            _ => {
                // These have the value encoded in the operation, eg DW_OP_lit0.
            }
        },
        gimli::Operation::Register { register } => if dwop == gimli::DW_OP_regx {
            print!(" {}", register);
        },
        gimli::Operation::RegisterOffset { offset, .. } => {
            print!("{:+}", offset);
        }
        gimli::Operation::FrameOffset { offset } => {
            print!(" {}", offset);
        }
        gimli::Operation::Call { offset } => match offset {
            gimli::DieReference::UnitRef(gimli::UnitOffset(offset)) => {
                print!(" 0x{:08x}", offset);
            }
            gimli::DieReference::DebugInfoRef(gimli::DebugInfoOffset(offset)) => {
                print!(" 0x{:08x}", offset);
            }
        },
        gimli::Operation::Piece {
            size_in_bits,
            bit_offset: None,
        } => {
            print!(" {}", size_in_bits / 8);
        }
        gimli::Operation::Piece {
            size_in_bits,
            bit_offset: Some(bit_offset),
        } => {
            print!(" 0x{:08x} offset 0x{:08x}", size_in_bits, bit_offset);
        }
        gimli::Operation::ImplicitValue { data } => {
            let data = data.to_slice()?;
            print!(" 0x{:08x} contents 0x", data.len());
            for byte in data.iter() {
                print!("{:02x}", byte);
            }
        }
        gimli::Operation::ImplicitPointer { value, byte_offset } => {
            print!(" 0x{:08x} {}", value.0, byte_offset);
        }
        gimli::Operation::EntryValue { expression } => {
            print!(" 0x{:08x} contents 0x", expression.len());
            for byte in expression.to_slice()?.iter() {
                print!("{:02x}", byte);
            }
        }
        gimli::Operation::ParameterRef { offset } => {
            print!(" 0x{:08x}", offset.0);
        }
        gimli::Operation::TextRelativeOffset { offset } => {
            print!(" 0x{:08x}", offset);
        }
        gimli::Operation::Drop |
        gimli::Operation::Swap |
        gimli::Operation::Rot |
        gimli::Operation::Abs |
        gimli::Operation::And |
        gimli::Operation::Div |
        gimli::Operation::Minus |
        gimli::Operation::Mod |
        gimli::Operation::Mul |
        gimli::Operation::Neg |
        gimli::Operation::Not |
        gimli::Operation::Or |
        gimli::Operation::Plus |
        gimli::Operation::Shl |
        gimli::Operation::Shr |
        gimli::Operation::Shra |
        gimli::Operation::Xor |
        gimli::Operation::Eq |
        gimli::Operation::Ge |
        gimli::Operation::Gt |
        gimli::Operation::Le |
        gimli::Operation::Lt |
        gimli::Operation::Ne |
        gimli::Operation::Nop |
        gimli::Operation::PushObjectAddress |
        gimli::Operation::TLS |
        gimli::Operation::CallFrameCFA |
        gimli::Operation::StackValue => {}
    };
    Ok(())
}

fn dump_loc_list<R: Reader>(
    debug_loc: &gimli::DebugLoc<R>,
    debug_loclists: &gimli::DebugLocLists<R>,
    offset: gimli::DebugLocOffset<R::Offset>,
    unit: &Unit<R>,
) -> Result<()> {
    if unit.version < 5 {
        let locations = debug_loc.raw_locations(offset, unit.address_size)?;
        let mut locations: Vec<_> = locations.collect()?;

        // libdwarf-dwarfdump doesn't include the end entry.
        let has_end = if let Some(location) = locations.last() {
            location.range.is_end()
        } else {
            false
        };
        if has_end {
            locations.pop();
        }
        if locations.is_empty() {
            println!("");
            return Ok(());
        }

        println!(
            "<loclist at offset 0x{:08x} with {} entries follows>",
            offset.0,
            locations.len()
        );
        let mut base_address = unit.base_address;
        for (i, location) in locations.iter().enumerate() {
            print!("\t\t\t[{:2}]", i);
            if location.range.is_end() {
                println!("<end-of-list>");
            } else if location.range.is_base_address(unit.address_size) {
                println!("<new base address 0x{:08x}>", location.range.end);
                base_address = location.range.end;
            } else {
                let mut range = location.range;
                range.add_base_address(base_address, unit.address_size);
                // This messed up formatting matches libdwarf-dwarfdump.
                print!(
                    "< offset pair \
                     low-off : 0x{:08x} addr  0x{:08x} \
                     high-off  0x{:08x} addr 0x{:08x}>",
                    location.range.begin,
                    range.begin,
                    location.range.end,
                    range.end
                );
                dump_exprloc(&location.data, unit)?;
                println!("");
            }
        }
    } else {
        let raw_locations = debug_loclists.raw_locations(offset)?;
        let raw_locations: Vec<_> = raw_locations.collect()?;
        let mut locations = debug_loclists.locations(offset, unit.base_address)?;

        println!(
            "<loclist at offset 0x{:08x} with {} entries follows>",
            offset.0,
            raw_locations.len()
        );
        for (i, raw) in raw_locations.iter().enumerate() {
            print!("\t\t\t[{:2}]", i);
            match raw {
                &gimli::RawLocListEntry::BaseAddress { addr } => {
                    println!("<new base address 0x{:08x}>", addr);
                },
                &gimli::RawLocListEntry::OffsetPair { begin, end, ref data } => {
                    let location = locations.next()?.unwrap();
                    // libdwarf-dwarfdump doesn't support .debug_loclists yet,
                    // so stop the misformatting madness
                    print!(
                        "<offset pair \
                         low-off: 0x{:08x} addr 0x{:08x} \
                         high-off: 0x{:08x} addr 0x{:08x}>",
                        begin,
                        location.range.begin,
                        end,
                        location.range.end
                    );
                    dump_exprloc(data, unit)?;
                    println!("");
                },
                &gimli::RawLocListEntry::DefaultLocation { ref data } => {
                    print!("<default location>");
                    dump_exprloc(data, unit)?;
                    println!("");
                },
                &gimli::RawLocListEntry::StartEnd { begin, end, ref data } => {
                    let location = locations.next()?.unwrap();
                    print!(
                        "<start-end \
                         low-off: 0x{:08x} addr 0x{:08x} \
                         high-off: 0x{:08x} addr 0x{:08x}>",
                        begin,
                        location.range.begin,
                        end,
                        location.range.end
                    );
                    dump_exprloc(data, unit)?;
                    println!("");
                },
                &gimli::RawLocListEntry::StartLength { begin, length, ref data } => {
                    let location = locations.next()?.unwrap();
                    print!(
                        "<start-length \
                         low-off: 0x{:08x} addr 0x{:08x} \
                         high-off: 0x{:08x} addr 0x{:08x}>",
                        begin,
                        location.range.begin,
                        length,
                        location.range.end
                    );
                    dump_exprloc(data, unit)?;
                    println!("");
                },
                _ => {
                    panic!("AddressIndex not handled, should already have errored out");
                },
            };
        }
    }
    Ok(())
}

fn dump_range_list<R: Reader>(
    debug_ranges: &gimli::DebugRanges<R>,
    debug_rnglists: &gimli::DebugRngLists<R>,
    offset: gimli::DebugRangesOffset<R::Offset>,
    unit: &Unit<R>,
) -> Result<()> {
    if unit.version < 5 {
        let ranges = debug_ranges.raw_ranges(offset, unit.address_size)?;
        let ranges: Vec<_> = ranges.collect()?;
        println!(
            "\t\tranges: {} at .debug_ranges offset {} (0x{:08x}) ({} bytes)",
            ranges.len(),
            offset.0,
            offset.0,
            ranges.len() * unit.address_size as usize * 2
        );
        for (i, range) in ranges.iter().enumerate() {
            print!("\t\t\t[{:2}] ", i);
            if range.is_end() {
                print!("range end     ");
            } else if range.is_base_address(unit.address_size) {
                print!("addr selection");
            } else {
                print!("range entry   ");
            }
            println!(" 0x{:08x} 0x{:08x}", range.begin, range.end);
        }
    } else {
        let raw_ranges = debug_rnglists.raw_ranges(offset)?;
        let raw_ranges: Vec<_> = raw_ranges.collect()?;
        let mut ranges = debug_rnglists.ranges(offset, unit.base_address)?;
        println!(
            "\t\tranges: {} at .debug_rnglists offset {} (0x{:08x})",
            raw_ranges.len(),
            offset.0,
            offset.0
        );
        for (i, raw) in raw_ranges.iter().enumerate() {
            print!("\t\t\t[{:2}] ", i);
            match raw {
                &gimli::RawRngListEntry::BaseAddress { addr } => {
                    println!("<new base address 0x{:08x}>", addr);
                },
                &gimli::RawRngListEntry::OffsetPair { begin, end } => {
                    let range = ranges.next()?.unwrap();
                    // libdwarf-dwarfdump doesn't support .debug_loclists yet,
                    // so stop the misformatting madness
                    println!(
                        "<offset pair \
                         low-off: 0x{:08x} addr 0x{:08x} \
                         high-off: 0x{:08x} addr 0x{:08x}>",
                        begin,
                        range.begin,
                        end,
                        range.end
                    );
                },
                &gimli::RawRngListEntry::StartEnd { begin, end } => {
                    let range = ranges.next()?.unwrap();
                    println!(
                        "<start-end \
                         low-off: 0x{:08x} addr 0x{:08x} \
                         high-off: 0x{:08x} addr 0x{:08x}>",
                        begin,
                        range.begin,
                        end,
                        range.end
                    );
                },
                &gimli::RawRngListEntry::StartLength { begin, length } => {
                    let range = ranges.next()?.unwrap();
                    println!(
                        "<start-length \
                         low-off: 0x{:08x} addr 0x{:08x} \
                         high-off: 0x{:08x} addr 0x{:08x}>",
                        begin,
                        range.begin,
                        length,
                        range.end
                    );
                },
                _ => {
                    panic!("AddressIndex not handled, should already have errored out");
                },
            };
        }
    }
    Ok(())
}

fn dump_line<R: Reader>(
    debug_line: &gimli::DebugLine<R>,
    debug_info: &gimli::DebugInfo<R>,
    debug_abbrev: &gimli::DebugAbbrev<R>,
    debug_str: &gimli::DebugStr<R>,
) -> Result<()> {
    println!("\n.debug_line");

    let mut iter = debug_info.units();
    while let Some(unit) = iter.next()? {
        let abbrevs = unit.abbreviations(debug_abbrev)?;

        let mut cursor = unit.entries(&abbrevs);
        cursor.next_dfs()?;

        let root = cursor.current().ok_or(Error::MissingDIE)?;
        let offset = match root.attr_value(gimli::DW_AT_stmt_list)? {
            Some(gimli::AttributeValue::DebugLineRef(offset)) => offset,
            _ => continue,
        };
        let comp_dir = root.attr(gimli::DW_AT_comp_dir)?
            .and_then(|attr| attr.string_value(debug_str));
        let comp_name = root.attr(gimli::DW_AT_name)?
            .and_then(|attr| attr.string_value(debug_str));

        let program = debug_line.program(offset, unit.address_size(), comp_dir, comp_name);
        if let Ok(program) = program {
            {
                let header = program.header();
                println!("");
                println!("Offset:                             0x{:x}", offset.0);
                println!(
                    "Length:                             {}",
                    header.unit_length()
                );
                println!("DWARF version:                      {}", header.version());
                println!(
                    "Prologue length:                    {}",
                    header.header_length()
                );
                println!(
                    "Minimum instruction length:         {}",
                    header.minimum_instruction_length()
                );
                println!(
                    "Maximum operations per instruction: {}",
                    header.maximum_operations_per_instruction()
                );
                println!(
                    "Default is_stmt:                    {}",
                    header.default_is_stmt()
                );
                println!("Line base:                          {}", header.line_base());
                println!(
                    "Line range:                         {}",
                    header.line_range()
                );
                println!(
                    "Opcode base:                        {}",
                    header.opcode_base()
                );

                println!("");
                println!("Opcodes:");
                for (i, length) in header
                    .standard_opcode_lengths()
                    .to_slice()?
                    .iter()
                    .enumerate()
                {
                    println!("  Opcode {} as {} args", i + 1, length);
                }

                println!("");
                println!("The Directory Table:");
                for (i, dir) in header.include_directories().iter().enumerate() {
                    println!("  {} {}", i + 1, dir.to_string_lossy()?);
                }

                println!("");
                println!("The File Name Table");
                println!("  Entry\tDir\tTime\tSize\tName");
                for (i, file) in header.file_names().iter().enumerate() {
                    println!(
                        "  {}\t{}\t{}\t{}\t{}",
                        i + 1,
                        file.directory_index(),
                        file.last_modification(),
                        file.length(),
                        file.path_name().to_string_lossy()?
                    );
                }

                println!("");
                println!("Line Number Statements:");
                let mut opcodes = header.opcodes();
                while let Some(opcode) = opcodes.next_opcode(header)? {
                    println!("  {}", opcode);
                }

                println!("");
                println!("Line Number Rows:");
                println!("<pc>        [lno,col]");
            }
            let mut rows = program.rows();
            let mut file_index = 0;
            while let Some((header, row)) = rows.next_row()? {
                let line = row.line().unwrap_or(0);
                let column = match row.column() {
                    gimli::ColumnType::Column(column) => column,
                    gimli::ColumnType::LeftEdge => 0,
                };
                print!("0x{:08x}  [{:4},{:2}]", row.address(), line, column);
                if row.is_stmt() {
                    print!(" NS");
                }
                if row.basic_block() {
                    print!(" BB");
                }
                if row.end_sequence() {
                    print!(" ET");
                }
                if row.prologue_end() {
                    print!(" PE");
                }
                if row.epilogue_begin() {
                    print!(" EB");
                }
                if row.isa() != 0 {
                    print!(" IS={}", row.isa());
                }
                if row.discriminator() != 0 {
                    print!(" DI={}", row.discriminator());
                }
                if file_index != row.file_index() {
                    file_index = row.file_index();
                    if let Some(file) = row.file(header) {
                        if let Some(directory) = file.directory(header) {
                            print!(
                                " uri: \"{}/{}\"",
                                directory.to_string_lossy()?,
                                file.path_name().to_string_lossy()?
                            );
                        } else {
                            print!(" uri: \"{}\"", file.path_name().to_string_lossy()?);
                        }
                    }
                }
                println!("");
            }
        }
    }
    Ok(())
}

fn dump_pubnames<R: Reader>(
    debug_pubnames: &gimli::DebugPubNames<R>,
    debug_info: &gimli::DebugInfo<R>,
) -> Result<()> {
    println!("\n.debug_pubnames");

    let mut cu_offset;
    let mut cu_die_offset = gimli::DebugInfoOffset(0);
    let mut prev_cu_offset = None;
    let mut pubnames = debug_pubnames.items();
    while let Some(pubname) = pubnames.next()? {
        cu_offset = pubname.unit_header_offset();
        if Some(cu_offset) != prev_cu_offset {
            let cu = debug_info.header_from_offset(cu_offset)?;
            cu_die_offset = gimli::DebugInfoOffset(cu_offset.0 + cu.header_size());
            prev_cu_offset = Some(cu_offset);
        }
        let die_in_cu = pubname.die_offset();
        let die_in_sect = cu_offset.0 + die_in_cu.0;
        println!(
            "global die-in-sect 0x{:08x}, cu-in-sect 0x{:08x}, die-in-cu 0x{:08x}, cu-header-in-sect 0x{:08x} '{}'",
            die_in_sect,
            cu_die_offset.0,
            die_in_cu.0,
            cu_offset.0,
            pubname.name().to_string_lossy()?
        )
    }
    Ok(())
}

fn dump_pubtypes<R: Reader>(
    debug_pubtypes: &gimli::DebugPubTypes<R>,
    debug_info: &gimli::DebugInfo<R>,
) -> Result<()> {
    println!("\n.debug_pubtypes");

    let mut cu_offset;
    let mut cu_die_offset = gimli::DebugInfoOffset(0);
    let mut prev_cu_offset = None;
    let mut pubtypes = debug_pubtypes.items();
    while let Some(pubtype) = pubtypes.next()? {
        cu_offset = pubtype.unit_header_offset();
        if Some(cu_offset) != prev_cu_offset {
            let cu = debug_info.header_from_offset(cu_offset)?;
            cu_die_offset = gimli::DebugInfoOffset(cu_offset.0 + cu.header_size());
            prev_cu_offset = Some(cu_offset);
        }
        let die_in_cu = pubtype.die_offset();
        let die_in_sect = cu_offset.0 + die_in_cu.0;
        println!(
            "pubtype die-in-sect 0x{:08x}, cu-in-sect 0x{:08x}, die-in-cu 0x{:08x}, cu-header-in-sect 0x{:08x} '{}'",
            die_in_sect,
            cu_die_offset.0,
            die_in_cu.0,
            cu_offset.0,
            pubtype.name().to_string_lossy()?
        )
    }
    Ok(())
}

fn dump_aranges<R: Reader>(
    debug_aranges: &gimli::DebugAranges<R>,
    debug_info: &gimli::DebugInfo<R>,
) -> Result<()> {
    println!("\n.debug_aranges");

    let mut cu_die_offset = gimli::DebugInfoOffset(0);
    let mut prev_cu_offset = None;
    let mut aranges = debug_aranges.items();
    while let Some(arange) = aranges.next()? {
        let cu_offset = arange.debug_info_offset();
        if Some(cu_offset) != prev_cu_offset {
            let cu = debug_info.header_from_offset(cu_offset)?;
            cu_die_offset = gimli::DebugInfoOffset(cu_offset.0 + cu.header_size());
            prev_cu_offset = Some(cu_offset);
        }
        if let Some(segment) = arange.segment() {
            print!(
                "arange starts at seg,off 0x{:08x},0x{:08x}, ",
                segment,
                arange.address()
            );
        } else {
            print!("arange starts at 0x{:08x}, ", arange.address());
        }
        println!(
            "length of 0x{:08x}, cu_die_offset = 0x{:08x}",
            arange.length(),
            cu_die_offset.0
        );
    }
    Ok(())
}
