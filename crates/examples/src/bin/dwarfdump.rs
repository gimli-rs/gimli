// Allow clippy lints when building without clippy.
#![allow(unknown_lints)]
// style: allow verbose lifetimes
#![allow(clippy::needless_lifetimes)]

use fallible_iterator::FallibleIterator;
use gimli::{Section, UnitHeader, UnitOffset, UnitSectionOffset, UnitType, UnwindSection};
use object::{Object, ObjectSection};
use regex::bytes::Regex;
use std::borrow::Cow;
use std::cmp;
use std::collections::HashMap;
use std::env;
use std::fmt::{self, Debug};
use std::fs;
use std::io;
use std::io::{BufWriter, Write};
use std::mem;
use std::process;
use std::result;
use std::sync::{Condvar, Mutex};
use typed_arena::Arena;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Error {
    Gimli(gimli::Error),
    Object(object::read::Error),
    Io,
}

impl fmt::Display for Error {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> ::std::result::Result<(), fmt::Error> {
        Debug::fmt(self, f)
    }
}

fn writeln_error<W: Write, R: Reader>(
    w: &mut W,
    dwarf: &gimli::Dwarf<R>,
    err: Error,
    msg: &str,
) -> io::Result<()> {
    writeln!(
        w,
        "{}: {}",
        msg,
        match err {
            Error::Gimli(err) => dwarf.format_error(err),
            Error::Object(err) => format!("{}:{:?}", "An object error occurred while reading", err),
            Error::Io => "An I/O error occurred while writing.".to_string(),
        }
    )
}

impl From<gimli::Error> for Error {
    fn from(err: gimli::Error) -> Self {
        Error::Gimli(err)
    }
}

impl From<io::Error> for Error {
    fn from(_: io::Error) -> Self {
        Error::Io
    }
}

impl From<object::read::Error> for Error {
    fn from(err: object::read::Error) -> Self {
        Error::Object(err)
    }
}

type Result<T> = result::Result<T, Error>;

fn parallel_output<W, II, F>(w: &mut W, max_workers: usize, iter: II, f: F) -> Result<()>
where
    W: Write + Send,
    F: Sync + Fn(II::Item, &mut Vec<u8>) -> Result<()>,
    II: IntoIterator,
    II::IntoIter: Send,
{
    struct ParallelOutputState<I, W> {
        iterator: I,
        current_worker: usize,
        result: Result<()>,
        w: W,
    }

    let state = Mutex::new(ParallelOutputState {
        iterator: iter.into_iter().fuse(),
        current_worker: 0,
        result: Ok(()),
        w,
    });
    let workers = cmp::min(max_workers, num_cpus::get());
    let mut condvars = Vec::new();
    for _ in 0..workers {
        condvars.push(Condvar::new());
    }
    {
        let state_ref = &state;
        let f_ref = &f;
        let condvars_ref = &condvars;
        crossbeam::scope(|scope| {
            for i in 0..workers {
                scope.spawn(move |_| {
                    let mut v = Vec::new();
                    let mut lock = state_ref.lock().unwrap();
                    while lock.current_worker != i {
                        lock = condvars_ref[i].wait(lock).unwrap();
                    }
                    loop {
                        let item = if lock.result.is_ok() {
                            lock.iterator.next()
                        } else {
                            None
                        };
                        lock.current_worker = (i + 1) % workers;
                        condvars_ref[lock.current_worker].notify_one();
                        mem::drop(lock);

                        let ret = if let Some(item) = item {
                            v.clear();
                            f_ref(item, &mut v)
                        } else {
                            return;
                        };

                        lock = state_ref.lock().unwrap();
                        while lock.current_worker != i {
                            lock = condvars_ref[i].wait(lock).unwrap();
                        }
                        if lock.result.is_ok() {
                            let ret2 = lock.w.write_all(&v);
                            if ret.is_err() {
                                lock.result = ret;
                            } else {
                                lock.result = ret2.map_err(Error::from);
                            }
                        }
                    }
                });
            }
        })
        .unwrap();
    }
    state.into_inner().unwrap().result
}

#[derive(Debug, Default)]
struct RelocationMap(object::read::RelocationMap);

impl RelocationMap {
    fn add(&mut self, file: &object::File, section: &object::Section) {
        for (offset, relocation) in section.relocations() {
            if let Err(e) = self.0.add(file, offset, relocation) {
                eprintln!(
                    "Relocation error for section {} at offset 0x{:08x}: {}",
                    section.name().unwrap(),
                    offset,
                    e
                );
            }
        }
    }
}

impl<'a> gimli::read::Relocate for &'a RelocationMap {
    fn relocate_address(&self, offset: usize, value: u64) -> gimli::Result<u64> {
        Ok(self.0.relocate(offset as u64, value))
    }

    fn relocate_offset(&self, offset: usize, value: usize) -> gimli::Result<usize> {
        <usize as gimli::ReaderOffset>::from_u64(self.0.relocate(offset as u64, value as u64))
    }
}

type Relocate<'a, R> = gimli::RelocateReader<R, &'a RelocationMap>;

trait Reader: gimli::Reader<Offset = usize> + Send + Sync {}

impl<'a, R: gimli::Reader<Offset = usize> + Send + Sync> Reader for Relocate<'a, R> {}

#[derive(Default)]
struct Flags<'a> {
    eh_frame: bool,
    goff: bool,
    info: bool,
    line: bool,
    pubnames: bool,
    pubtypes: bool,
    aranges: bool,
    addr: bool,
    dwo: bool,
    dwp: bool,
    dwo_parent: Option<object::File<'a>>,
    sup: Option<object::File<'a>>,
    raw: bool,
    match_units: Option<Regex>,
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
    opts.optflag("G", "", "show global die offsets");
    opts.optflag("i", "", "print .debug_info and .debug_types sections");
    opts.optflag("l", "", "print .debug_line section");
    opts.optflag("p", "", "print .debug_pubnames section");
    opts.optflag("r", "", "print .debug_aranges section");
    opts.optflag("y", "", "print .debug_pubtypes section");
    opts.optflag("", "debug-addr", "print .debug_addr section");
    opts.optflag(
        "",
        "dwo",
        "print the .dwo versions of the selected sections",
    );
    opts.optflag(
        "",
        "dwp",
        "print the .dwp versions of the selected sections",
    );
    opts.optopt(
        "",
        "dwo-parent",
        "use the specified file as the parent of the dwo or dwp (e.g. for .debug_addr)",
        "library path",
    );
    opts.optflag("", "raw", "print raw data values");
    opts.optopt(
        "u",
        "match-units",
        "print compilation units whose output matches a regex",
        "REGEX",
    );
    opts.optopt("", "sup", "path to supplementary object file", "PATH");

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
    if matches.opt_present("G") {
        flags.goff = true;
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
    if matches.opt_present("debug-addr") {
        flags.addr = true;
        all = false;
    }
    if matches.opt_present("dwo") {
        flags.dwo = true;
    }
    if matches.opt_present("dwp") {
        flags.dwp = true;
    }
    if matches.opt_present("raw") {
        flags.raw = true;
    }
    if all {
        // .eh_frame is excluded even when printing all information.
        // cosmetic flags like -G must be set explicitly too.
        flags.info = true;
        flags.line = true;
        flags.pubnames = true;
        flags.pubtypes = true;
        flags.aranges = true;
        flags.addr = true;
    }
    flags.match_units = if let Some(r) = matches.opt_str("u") {
        match Regex::new(&r) {
            Ok(r) => Some(r),
            Err(e) => {
                eprintln!("Invalid regular expression {}: {}", r, e);
                process::exit(1);
            }
        }
    } else {
        None
    };

    let arena_mmap = Arena::new();
    let load_file = |path| {
        let file = match fs::File::open(&path) {
            Ok(file) => file,
            Err(err) => {
                eprintln!("Failed to open file '{}': {}", path, err);
                process::exit(1);
            }
        };
        let mmap = match unsafe { memmap2::Mmap::map(&file) } {
            Ok(mmap) => mmap,
            Err(err) => {
                eprintln!("Failed to map file '{}': {}", path, err);
                process::exit(1);
            }
        };
        let mmap_ref = arena_mmap.alloc(mmap);
        match object::File::parse(&**mmap_ref) {
            Ok(file) => Some(file),
            Err(err) => {
                eprintln!("Failed to parse file '{}': {}", path, err);
                process::exit(1);
            }
        }
    };

    flags.sup = matches.opt_str("sup").and_then(load_file);
    flags.dwo_parent = matches.opt_str("dwo-parent").and_then(load_file);
    if flags.dwo_parent.is_some() && !flags.dwo && !flags.dwp {
        eprintln!("--dwo-parent also requires --dwo or --dwp");
        process::exit(1);
    }
    if flags.dwo_parent.is_none() && flags.dwp {
        eprintln!("--dwp also requires --dwo-parent");
        process::exit(1);
    }

    for file_path in &matches.free {
        if matches.free.len() != 1 {
            println!("{}", file_path);
            println!();
        }

        let file = match fs::File::open(file_path) {
            Ok(file) => file,
            Err(err) => {
                eprintln!("Failed to open file '{}': {}", file_path, err);
                continue;
            }
        };
        let file = match unsafe { memmap2::Mmap::map(&file) } {
            Ok(mmap) => mmap,
            Err(err) => {
                eprintln!("Failed to map file '{}': {}", file_path, err);
                continue;
            }
        };
        let file = match object::File::parse(&*file) {
            Ok(file) => file,
            Err(err) => {
                eprintln!("Failed to parse file '{}': {}", file_path, err);
                continue;
            }
        };

        let endian = if file.is_little_endian() {
            gimli::RunTimeEndian::Little
        } else {
            gimli::RunTimeEndian::Big
        };
        let ret = dump_file(&file, endian, &flags);
        match ret {
            Ok(_) => (),
            Err(err) => eprintln!("Failed to dump '{}': {}", file_path, err,),
        }
    }
}

fn load_file_section<'input, 'arena, Endian: gimli::Endianity>(
    id: gimli::SectionId,
    file: &object::File<'input>,
    endian: Endian,
    is_dwo: bool,
    arena_data: &'arena Arena<Cow<'input, [u8]>>,
    arena_relocations: &'arena Arena<RelocationMap>,
) -> Result<Relocate<'arena, gimli::EndianSlice<'arena, Endian>>> {
    let mut relocations = RelocationMap::default();
    let name = if is_dwo {
        id.dwo_name()
    } else if file.format() == object::BinaryFormat::Xcoff {
        id.xcoff_name()
    } else {
        Some(id.name())
    };

    let data = match name.and_then(|name| file.section_by_name(name)) {
        Some(ref section) => {
            // DWO sections never have relocations, so don't bother.
            if !is_dwo {
                relocations.add(file, section);
            }
            section.uncompressed_data()?
        }
        // Use a non-zero capacity so that `ReaderOffsetId`s are unique.
        None => Cow::Owned(Vec::with_capacity(1)),
    };
    let data_ref = arena_data.alloc(data);
    let section = gimli::EndianSlice::new(data_ref, endian);
    let relocations = arena_relocations.alloc(relocations);
    Ok(Relocate::new(section, relocations))
}

fn dump_file<Endian>(file: &object::File, endian: Endian, flags: &Flags) -> Result<()>
where
    Endian: gimli::Endianity + Send + Sync,
{
    let arena_data = Arena::new();
    let arena_relocations = Arena::new();

    let dwo_parent = if let Some(dwo_parent_file) = flags.dwo_parent.as_ref() {
        let mut load_dwo_parent_section = |id: gimli::SectionId| -> Result<_> {
            load_file_section(
                id,
                dwo_parent_file,
                endian,
                false,
                &arena_data,
                &arena_relocations,
            )
        };
        Some(gimli::Dwarf::load(&mut load_dwo_parent_section)?)
    } else {
        None
    };
    let dwo_parent = dwo_parent.as_ref();

    let dwo_parent_units = if let Some(dwo_parent) = dwo_parent {
        Some(
            match dwo_parent
                .units()
                .map(|unit_header| dwo_parent.unit(unit_header))
                .filter_map(|unit| Ok(unit.dwo_id.map(|dwo_id| (dwo_id, unit))))
                .collect()
            {
                Ok(units) => units,
                Err(err) => {
                    eprintln!("Failed to process --dwo-parent units: {}", err);
                    return Ok(());
                }
            },
        )
    } else {
        None
    };
    let dwo_parent_units = dwo_parent_units.as_ref();

    let mut load_section = |id: gimli::SectionId| -> Result<_> {
        load_file_section(
            id,
            file,
            endian,
            flags.dwo || flags.dwp,
            &arena_data,
            &arena_relocations,
        )
    };

    let w = &mut BufWriter::new(io::stdout());
    if flags.dwp {
        let empty_relocations = arena_relocations.alloc(RelocationMap::default());
        let empty = Relocate::new(gimli::EndianSlice::new(&[], endian), empty_relocations);
        let dwp = gimli::DwarfPackage::load(&mut load_section, empty)?;
        dump_dwp(w, &dwp, dwo_parent.unwrap(), dwo_parent_units, flags)?;
        w.flush()?;
        return Ok(());
    }

    let mut dwarf = gimli::Dwarf::load(&mut load_section)?;
    if flags.dwo {
        if let Some(dwo_parent) = dwo_parent {
            dwarf.make_dwo(dwo_parent);
        } else {
            dwarf.file_type = gimli::DwarfFileType::Dwo;
        }
    }

    if let Some(sup_file) = flags.sup.as_ref() {
        let mut load_sup_section = |id: gimli::SectionId| -> Result<_> {
            // Note: we really only need the `.debug_str` section,
            // but for now we load them all.
            load_file_section(id, sup_file, endian, false, &arena_data, &arena_relocations)
        };
        dwarf.load_sup(&mut load_sup_section)?;
    }

    dwarf.populate_abbreviations_cache(gimli::AbbreviationsCacheStrategy::All);

    if flags.eh_frame {
        let eh_frame = gimli::EhFrame::load(load_section).unwrap();
        dump_eh_frame(w, file, eh_frame)?;
    }
    if flags.info {
        dump_info(w, &dwarf, dwo_parent_units, flags)?;
        dump_types(w, &dwarf, dwo_parent_units, flags)?;
    }
    if flags.line {
        dump_line(w, &dwarf)?;
    }
    if flags.pubnames {
        let debug_pubnames = &gimli::Section::load(load_section).unwrap();
        dump_pubnames(w, debug_pubnames, &dwarf.debug_info)?;
    }
    if flags.aranges {
        let debug_aranges = &gimli::Section::load(load_section).unwrap();
        dump_aranges(w, debug_aranges)?;
    }
    if flags.addr {
        let debug_addr = &gimli::Section::load(load_section).unwrap();
        dump_addr(w, debug_addr)?;
    }
    if flags.pubtypes {
        let debug_pubtypes = &gimli::Section::load(load_section).unwrap();
        dump_pubtypes(w, debug_pubtypes, &dwarf.debug_info)?;
    }
    w.flush()?;
    Ok(())
}

fn dump_eh_frame<R: Reader, W: Write>(
    w: &mut W,
    file: &object::File,
    mut eh_frame: gimli::EhFrame<R>,
) -> Result<()> {
    // TODO: this might be better based on the file format.
    let address_size = file
        .architecture()
        .address_size()
        .map(|w| w.bytes())
        .unwrap_or(mem::size_of::<usize>() as u8);
    eh_frame.set_address_size(address_size);

    // There are other things we could match but currently don't
    #[allow(clippy::single_match)]
    match file.architecture() {
        object::Architecture::Aarch64 => eh_frame.set_vendor(gimli::Vendor::AArch64),
        _ => {}
    }

    fn register_name_none(_: gimli::Register) -> Option<&'static str> {
        None
    }
    let arch_register_name = match file.architecture() {
        object::Architecture::PowerPc64 => gimli::PowerPc64::register_name,
        object::Architecture::Arm | object::Architecture::Aarch64 => gimli::Arm::register_name,
        object::Architecture::I386 => gimli::X86::register_name,
        object::Architecture::X86_64 => gimli::X86_64::register_name,
        _ => register_name_none,
    };
    let register_name = &|register| match arch_register_name(register) {
        Some(name) => Cow::Borrowed(name),
        None => Cow::Owned(format!("{}", register.0)),
    };

    let mut bases = gimli::BaseAddresses::default();
    if let Some(section) = file.section_by_name(".eh_frame_hdr") {
        bases = bases.set_eh_frame_hdr(section.address());
    }
    if let Some(section) = file.section_by_name(".eh_frame") {
        bases = bases.set_eh_frame(section.address());
    }
    if let Some(section) = file.section_by_name(".text") {
        bases = bases.set_text(section.address());
    }
    if let Some(section) = file.section_by_name(".got") {
        bases = bases.set_got(section.address());
    }

    // TODO: Print "__eh_frame" here on macOS, and more generally use the
    // section that we're actually looking at, which is what the canonical
    // dwarfdump does.
    writeln!(
        w,
        "Exception handling frame information for section .eh_frame"
    )?;

    let mut cies = HashMap::new();

    let mut entries = eh_frame.entries(&bases);
    loop {
        match entries.next()? {
            None => return Ok(()),
            Some(gimli::CieOrFde::Cie(cie)) => {
                writeln!(w)?;
                writeln!(w, "{:#010x}: CIE", cie.offset())?;
                writeln!(w, "        length: {:#010x}", cie.entry_len())?;
                // TODO: CIE_id
                writeln!(w, "       version: {:#04x}", cie.version())?;
                // TODO: augmentation
                writeln!(w, "    code_align: {}", cie.code_alignment_factor())?;
                writeln!(w, "    data_align: {}", cie.data_alignment_factor())?;
                writeln!(
                    w,
                    "   ra_register: {}",
                    register_name(cie.return_address_register())
                )?;
                if let Some(encoding) = cie.lsda_encoding() {
                    writeln!(
                        w,
                        " lsda_encoding: {}/{}",
                        encoding.application(),
                        encoding.format()
                    )?;
                }
                if let Some((encoding, personality)) = cie.personality_with_encoding() {
                    write!(
                        w,
                        "   personality: {}/{} ",
                        encoding.application(),
                        encoding.format()
                    )?;
                    dump_pointer(w, personality)?;
                    writeln!(w)?;
                }
                if let Some(encoding) = cie.fde_address_encoding() {
                    writeln!(
                        w,
                        "  fde_encoding: {}/{}",
                        encoding.application(),
                        encoding.format()
                    )?;
                }
                let instructions = cie.instructions(&eh_frame, &bases);
                dump_cfi_instructions(w, instructions, true, register_name)?;
                writeln!(w)?;
            }
            Some(gimli::CieOrFde::Fde(partial)) => {
                writeln!(w)?;
                writeln!(w, "{:#010x}: FDE", partial.offset())?;
                writeln!(w, "        length: {:#010x}", partial.entry_len())?;
                writeln!(w, "   CIE_pointer: {:#010x}", partial.cie_offset().0)?;

                let fde = match partial.parse(|_, bases, o| {
                    cies.entry(o)
                        .or_insert_with(|| eh_frame.cie_from_offset(bases, o))
                        .clone()
                }) {
                    Ok(fde) => fde,
                    Err(e) => {
                        writeln!(w, "Failed to parse FDE: {}", e)?;
                        continue;
                    }
                };

                // TODO: symbolicate the start address like the canonical dwarfdump does.
                writeln!(w, "    start_addr: {:#x}", fde.initial_address())?;
                writeln!(
                    w,
                    "    range_size: {:#x} (end_addr = {:#x})",
                    fde.len(),
                    fde.end_address(),
                )?;
                if let Some(lsda) = fde.lsda() {
                    write!(w, "          lsda: ")?;
                    dump_pointer(w, lsda)?;
                    writeln!(w)?;
                }
                let instructions = fde.instructions(&eh_frame, &bases);
                dump_cfi_instructions(w, instructions, false, register_name)?;
                writeln!(w)?;
            }
        }
    }
}

fn dump_pointer<W: Write>(w: &mut W, p: gimli::Pointer) -> Result<()> {
    match p {
        gimli::Pointer::Direct(p) => {
            write!(w, "{:#x}", p)?;
        }
        gimli::Pointer::Indirect(p) => {
            write!(w, "({:#x})", p)?;
        }
    }
    Ok(())
}

#[allow(clippy::unneeded_field_pattern)]
fn dump_cfi_instructions<R: Reader, W: Write>(
    w: &mut W,
    mut insns: gimli::CallFrameInstructionIter<R>,
    is_initial: bool,
    register_name: &dyn Fn(gimli::Register) -> Cow<'static, str>,
) -> Result<()> {
    use gimli::CallFrameInstruction::*;

    // TODO: we need to actually evaluate these instructions as we iterate them
    // so we can print the initialized state for CIEs, and each unwind row's
    // registers for FDEs.
    //
    // TODO: We should print DWARF expressions for the CFI instructions that
    // embed DWARF expressions within themselves.

    if !is_initial {
        writeln!(w, "  Instructions:")?;
    }

    loop {
        match insns.next() {
            Err(e) => {
                writeln!(w, "Failed to decode CFI instruction: {}", e)?;
                return Ok(());
            }
            Ok(None) => {
                if is_initial {
                    writeln!(w, "  Instructions: Init State:")?;
                }
                return Ok(());
            }
            Ok(Some(op)) => match op {
                SetLoc { address } => {
                    writeln!(w, "                DW_CFA_set_loc ({:#x})", address)?;
                }
                AdvanceLoc { delta } => {
                    writeln!(w, "                DW_CFA_advance_loc ({})", delta)?;
                }
                DefCfa { register, offset } => {
                    writeln!(
                        w,
                        "                DW_CFA_def_cfa ({}, {})",
                        register_name(register),
                        offset
                    )?;
                }
                DefCfaSf {
                    register,
                    factored_offset,
                } => {
                    writeln!(
                        w,
                        "                DW_CFA_def_cfa_sf ({}, {})",
                        register_name(register),
                        factored_offset
                    )?;
                }
                DefCfaRegister { register } => {
                    writeln!(
                        w,
                        "                DW_CFA_def_cfa_register ({})",
                        register_name(register)
                    )?;
                }
                DefCfaOffset { offset } => {
                    writeln!(w, "                DW_CFA_def_cfa_offset ({})", offset)?;
                }
                DefCfaOffsetSf { factored_offset } => {
                    writeln!(
                        w,
                        "                DW_CFA_def_cfa_offset_sf ({})",
                        factored_offset
                    )?;
                }
                DefCfaExpression { expression: _ } => {
                    writeln!(w, "                DW_CFA_def_cfa_expression (...)")?;
                }
                Undefined { register } => {
                    writeln!(
                        w,
                        "                DW_CFA_undefined ({})",
                        register_name(register)
                    )?;
                }
                SameValue { register } => {
                    writeln!(
                        w,
                        "                DW_CFA_same_value ({})",
                        register_name(register)
                    )?;
                }
                Offset {
                    register,
                    factored_offset,
                } => {
                    writeln!(
                        w,
                        "                DW_CFA_offset ({}, {})",
                        register_name(register),
                        factored_offset
                    )?;
                }
                OffsetExtendedSf {
                    register,
                    factored_offset,
                } => {
                    writeln!(
                        w,
                        "                DW_CFA_offset_extended_sf ({}, {})",
                        register_name(register),
                        factored_offset
                    )?;
                }
                ValOffset {
                    register,
                    factored_offset,
                } => {
                    writeln!(
                        w,
                        "                DW_CFA_val_offset ({}, {})",
                        register_name(register),
                        factored_offset
                    )?;
                }
                ValOffsetSf {
                    register,
                    factored_offset,
                } => {
                    writeln!(
                        w,
                        "                DW_CFA_val_offset_sf ({}, {})",
                        register_name(register),
                        factored_offset
                    )?;
                }
                Register {
                    dest_register,
                    src_register,
                } => {
                    writeln!(
                        w,
                        "                DW_CFA_register ({}, {})",
                        register_name(dest_register),
                        register_name(src_register)
                    )?;
                }
                Expression {
                    register,
                    expression: _,
                } => {
                    writeln!(
                        w,
                        "                DW_CFA_expression ({}, ...)",
                        register_name(register)
                    )?;
                }
                ValExpression {
                    register,
                    expression: _,
                } => {
                    writeln!(
                        w,
                        "                DW_CFA_val_expression ({}, ...)",
                        register_name(register)
                    )?;
                }
                Restore { register } => {
                    writeln!(
                        w,
                        "                DW_CFA_restore ({})",
                        register_name(register)
                    )?;
                }
                RememberState => {
                    writeln!(w, "                DW_CFA_remember_state")?;
                }
                RestoreState => {
                    writeln!(w, "                DW_CFA_restore_state")?;
                }
                ArgsSize { size } => {
                    writeln!(w, "                DW_CFA_GNU_args_size ({})", size)?;
                }
                NegateRaState => {
                    writeln!(w, "                DW_CFA_AARCH64_negate_ra_state")?;
                }
                Nop => {
                    writeln!(w, "                DW_CFA_nop")?;
                }
            },
        }
    }
}

fn dump_dwp<R: Reader, W: Write + Send>(
    w: &mut W,
    dwp: &gimli::DwarfPackage<R>,
    dwo_parent: &gimli::Dwarf<R>,
    dwo_parent_units: Option<&HashMap<gimli::DwoId, gimli::Unit<R>>>,
    flags: &Flags,
) -> Result<()>
where
    R::Endian: Send + Sync,
{
    if dwp.cu_index.version() != 0 {
        writeln!(
            w,
            "\n.debug_cu_index: version = {}, sections = {}, units = {}, slots = {}",
            dwp.cu_index.version(),
            dwp.cu_index.section_count(),
            dwp.cu_index.unit_count(),
            dwp.cu_index.slot_count(),
        )?;
        for i in 1..=dwp.cu_index.unit_count() {
            writeln!(w, "\nCU index {}", i)?;
            dump_dwp_sections(
                w,
                dwp,
                dwo_parent,
                dwo_parent_units,
                flags,
                dwp.cu_index.sections(i)?,
            )?;
        }
    }

    if dwp.tu_index.version() != 0 {
        writeln!(
            w,
            "\n.debug_tu_index: version = {}, sections = {}, units = {}, slots = {}",
            dwp.tu_index.version(),
            dwp.tu_index.section_count(),
            dwp.tu_index.unit_count(),
            dwp.tu_index.slot_count(),
        )?;
        for i in 1..=dwp.tu_index.unit_count() {
            writeln!(w, "\nTU index {}", i)?;
            dump_dwp_sections(
                w,
                dwp,
                dwo_parent,
                dwo_parent_units,
                flags,
                dwp.tu_index.sections(i)?,
            )?;
        }
    }

    Ok(())
}

fn dump_dwp_sections<R: Reader, W: Write + Send>(
    w: &mut W,
    dwp: &gimli::DwarfPackage<R>,
    dwo_parent: &gimli::Dwarf<R>,
    dwo_parent_units: Option<&HashMap<gimli::DwoId, gimli::Unit<R>>>,
    flags: &Flags,
    sections: gimli::UnitIndexSectionIterator<R>,
) -> Result<()>
where
    R::Endian: Send + Sync,
{
    for section in sections.clone() {
        writeln!(
            w,
            "  {}: offset = 0x{:x}, size = 0x{:x}",
            section.section.dwo_name(),
            section.offset,
            section.size
        )?;
    }
    let dwarf = dwp.sections(sections, dwo_parent)?;
    if flags.info {
        dump_info(w, &dwarf, dwo_parent_units, flags)?;
        dump_types(w, &dwarf, dwo_parent_units, flags)?;
    }
    if flags.line {
        dump_line(w, &dwarf)?;
    }
    Ok(())
}

fn dump_info<R: Reader, W: Write + Send>(
    w: &mut W,
    dwarf: &gimli::Dwarf<R>,
    dwo_parent_units: Option<&HashMap<gimli::DwoId, gimli::Unit<R>>>,
    flags: &Flags,
) -> Result<()>
where
    R::Endian: Send + Sync,
{
    writeln!(w, "\n.debug_info")?;

    let units = match dwarf.units().collect::<Vec<_>>() {
        Ok(units) => units,
        Err(err) => {
            writeln_error(w, dwarf, Error::Gimli(err), "Failed to read unit headers")?;
            return Ok(());
        }
    };
    let process_unit = |header: UnitHeader<R>, buf: &mut Vec<u8>| -> Result<()> {
        dump_unit(buf, header, dwarf, dwo_parent_units, flags)?;
        if !flags
            .match_units
            .as_ref()
            .map(|r| r.is_match(buf))
            .unwrap_or(true)
        {
            buf.clear();
        }
        Ok(())
    };
    // Don't use more than 16 cores even if available. No point in soaking hundreds
    // of cores if you happen to have them.
    parallel_output(w, 16, units, process_unit)
}

fn dump_types<R: Reader, W: Write>(
    w: &mut W,
    dwarf: &gimli::Dwarf<R>,
    dwo_parent_units: Option<&HashMap<gimli::DwoId, gimli::Unit<R>>>,
    flags: &Flags,
) -> Result<()> {
    writeln!(w, "\n.debug_types")?;

    let mut iter = dwarf.type_units();
    while let Some(header) = iter.next()? {
        dump_unit(w, header, dwarf, dwo_parent_units, flags)?;
    }
    Ok(())
}

fn dump_unit<R: Reader, W: Write>(
    w: &mut W,
    header: UnitHeader<R>,
    dwarf: &gimli::Dwarf<R>,
    dwo_parent_units: Option<&HashMap<gimli::DwoId, gimli::Unit<R>>>,
    flags: &Flags,
) -> Result<()> {
    write!(w, "\nUNIT<")?;
    match header.offset() {
        UnitSectionOffset::DebugInfoOffset(o) => {
            write!(w, ".debug_info+0x{:08x}", o.0)?;
        }
        UnitSectionOffset::DebugTypesOffset(o) => {
            write!(w, ".debug_types+0x{:08x}", o.0)?;
        }
    }
    writeln!(w, ">: length = 0x{:x}, format = {:?}, version = {}, address_size = {}, abbrev_offset = 0x{:x}",
        header.unit_length(),
        header.format(),
        header.version(),
        header.address_size(),
        header.debug_abbrev_offset().0,
    )?;

    match header.type_() {
        UnitType::Compilation | UnitType::Partial => (),
        UnitType::Type {
            type_signature,
            type_offset,
        }
        | UnitType::SplitType {
            type_signature,
            type_offset,
        } => {
            write!(w, "  signature        = ")?;
            dump_type_signature(w, type_signature)?;
            writeln!(w)?;
            writeln!(w, "  type_offset      = 0x{:x}", type_offset.0,)?;
        }
        UnitType::Skeleton(dwo_id) | UnitType::SplitCompilation(dwo_id) => {
            write!(w, "  dwo_id           = ")?;
            writeln!(w, "0x{:016x}", dwo_id.0)?;
        }
    }

    let mut unit = match dwarf.unit(header) {
        Ok(unit) => unit,
        Err(err) => {
            writeln_error(w, dwarf, err.into(), "Failed to parse unit root entry")?;
            return Ok(());
        }
    };

    if let Some(dwo_parent_units) = dwo_parent_units {
        if let Some(dwo_id) = unit.dwo_id {
            if let Some(parent_unit) = dwo_parent_units.get(&dwo_id) {
                unit.copy_relocated_attributes(parent_unit);
            }
        }
    }

    let unit_ref = unit.unit_ref(dwarf);
    let entries_result = dump_entries(w, unit_ref, flags);
    if let Err(err) = entries_result {
        writeln_error(w, dwarf, err, "Failed to dump entries")?;
    }
    Ok(())
}

fn spaces(buf: &mut String, len: usize) -> &str {
    while buf.len() < len {
        buf.push(' ');
    }
    &buf[..len]
}

// " GOFF=0x{:08x}" adds exactly 16 spaces.
const GOFF_SPACES: usize = 16;

fn write_offset<R: Reader, W: Write>(
    w: &mut W,
    unit: &gimli::Unit<R>,
    offset: gimli::UnitOffset<R::Offset>,
    flags: &Flags,
) -> Result<()> {
    write!(w, "<0x{:08x}", offset.0)?;
    if flags.goff {
        let goff = match offset.to_unit_section_offset(unit) {
            UnitSectionOffset::DebugInfoOffset(o) => o.0,
            UnitSectionOffset::DebugTypesOffset(o) => o.0,
        };
        write!(w, " GOFF=0x{:08x}", goff)?;
    }
    write!(w, ">")?;
    Ok(())
}

fn dump_entries<R: Reader, W: Write>(
    w: &mut W,
    unit: gimli::UnitRef<R>,
    flags: &Flags,
) -> Result<()> {
    let mut spaces_buf = String::new();
    let mut deferred_macinfo = Vec::new();
    let mut deferred_macros = Vec::new();

    let mut entries = unit.entries_raw(None)?;
    while !entries.is_empty() {
        let offset = entries.next_offset();
        let depth = entries.next_depth();
        let abbrev = entries.read_abbreviation()?;

        let mut indent = if depth >= 0 {
            depth as usize * 2 + 2
        } else {
            2
        };
        write!(w, "<{}{}>", if depth < 10 { " " } else { "" }, depth)?;
        write_offset(w, &unit, offset, flags)?;
        writeln!(
            w,
            "{}{}",
            spaces(&mut spaces_buf, indent),
            abbrev.map(|x| x.tag()).unwrap_or(gimli::DW_TAG_null)
        )?;

        indent += 18;
        if flags.goff {
            indent += GOFF_SPACES;
        }

        for spec in abbrev.map(|x| x.attributes()).unwrap_or(&[]) {
            let attr = entries.read_attribute(*spec)?;
            w.write_all(spaces(&mut spaces_buf, indent).as_bytes())?;
            if let Some(n) = attr.name().static_string() {
                let right_padding = 27 - cmp::min(27, n.len());
                write!(w, "{}{} ", n, spaces(&mut spaces_buf, right_padding))?;
            } else {
                write!(w, "{:27} ", attr.name())?;
            }
            if flags.raw {
                writeln!(w, "{:?}", attr.raw_value())?;
            } else {
                match dump_attr_value(w, &attr, unit) {
                    Ok(_) => (),
                    Err(err) => {
                        writeln_error(w, unit.dwarf, err, "Failed to dump attribute value")?
                    }
                };
                // dump_attr_value only prints the offset for the macro info attribute.
                // The content is too long to print inline, so store the offset to print later.
                if attr.name() == gimli::DW_AT_macro_info {
                    if let gimli::AttributeValue::DebugMacinfoRef(offset) = attr.value() {
                        deferred_macinfo.push(offset);
                    }
                } else if attr.name() == gimli::DW_AT_macros {
                    if let gimli::AttributeValue::DebugMacroRef(offset) = attr.value() {
                        deferred_macros.push(offset);
                    }
                }
            }
        }
    }

    for offset in deferred_macinfo {
        writeln!(w)?;
        writeln!(w, "Macros <.debug_macinfo+0x{:08x}>", offset.0)?;
        dump_macros(w, unit, unit.macinfo(offset)?, false)?;
    }

    for offset in deferred_macros {
        writeln!(w)?;
        writeln!(w, "Macros <.debug_macro+0x{:08x}>", offset.0)?;
        dump_macros(w, unit, unit.macros(offset)?, true)?;
    }

    Ok(())
}

fn dump_attr_value<R: Reader, W: Write>(
    w: &mut W,
    attr: &gimli::Attribute<R>,
    unit: gimli::UnitRef<R>,
) -> Result<()> {
    let value = attr.value();
    match value {
        gimli::AttributeValue::Addr(address) => {
            writeln!(w, "{:#x}", address)?;
        }
        gimli::AttributeValue::Block(data) => {
            for byte in data.to_slice()?.iter() {
                write!(w, "{:02x}", byte)?;
            }
            writeln!(w)?;
        }
        gimli::AttributeValue::Data1(_)
        | gimli::AttributeValue::Data2(_)
        | gimli::AttributeValue::Data4(_)
        | gimli::AttributeValue::Data8(_) => {
            if let (Some(udata), Some(sdata)) = (attr.udata_value(), attr.sdata_value()) {
                if sdata >= 0 {
                    writeln!(w, "{}", udata)?;
                } else {
                    writeln!(w, "{} ({})", udata, sdata)?;
                }
            } else {
                writeln!(w, "{:?}", value)?;
            }
        }
        gimli::AttributeValue::Sdata(data) => {
            match attr.name() {
                gimli::DW_AT_data_member_location => {
                    writeln!(w, "{}", data)?;
                }
                _ => {
                    if data >= 0 {
                        writeln!(w, "0x{:08x}", data)?;
                    } else {
                        writeln!(w, "0x{:08x} ({})", data, data)?;
                    }
                }
            };
        }
        gimli::AttributeValue::Udata(data) => {
            match attr.name() {
                gimli::DW_AT_high_pc => {
                    writeln!(w, "<offset-from-lowpc>{}", data)?;
                }
                gimli::DW_AT_data_member_location => {
                    if let Some(sdata) = attr.sdata_value() {
                        // This is a DW_FORM_data* value.
                        // libdwarf-dwarfdump displays this as signed too.
                        if sdata >= 0 {
                            writeln!(w, "{}", data)?;
                        } else {
                            writeln!(w, "{} ({})", data, sdata)?;
                        }
                    } else {
                        writeln!(w, "{}", data)?;
                    }
                }
                gimli::DW_AT_lower_bound | gimli::DW_AT_upper_bound => {
                    writeln!(w, "{}", data)?;
                }
                _ => {
                    writeln!(w, "0x{:08x}", data)?;
                }
            };
        }
        gimli::AttributeValue::Exprloc(ref data) => {
            if let gimli::AttributeValue::Exprloc(_) = attr.raw_value() {
                write!(w, "len 0x{:04x}: ", data.0.len())?;
                for byte in data.0.to_slice()?.iter() {
                    write!(w, "{:02x}", byte)?;
                }
                write!(w, ": ")?;
            }
            dump_exprloc(w, unit, data)?;
            writeln!(w)?;
        }
        gimli::AttributeValue::Flag(true) => {
            writeln!(w, "yes")?;
        }
        gimli::AttributeValue::Flag(false) => {
            writeln!(w, "no")?;
        }
        gimli::AttributeValue::SecOffset(offset) => {
            writeln!(w, "0x{:08x}", offset)?;
        }
        gimli::AttributeValue::DebugAddrBase(base) => {
            writeln!(w, "<.debug_addr+0x{:08x}>", base.0)?;
        }
        gimli::AttributeValue::DebugAddrIndex(index) => {
            write!(w, "(index {:#x}): ", index.0)?;
            let address = unit.address(index)?;
            writeln!(w, "{:#x}", address)?;
        }
        gimli::AttributeValue::UnitRef(offset) => {
            write!(w, "0x{:08x}", offset.0)?;
            match offset.to_unit_section_offset(&unit) {
                UnitSectionOffset::DebugInfoOffset(goff) => {
                    write!(w, "<.debug_info+0x{:08x}>", goff.0)?;
                }
                UnitSectionOffset::DebugTypesOffset(goff) => {
                    write!(w, "<.debug_types+0x{:08x}>", goff.0)?;
                }
            }
            writeln!(w)?;
        }
        gimli::AttributeValue::DebugInfoRef(offset) => {
            writeln!(w, "<.debug_info+0x{:08x}>", offset.0)?;
        }
        gimli::AttributeValue::DebugInfoRefSup(offset) => {
            writeln!(w, "<.debug_info(sup)+0x{:08x}>", offset.0)?;
        }
        gimli::AttributeValue::DebugLineRef(offset) => {
            writeln!(w, "<.debug_line+0x{:08x}>", offset.0)?;
        }
        gimli::AttributeValue::LocationListsRef(offset) => {
            dump_loc_list(w, offset, unit)?;
        }
        gimli::AttributeValue::DebugLocListsBase(base) => {
            writeln!(w, "<.debug_loclists+0x{:08x}>", base.0)?;
        }
        gimli::AttributeValue::DebugLocListsIndex(index) => {
            write!(w, "(indirect location list, index {:#x}): ", index.0)?;
            let offset = unit.locations_offset(index)?;
            dump_loc_list(w, offset, unit)?;
        }
        gimli::AttributeValue::DebugMacinfoRef(offset) => {
            writeln!(w, "<.debug_macinfo+0x{:08x}>", offset.0)?;
        }
        gimli::AttributeValue::DebugMacroRef(offset) => {
            writeln!(w, "<.debug_macro+0x{:08x}>", offset.0)?;
        }
        gimli::AttributeValue::RangeListsRef(offset) => {
            let offset = unit.ranges_offset_from_raw(offset);
            dump_range_list(w, offset, unit)?;
        }
        gimli::AttributeValue::DebugRngListsBase(base) => {
            writeln!(w, "<.debug_rnglists+0x{:08x}>", base.0)?;
        }
        gimli::AttributeValue::DebugRngListsIndex(index) => {
            write!(w, "(indirect range list, index {:#x}): ", index.0)?;
            let offset = unit.ranges_offset(index)?;
            dump_range_list(w, offset, unit)?;
        }
        gimli::AttributeValue::DebugTypesRef(signature) => {
            dump_type_signature(w, signature)?;
            writeln!(w, " <type signature>")?;
        }
        gimli::AttributeValue::DebugStrRef(offset) => {
            if let Ok(s) = unit.string(offset) {
                writeln!(w, "{}", s.to_string_lossy()?)?;
            } else {
                writeln!(w, "<.debug_str+0x{:08x}>", offset.0)?;
            }
        }
        gimli::AttributeValue::DebugStrRefSup(offset) => {
            if let Ok(s) = unit.sup_string(offset) {
                writeln!(w, "{}", s.to_string_lossy()?)?;
            } else {
                writeln!(w, "<.debug_str(sup)+0x{:08x}>", offset.0)?;
            }
        }
        gimli::AttributeValue::DebugStrOffsetsBase(base) => {
            writeln!(w, "<.debug_str_offsets+0x{:08x}>", base.0)?;
        }
        gimli::AttributeValue::DebugStrOffsetsIndex(index) => {
            write!(w, "(indirect string, index {:#x}): ", index.0)?;
            let offset = unit.string_offset(index)?;
            if let Ok(s) = unit.string(offset) {
                writeln!(w, "{}", s.to_string_lossy()?)?;
            } else {
                writeln!(w, "<.debug_str+0x{:08x}>", offset.0)?;
            }
        }
        gimli::AttributeValue::DebugLineStrRef(offset) => {
            if let Ok(s) = unit.line_string(offset) {
                writeln!(w, "{}", s.to_string_lossy()?)?;
            } else {
                writeln!(w, "<.debug_line_str=0x{:08x}>", offset.0)?;
            }
        }
        gimli::AttributeValue::String(s) => {
            writeln!(w, "{}", s.to_string_lossy()?)?;
        }
        gimli::AttributeValue::Encoding(value) => {
            writeln!(w, "{}", value)?;
        }
        gimli::AttributeValue::DecimalSign(value) => {
            writeln!(w, "{}", value)?;
        }
        gimli::AttributeValue::Endianity(value) => {
            writeln!(w, "{}", value)?;
        }
        gimli::AttributeValue::Accessibility(value) => {
            writeln!(w, "{}", value)?;
        }
        gimli::AttributeValue::Visibility(value) => {
            writeln!(w, "{}", value)?;
        }
        gimli::AttributeValue::Virtuality(value) => {
            writeln!(w, "{}", value)?;
        }
        gimli::AttributeValue::Language(value) => {
            writeln!(w, "{}", value)?;
        }
        gimli::AttributeValue::AddressClass(value) => {
            writeln!(w, "{}", value)?;
        }
        gimli::AttributeValue::IdentifierCase(value) => {
            writeln!(w, "{}", value)?;
        }
        gimli::AttributeValue::CallingConvention(value) => {
            writeln!(w, "{}", value)?;
        }
        gimli::AttributeValue::Inline(value) => {
            writeln!(w, "{}", value)?;
        }
        gimli::AttributeValue::Ordering(value) => {
            writeln!(w, "{}", value)?;
        }
        gimli::AttributeValue::FileIndex(value) => {
            write!(w, "0x{:08x}", value)?;
            dump_file_index(w, value, unit)?;
            writeln!(w)?;
        }
        gimli::AttributeValue::DwoId(value) => {
            writeln!(w, "0x{:016x}", value.0)?;
        }
    }

    Ok(())
}

fn dump_type_signature<W: Write>(w: &mut W, signature: gimli::DebugTypeSignature) -> Result<()> {
    write!(w, "0x{:016x}", signature.0)?;
    Ok(())
}

fn dump_file_index<R: Reader, W: Write>(
    w: &mut W,
    file_index: u64,
    unit: gimli::UnitRef<R>,
) -> Result<()> {
    if file_index == 0 && unit.header.version() <= 4 {
        return Ok(());
    }
    let header = match unit.line_program {
        Some(ref program) => program.header(),
        None => return Ok(()),
    };
    let file = match header.file(file_index) {
        Some(file) => file,
        None => {
            writeln!(w, "Unable to get header for file {}", file_index)?;
            return Ok(());
        }
    };
    write!(w, " ")?;
    if let Some(directory) = file.directory(header) {
        let directory = unit.attr_string(directory)?;
        let directory = directory.to_string_lossy()?;
        if file.directory_index() != 0 && !directory.starts_with('/') {
            if let Some(ref comp_dir) = unit.comp_dir {
                write!(w, "{}/", comp_dir.to_string_lossy()?,)?;
            }
        }
        write!(w, "{}/", directory)?;
    }
    write!(
        w,
        "{}",
        unit.attr_string(file.path_name())?.to_string_lossy()?
    )?;
    Ok(())
}

fn dump_exprloc<R: Reader, W: Write>(
    w: &mut W,
    unit: gimli::UnitRef<R>,
    data: &gimli::Expression<R>,
) -> Result<()> {
    let mut pc = data.0.clone();
    let mut space = false;
    while pc.len() != 0 {
        let pc_clone = pc.clone();
        match gimli::Operation::parse(&mut pc, unit.encoding()) {
            Ok(op) => {
                if space {
                    write!(w, " ")?;
                } else {
                    space = true;
                }
                dump_op(w, unit, pc_clone, op)?;
            }
            Err(gimli::Error::InvalidExpression(op)) => {
                writeln!(w, "WARNING: unsupported operation 0x{:02x}", op.0)?;
                return Ok(());
            }
            Err(gimli::Error::UnsupportedRegister(register)) => {
                writeln!(w, "WARNING: unsupported register {}", register)?;
                return Ok(());
            }
            Err(gimli::Error::UnexpectedEof(_)) => {
                writeln!(w, "WARNING: truncated or malformed expression")?;
                return Ok(());
            }
            Err(e) => {
                writeln!(w, "WARNING: unexpected operation parse error: {}", e)?;
                return Ok(());
            }
        }
    }
    Ok(())
}

fn dump_op<R: Reader, W: Write>(
    w: &mut W,
    unit: gimli::UnitRef<R>,
    mut pc: R,
    op: gimli::Operation<R>,
) -> Result<()> {
    let dwop = gimli::DwOp(pc.read_u8()?);
    write!(w, "{}", dwop)?;
    match op {
        gimli::Operation::Deref {
            base_type, size, ..
        } => {
            if dwop == gimli::DW_OP_deref_size || dwop == gimli::DW_OP_xderef_size {
                write!(w, " {}", size)?;
            }
            if base_type != UnitOffset(0) {
                write!(w, " type 0x{:08x}", base_type.0)?;
            }
        }
        gimli::Operation::Pick { index } => {
            if dwop == gimli::DW_OP_pick {
                write!(w, " {}", index)?;
            }
        }
        gimli::Operation::PlusConstant { value } => {
            write!(w, " {}", value as i64)?;
        }
        gimli::Operation::Bra { target } => {
            write!(w, " {}", target)?;
        }
        gimli::Operation::Skip { target } => {
            write!(w, " {}", target)?;
        }
        gimli::Operation::SignedConstant { value } => match dwop {
            gimli::DW_OP_const1s
            | gimli::DW_OP_const2s
            | gimli::DW_OP_const4s
            | gimli::DW_OP_const8s
            | gimli::DW_OP_consts => {
                write!(w, " {}", value)?;
            }
            _ => {}
        },
        gimli::Operation::UnsignedConstant { value } => match dwop {
            gimli::DW_OP_const1u
            | gimli::DW_OP_const2u
            | gimli::DW_OP_const4u
            | gimli::DW_OP_const8u
            | gimli::DW_OP_constu => {
                write!(w, " {}", value)?;
            }
            _ => {
                // These have the value encoded in the operation, eg DW_OP_lit0.
            }
        },
        gimli::Operation::Register { register } => {
            if dwop == gimli::DW_OP_regx {
                write!(w, " {}", register.0)?;
            }
        }
        gimli::Operation::RegisterOffset {
            register,
            offset,
            base_type,
        } => {
            if dwop >= gimli::DW_OP_breg0 && dwop <= gimli::DW_OP_breg31 {
                write!(w, "{:+}", offset)?;
            } else {
                write!(w, " {}", register.0)?;
                if offset != 0 {
                    write!(w, "{:+}", offset)?;
                }
                if base_type != UnitOffset(0) {
                    write!(w, " type 0x{:08x}", base_type.0)?;
                }
            }
        }
        gimli::Operation::FrameOffset { offset } => {
            write!(w, " {}", offset)?;
        }
        gimli::Operation::Call { offset } => match offset {
            gimli::DieReference::UnitRef(gimli::UnitOffset(offset)) => {
                write!(w, " 0x{:08x}", offset)?;
            }
            gimli::DieReference::DebugInfoRef(gimli::DebugInfoOffset(offset)) => {
                write!(w, " 0x{:08x}", offset)?;
            }
        },
        gimli::Operation::Piece {
            size_in_bits,
            bit_offset: None,
        } => {
            write!(w, " {}", size_in_bits / 8)?;
        }
        gimli::Operation::Piece {
            size_in_bits,
            bit_offset: Some(bit_offset),
        } => {
            write!(w, " 0x{:08x} offset 0x{:08x}", size_in_bits, bit_offset)?;
        }
        gimli::Operation::ImplicitValue { data } => {
            let data = data.to_slice()?;
            write!(w, " len {:#x} contents 0x", data.len())?;
            for byte in data.iter() {
                write!(w, "{:02x}", byte)?;
            }
        }
        gimli::Operation::ImplicitPointer { value, byte_offset } => {
            write!(w, " 0x{:08x} {}", value.0, byte_offset)?;
        }
        gimli::Operation::EntryValue { expression } => {
            write!(w, "(")?;
            dump_exprloc(w, unit, &gimli::Expression(expression))?;
            write!(w, ")")?;
        }
        gimli::Operation::ParameterRef { offset } => {
            write!(w, " 0x{:08x}", offset.0)?;
        }
        gimli::Operation::Address { address } => {
            write!(w, " {:#x}", address)?;
        }
        gimli::Operation::AddressIndex { index } => {
            write!(w, " {:#x}", index.0)?;
            let address = unit.address(index)?;
            write!(w, " ({:#x})", address)?;
        }
        gimli::Operation::ConstantIndex { index } => {
            write!(w, " {:#x}", index.0)?;
            let address = unit.address(index)?;
            write!(w, " ({:#x})", address)?;
        }
        gimli::Operation::TypedLiteral { base_type, value } => {
            write!(w, " type 0x{:08x} contents 0x", base_type.0)?;
            for byte in value.to_slice()?.iter() {
                write!(w, "{:02x}", byte)?;
            }
        }
        gimli::Operation::Convert { base_type } => {
            write!(w, " type 0x{:08x}", base_type.0)?;
        }
        gimli::Operation::Reinterpret { base_type } => {
            write!(w, " type 0x{:08x}", base_type.0)?;
        }
        gimli::Operation::WasmLocal { index }
        | gimli::Operation::WasmGlobal { index }
        | gimli::Operation::WasmStack { index } => {
            let wasmop = pc.read_u8()?;
            write!(w, " 0x{:x} 0x{:x}", wasmop, index)?;
        }
        gimli::Operation::Drop
        | gimli::Operation::Swap
        | gimli::Operation::Rot
        | gimli::Operation::Abs
        | gimli::Operation::And
        | gimli::Operation::Div
        | gimli::Operation::Minus
        | gimli::Operation::Mod
        | gimli::Operation::Mul
        | gimli::Operation::Neg
        | gimli::Operation::Not
        | gimli::Operation::Or
        | gimli::Operation::Plus
        | gimli::Operation::Shl
        | gimli::Operation::Shr
        | gimli::Operation::Shra
        | gimli::Operation::Xor
        | gimli::Operation::Eq
        | gimli::Operation::Ge
        | gimli::Operation::Gt
        | gimli::Operation::Le
        | gimli::Operation::Lt
        | gimli::Operation::Ne
        | gimli::Operation::Nop
        | gimli::Operation::PushObjectAddress
        | gimli::Operation::TLS
        | gimli::Operation::CallFrameCFA
        | gimli::Operation::StackValue => {}
    };
    Ok(())
}

fn dump_range<W: Write>(w: &mut W, range: Option<gimli::Range>) -> Result<()> {
    if let Some(range) = range {
        write!(w, " [{:#x}, {:#x}]", range.begin, range.end)?;
    } else {
        write!(w, " [ignored]")?;
    }
    Ok(())
}

fn dump_loc_list<R: Reader, W: Write>(
    w: &mut W,
    offset: gimli::LocationListsOffset<R::Offset>,
    unit: gimli::UnitRef<R>,
) -> Result<()> {
    let mut locations = unit.locations(offset)?;
    writeln!(
        w,
        "<loclist at {}+0x{:08x}>",
        if unit.encoding().version < 5 {
            ".debug_loc"
        } else {
            ".debug_loclists"
        },
        offset.0,
    )?;
    let mut i = 0;
    while let Some(raw) = locations.next_raw()? {
        write!(w, "\t\t\t[{:2}]", i)?;
        i += 1;
        let range = locations
            .convert_raw(raw.clone())?
            .map(|location| location.range);
        match raw {
            gimli::RawLocListEntry::BaseAddress { addr } => {
                writeln!(w, "<base-address {:#x}>", addr)?;
            }
            gimli::RawLocListEntry::BaseAddressx { addr } => {
                let addr_val = unit.address(addr)?;
                writeln!(w, "<base-addressx [{}]{:#x}>", addr.0, addr_val)?;
            }
            gimli::RawLocListEntry::StartxEndx {
                begin,
                end,
                ref data,
            } => {
                let begin_val = unit.address(begin)?;
                let end_val = unit.address(end)?;
                write!(
                    w,
                    "<startx-endx [{}]{:#x}, [{}]{:#x}>",
                    begin.0, begin_val, end.0, end_val,
                )?;
                dump_range(w, range)?;
                dump_exprloc(w, unit, data)?;
                writeln!(w)?;
            }
            gimli::RawLocListEntry::StartxLength {
                begin,
                length,
                ref data,
            } => {
                let begin_val = unit.address(begin)?;
                write!(
                    w,
                    "<startx-length [{}]{:#x}, {:#x}>",
                    begin.0, begin_val, length,
                )?;
                dump_range(w, range)?;
                dump_exprloc(w, unit, data)?;
                writeln!(w)?;
            }
            gimli::RawLocListEntry::AddressOrOffsetPair {
                begin,
                end,
                ref data,
            }
            | gimli::RawLocListEntry::OffsetPair {
                begin,
                end,
                ref data,
            } => {
                write!(w, "<offset-pair {:#x}, {:#x}>", begin, end)?;
                dump_range(w, range)?;
                dump_exprloc(w, unit, data)?;
                writeln!(w)?;
            }
            gimli::RawLocListEntry::DefaultLocation { ref data } => {
                write!(w, "<default location>")?;
                dump_exprloc(w, unit, data)?;
                writeln!(w)?;
            }
            gimli::RawLocListEntry::StartEnd {
                begin,
                end,
                ref data,
            } => {
                write!(w, "<start-end {:#x}, {:#x}>", begin, end)?;
                dump_range(w, range)?;
                dump_exprloc(w, unit, data)?;
                writeln!(w)?;
            }
            gimli::RawLocListEntry::StartLength {
                begin,
                length,
                ref data,
            } => {
                write!(w, "<start-length {:#x}, {:#x}>", begin, length)?;
                dump_range(w, range)?;
                dump_exprloc(w, unit, data)?;
                writeln!(w)?;
            }
        };
    }
    Ok(())
}

fn dump_range_list<R: Reader, W: Write>(
    w: &mut W,
    offset: gimli::RangeListsOffset<R::Offset>,
    unit: gimli::UnitRef<R>,
) -> Result<()> {
    let mut ranges = unit.ranges(offset)?;
    writeln!(
        w,
        "<rnglist at {}+0x{:08x}>",
        if unit.encoding().version < 5 {
            ".debug_ranges"
        } else {
            ".debug_rnglists"
        },
        offset.0,
    )?;
    let mut i = 0;
    while let Some(raw) = ranges.next_raw()? {
        write!(w, "\t\t\t[{:2}] ", i)?;
        i += 1;
        let range = ranges.convert_raw(raw.clone())?;
        match raw {
            gimli::RawRngListEntry::BaseAddress { addr } => {
                writeln!(w, "<new base address {:#x}>", addr)?;
            }
            gimli::RawRngListEntry::BaseAddressx { addr } => {
                let addr_val = unit.address(addr)?;
                writeln!(w, "<new base addressx [{}]{:#x}>", addr.0, addr_val)?;
            }
            gimli::RawRngListEntry::StartxEndx { begin, end } => {
                let begin_val = unit.address(begin)?;
                let end_val = unit.address(end)?;
                write!(
                    w,
                    "<startx-endx [{}]{:#x}, [{}]{:#x}>",
                    begin.0, begin_val, end.0, end_val,
                )?;
                dump_range(w, range)?;
                writeln!(w)?;
            }
            gimli::RawRngListEntry::StartxLength { begin, length } => {
                let begin_val = unit.address(begin)?;
                write!(
                    w,
                    "<startx-length [{}]{:#x}, {:#x}>",
                    begin.0, begin_val, length,
                )?;
                dump_range(w, range)?;
                writeln!(w)?;
            }
            gimli::RawRngListEntry::AddressOrOffsetPair { begin, end }
            | gimli::RawRngListEntry::OffsetPair { begin, end } => {
                write!(w, "<offset-pair {:#x}, {:#x}>", begin, end)?;
                dump_range(w, range)?;
                writeln!(w)?;
            }
            gimli::RawRngListEntry::StartEnd { begin, end } => {
                write!(w, "<start-end {:#x}, {:#x}>", begin, end)?;
                dump_range(w, range)?;
                writeln!(w)?;
            }
            gimli::RawRngListEntry::StartLength { begin, length } => {
                write!(w, "<start-length {:#x}, {:#x}>", begin, length)?;
                dump_range(w, range)?;
                writeln!(w)?;
            }
        };
    }
    Ok(())
}

fn dump_line<R: Reader, W: Write>(w: &mut W, dwarf: &gimli::Dwarf<R>) -> Result<()> {
    let mut iter = dwarf.units();
    while let Some(header) = iter.next()? {
        writeln!(
            w,
            "\n.debug_line: line number info for unit at .debug_info offset 0x{:08x}",
            header.offset().as_debug_info_offset().unwrap().0
        )?;
        let unit = match dwarf.unit(header) {
            Ok(unit) => unit,
            Err(err) => {
                writeln_error(
                    w,
                    dwarf,
                    err.into(),
                    "Failed to parse unit root entry for dump_line",
                )?;
                continue;
            }
        };
        let unit_ref = unit.unit_ref(dwarf);
        match dump_line_program(w, unit_ref) {
            Ok(_) => (),
            Err(Error::Io) => return Err(Error::Io),
            Err(err) => writeln_error(w, dwarf, err, "Failed to dump line program")?,
        }
    }
    Ok(())
}

fn dump_line_program<R: Reader, W: Write>(w: &mut W, unit: gimli::UnitRef<R>) -> Result<()> {
    if let Some(program) = unit.line_program.clone() {
        {
            let header = program.header();
            writeln!(w)?;
            writeln!(
                w,
                "Offset:                             0x{:x}",
                header.offset().0
            )?;
            writeln!(
                w,
                "Length:                             {}",
                header.unit_length()
            )?;
            writeln!(
                w,
                "DWARF version:                      {}",
                header.version()
            )?;
            writeln!(
                w,
                "Address size:                       {}",
                header.address_size()
            )?;
            writeln!(
                w,
                "Prologue length:                    {}",
                header.header_length()
            )?;
            writeln!(
                w,
                "Minimum instruction length:         {}",
                header.minimum_instruction_length()
            )?;
            writeln!(
                w,
                "Maximum operations per instruction: {}",
                header.maximum_operations_per_instruction()
            )?;
            writeln!(
                w,
                "Default is_stmt:                    {}",
                header.default_is_stmt()
            )?;
            writeln!(
                w,
                "Line base:                          {}",
                header.line_base()
            )?;
            writeln!(
                w,
                "Line range:                         {}",
                header.line_range()
            )?;
            writeln!(
                w,
                "Opcode base:                        {}",
                header.opcode_base()
            )?;

            writeln!(w)?;
            writeln!(w, "Opcodes:")?;
            for (i, length) in header
                .standard_opcode_lengths()
                .to_slice()?
                .iter()
                .enumerate()
            {
                writeln!(w, "  Opcode {} has {} args", i + 1, length)?;
            }

            let base = if header.version() >= 5 { 0 } else { 1 };
            writeln!(w)?;
            writeln!(w, "The Directory Table:")?;
            for (i, dir) in header.include_directories().iter().enumerate() {
                writeln!(
                    w,
                    "  {} {}",
                    base + i,
                    unit.attr_string(dir.clone())?.to_string_lossy()?
                )?;
            }

            writeln!(w)?;
            writeln!(w, "The File Name Table")?;
            write!(w, "  Entry\tDir\tTime\tSize")?;
            if header.file_has_md5() {
                write!(w, "\tMD5\t\t\t\t")?;
            }
            writeln!(w, "\tName")?;
            for (i, file) in header.file_names().iter().enumerate() {
                write!(
                    w,
                    "  {}\t{}\t{}\t{}",
                    base + i,
                    file.directory_index(),
                    file.timestamp(),
                    file.size(),
                )?;
                if header.file_has_md5() {
                    let md5 = file.md5();
                    write!(w, "\t")?;
                    for byte in md5 {
                        write!(w, "{:02X}", byte)?;
                    }
                }
                writeln!(
                    w,
                    "\t{}",
                    unit.attr_string(file.path_name())?.to_string_lossy()?
                )?;
            }

            writeln!(w)?;
            writeln!(w, "Line Number Instructions:")?;
            let mut instructions = header.instructions();
            while let Some(instruction) = instructions.next_instruction(header)? {
                use gimli::{constants, LineInstruction};
                write!(w, "  ")?;
                match instruction {
                    LineInstruction::Special(opcode) => write!(w, "Special opcode {}", opcode),
                    LineInstruction::Copy => write!(w, "{}", constants::DW_LNS_copy),
                    LineInstruction::AdvancePc(advance) => {
                        write!(w, "{} by {}", constants::DW_LNS_advance_pc, advance)
                    }
                    LineInstruction::AdvanceLine(increment) => {
                        write!(w, "{} by {}", constants::DW_LNS_advance_line, increment)
                    }
                    LineInstruction::SetFile(file) => {
                        write!(w, "{} to {}", constants::DW_LNS_set_file, file)
                    }
                    LineInstruction::SetColumn(column) => {
                        write!(w, "{} to {}", constants::DW_LNS_set_column, column)
                    }
                    LineInstruction::NegateStatement => {
                        write!(w, "{}", constants::DW_LNS_negate_stmt)
                    }
                    LineInstruction::SetBasicBlock => {
                        write!(w, "{}", constants::DW_LNS_set_basic_block)
                    }
                    LineInstruction::ConstAddPc => write!(w, "{}", constants::DW_LNS_const_add_pc),
                    LineInstruction::FixedAddPc(advance) => {
                        write!(w, "{} by {}", constants::DW_LNS_fixed_advance_pc, advance)
                    }
                    LineInstruction::SetPrologueEnd => {
                        write!(w, "{}", constants::DW_LNS_set_prologue_end)
                    }
                    LineInstruction::SetEpilogueBegin => {
                        write!(w, "{}", constants::DW_LNS_set_epilogue_begin)
                    }
                    LineInstruction::SetIsa(isa) => {
                        write!(w, "{} to {}", constants::DW_LNS_set_isa, isa)
                    }
                    LineInstruction::UnknownStandard0(opcode) => write!(w, "Unknown {}", opcode),
                    LineInstruction::UnknownStandard1(opcode, arg) => {
                        write!(w, "Unknown {} with operand {}", opcode, arg)
                    }
                    LineInstruction::UnknownStandardN(opcode, ref args) => {
                        write!(w, "Unknown {} with operands {:?}", opcode, args)
                    }
                    LineInstruction::EndSequence => write!(w, "{}", constants::DW_LNE_end_sequence),
                    LineInstruction::SetAddress(address) => {
                        write!(w, "{} to {:#x}", constants::DW_LNE_set_address, address)
                    }
                    LineInstruction::DefineFile(_) => {
                        write!(w, "{}", constants::DW_LNE_define_file)
                    }
                    LineInstruction::SetDiscriminator(discr) => {
                        write!(w, "{} to {}", constants::DW_LNE_set_discriminator, discr)
                    }
                    LineInstruction::UnknownExtended(opcode, _) => write!(w, "Unknown {}", opcode),
                }?;
                writeln!(w)?;
            }

            writeln!(w)?;
            writeln!(w, "Line Number Rows:")?;
            writeln!(w, "<pc>        [lno,col]")?;
        }
        let mut rows = program.rows();
        let mut file_index = u64::MAX;
        while let Some((header, row)) = rows.next_row()? {
            let line = match row.line() {
                Some(line) => line.get(),
                None => 0,
            };
            let column = match row.column() {
                gimli::ColumnType::Column(column) => column.get(),
                gimli::ColumnType::LeftEdge => 0,
            };
            write!(w, "{:#x}  [{:4},{:2}]", row.address(), line, column)?;
            if row.is_stmt() {
                write!(w, " NS")?;
            }
            if row.basic_block() {
                write!(w, " BB")?;
            }
            if row.end_sequence() {
                write!(w, " ET")?;
            }
            if row.prologue_end() {
                write!(w, " PE")?;
            }
            if row.epilogue_begin() {
                write!(w, " EB")?;
            }
            if row.isa() != 0 {
                write!(w, " IS={}", row.isa())?;
            }
            if row.discriminator() != 0 {
                write!(w, " DI={}", row.discriminator())?;
            }
            if file_index != row.file_index() {
                file_index = row.file_index();
                if let Some(file) = row.file(header) {
                    if let Some(directory) = file.directory(header) {
                        write!(
                            w,
                            " uri: \"{}/{}\"",
                            unit.attr_string(directory)?.to_string_lossy()?,
                            unit.attr_string(file.path_name())?.to_string_lossy()?
                        )?;
                    } else {
                        write!(
                            w,
                            " uri: \"{}\"",
                            unit.attr_string(file.path_name())?.to_string_lossy()?
                        )?;
                    }
                }
            }
            writeln!(w)?;
        }
    }
    Ok(())
}

fn dump_pubnames<R: Reader, W: Write>(
    w: &mut W,
    debug_pubnames: &gimli::DebugPubNames<R>,
    debug_info: &gimli::DebugInfo<R>,
) -> Result<()> {
    writeln!(w, "\n.debug_pubnames")?;

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
        writeln!(w,
            "global die-in-sect 0x{:08x}, cu-in-sect 0x{:08x}, die-in-cu 0x{:08x}, cu-header-in-sect 0x{:08x} '{}'",
            die_in_sect,
            cu_die_offset.0,
            die_in_cu.0,
            cu_offset.0,
            pubname.name().to_string_lossy()?
        )?;
    }
    Ok(())
}

fn dump_pubtypes<R: Reader, W: Write>(
    w: &mut W,
    debug_pubtypes: &gimli::DebugPubTypes<R>,
    debug_info: &gimli::DebugInfo<R>,
) -> Result<()> {
    writeln!(w, "\n.debug_pubtypes")?;

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
        writeln!(w,
            "pubtype die-in-sect 0x{:08x}, cu-in-sect 0x{:08x}, die-in-cu 0x{:08x}, cu-header-in-sect 0x{:08x} '{}'",
            die_in_sect,
            cu_die_offset.0,
            die_in_cu.0,
            cu_offset.0,
            pubtype.name().to_string_lossy()?
        )?;
    }
    Ok(())
}

fn dump_aranges<R: Reader, W: Write>(
    w: &mut W,
    debug_aranges: &gimli::DebugAranges<R>,
) -> Result<()> {
    writeln!(w, "\n.debug_aranges")?;

    let mut headers = debug_aranges.headers();
    while let Some(header) = headers.next()? {
        writeln!(
            w,
            "Address Range Header: length = 0x{:08x}, version = 0x{:04x}, cu_offset = 0x{:08x}, addr_size = 0x{:02x}",
            header.length(),
            header.encoding().version,
            header.debug_info_offset().0,
            header.encoding().address_size,
        )?;
        let mut aranges = header.entries();
        while let Some(raw) = aranges.next_raw()? {
            if let Some(arange) = aranges.convert_raw(raw.clone())? {
                let range = arange.range();
                writeln!(w, "[{:#x}, {:#x})", range.begin, range.end)?;
            } else {
                writeln!(w, "[{:#x}, {:#x}) (ignored)", raw.address(), raw.length())?;
            }
        }
    }
    Ok(())
}

fn dump_addr<R: Reader, W: Write>(w: &mut W, debug_addr: &gimli::DebugAddr<R>) -> Result<()> {
    writeln!(w, "\n.debug_addr")?;

    let mut headers = debug_addr.headers();
    while let Some(header) = headers.next()? {
        writeln!(
            w,
            "Address Table Header: length = 0x{:08x}, version = 0x{:04x}, addr_size = 0x{:02x}",
            header.length(),
            header.encoding().version,
            header.encoding().address_size,
        )?;
        writeln!(w, "Addrs: [",)?;
        let mut addrs = header.entries();
        while let Some(addr) = addrs.next()? {
            writeln!(
                w,
                "0x{:01$x}",
                addr,
                (header.encoding().address_size * 2) as usize,
            )?
        }
        writeln!(w, "]",)?;
    }
    Ok(())
}

fn dump_macros<R: Reader, W: Write>(
    w: &mut W,
    unit: gimli::UnitRef<'_, R>,
    mut macros: gimli::MacroIter<R>,
    is_macro: bool,
) -> Result<()> {
    let mut indent = 2; // base indent is 2 spaces
    let prefix = if is_macro { "DW_MACRO_" } else { "DW_MACINFO_" };
    while let Some(entry) = macros.next()? {
        match entry {
            gimli::MacroEntry::StartFile { .. } => {
                // print the item first, then indent
                write!(w, "{:indent$}{prefix}", "", indent = indent)?;
                dump_macro(w, unit, entry)?;
                indent += 2;
            }
            gimli::MacroEntry::EndFile => {
                // unindent first, then print the item
                indent -= 2;
                write!(w, "{:indent$}{prefix}", "", indent = indent)?;
                dump_macro(w, unit, entry)?;
            }
            _ => {
                // no indentation change
                write!(w, "{:indent$}{prefix}", "", indent = indent)?;
                dump_macro(w, unit, entry)?;
            }
        }
    }
    Ok(())
}

fn dump_macro<R: Reader, W: Write>(
    w: &mut W,
    unit: gimli::UnitRef<'_, R>,
    entry: gimli::MacroEntry<R>,
) -> Result<()> {
    match entry {
        gimli::MacroEntry::Define { line, text } => {
            match text {
                gimli::MacroString::Direct(text) => writeln!(
                    w,
                    "define - lineno: {line}, macro: {}",
                    text.to_string_lossy()?
                )?,
                gimli::MacroString::StringPointer(_) => writeln!(
                    w,
                    "define_strp - lineno: {line}, macro: {}",
                    text.string(unit)?.to_string_lossy()?
                )?,
                gimli::MacroString::IndirectStringPointer(_) => writeln!(
                    w,
                    "define_strx - lineno: {line}, macro: {}",
                    text.string(unit)?.to_string_lossy()?
                )?,
                gimli::MacroString::Supplementary(_) => writeln!(
                    w,
                    "define_sup - lineno: {line}, macro: {}",
                    text.string(unit)?.to_string_lossy()?
                )?,
            };
        }
        gimli::MacroEntry::Undef { line, name } => {
            match name {
                gimli::MacroString::Direct(name) => writeln!(
                    w,
                    "undef - lineno: {line}, macro: {}",
                    name.to_string_lossy()?
                )?,
                gimli::MacroString::StringPointer(_) => writeln!(
                    w,
                    "undef_strp - lineno: {line}, macro: {}",
                    name.string(unit)?.to_string_lossy()?
                )?,
                gimli::MacroString::IndirectStringPointer(_) => writeln!(
                    w,
                    "undef_strx - lineno: {line}, macro: {}",
                    name.string(unit)?.to_string_lossy()?
                )?,
                gimli::MacroString::Supplementary(_) => writeln!(
                    w,
                    "undef_sup - lineno: {line}, macro: {}",
                    name.string(unit)?.to_string_lossy()?
                )?,
            };
        }
        gimli::MacroEntry::StartFile { line, file } => {
            write!(w, "start_file - lineno: {line}, file: ")?;
            dump_file_index(w, file, unit)?;
            writeln!(w)?;
        }
        gimli::MacroEntry::EndFile => {
            writeln!(w, "end_file")?;
        }
        gimli::MacroEntry::Import { offset } => {
            writeln!(w, "import <.debug_macro+0x{:08x}>", offset.0)?;
        }
        gimli::MacroEntry::ImportSup { offset } => {
            writeln!(w, "import_sup <.debug_macro(sup)+0x{:08x}>", offset.0)?;
        }
        gimli::MacroEntry::VendorExt { numeric, string } => {
            writeln!(
                w,
                "vendor_ext - number: {numeric}, string: {}",
                string.to_string_lossy()?
            )?;
        }
    }
    Ok(())
}
