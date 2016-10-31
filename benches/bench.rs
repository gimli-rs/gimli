#![feature(test)]

extern crate gimli;
extern crate test;

use gimli::{DebugAbbrev, DebugAranges, DebugInfo, DebugLine, DebugLineOffset, DebugPubNames,
            DebugPubTypes, LittleEndian, EntriesTreeIter};
use std::env;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

pub fn read_section(section: &str) -> Vec<u8> {
    let mut path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap_or(".".into()));
    path.push("./fixtures/self/");
    path.push(section);

    assert!(path.is_file());
    let mut file = File::open(path).unwrap();

    let mut buf = Vec::new();
    file.read_to_end(&mut buf).unwrap();
    buf
}

#[bench]
fn bench_parsing_debug_abbrev(b: &mut test::Bencher) {
    let debug_info = read_section("debug_info");
    let debug_info = DebugInfo::<LittleEndian>::new(&debug_info);
    let unit = debug_info.units()
        .next()
        .expect("Should have at least one compilation unit")
        .expect("And it should parse OK");

    let debug_abbrev = read_section("debug_abbrev");

    b.iter(|| {
        let debug_abbrev = DebugAbbrev::<LittleEndian>::new(&debug_abbrev);
        test::black_box(unit.abbreviations(debug_abbrev)
            .expect("Should parse abbreviations"));
    });
}

#[bench]
fn bench_parsing_debug_info(b: &mut test::Bencher) {
    let debug_abbrev = read_section("debug_abbrev");
    let debug_abbrev = DebugAbbrev::<LittleEndian>::new(&debug_abbrev);

    let debug_info = read_section("debug_info");

    b.iter(|| {
        let debug_info = DebugInfo::<LittleEndian>::new(&debug_info);

        let mut iter = debug_info.units();
        while let Some(unit) = iter.next().expect("Should parse compilation unit") {
            let abbrevs = unit.abbreviations(debug_abbrev)
                .expect("Should parse abbreviations");

            let mut cursor = unit.entries(&abbrevs).expect("Should parse root entry");
            while let Some((_, entry)) = cursor.next_dfs().expect("Should parse next dfs") {
                let mut attrs = entry.attrs();
                while let Some(attr) = attrs.next().expect("Should parse entry's attribute") {
                    test::black_box(&attr);
                }
            }
        }
    });
}

#[bench]
fn bench_parsing_debug_info_tree(b: &mut test::Bencher) {
    let debug_abbrev = read_section("debug_abbrev");
    let debug_abbrev = DebugAbbrev::<LittleEndian>::new(&debug_abbrev);

    let debug_info = read_section("debug_info");

    b.iter(|| {
        let debug_info = DebugInfo::<LittleEndian>::new(&debug_info);

        let mut iter = debug_info.units();
        while let Some(unit) = iter.next().expect("Should parse compilation unit") {
            let abbrevs = unit.abbreviations(debug_abbrev)
                .expect("Should parse abbreviations");

            let mut tree = unit.entries_tree(&abbrevs).expect("Should have entries tree");
            parse_debug_info_tree(tree.iter());
        }
    });
}

fn parse_debug_info_tree(mut iter: EntriesTreeIter<LittleEndian>) {
    {
        let mut attrs = iter.entry().attrs();
        while let Some(attr) = attrs.next().expect("Should parse entry's attribute") {
            test::black_box(&attr);
        }
    }
    while let Some(child) = iter.next().expect("Should parse child entry") {
        parse_debug_info_tree(child);
    }
}

#[bench]
fn bench_parsing_debug_aranges(b: &mut test::Bencher) {
    let debug_aranges = read_section("debug_aranges");
    let debug_aranges = DebugAranges::<LittleEndian>::new(&debug_aranges);

    b.iter(|| {
        let mut aranges = debug_aranges.items();
        while let Some(arange) = aranges.next().expect("Should parse arange OK") {
            test::black_box(arange);
        }
    });
}

#[bench]
fn bench_parsing_debug_pubnames(b: &mut test::Bencher) {
    let debug_pubnames = read_section("debug_pubnames");
    let debug_pubnames = DebugPubNames::<LittleEndian>::new(&debug_pubnames);

    b.iter(|| {
        let mut pubnames = debug_pubnames.items();
        while let Some(pubname) = pubnames.next().expect("Should parse pubname OK") {
            test::black_box(pubname);
        }
    });
}

#[bench]
fn bench_parsing_debug_types(b: &mut test::Bencher) {
    let debug_pubtypes = read_section("debug_pubtypes");
    let debug_pubtypes = DebugPubTypes::<LittleEndian>::new(&debug_pubtypes);

    b.iter(|| {
        let mut pubtypes = debug_pubtypes.items();
        while let Some(pubtype) = pubtypes.next().expect("Should parse pubtype OK") {
            test::black_box(pubtype);
        }
    });
}

// We happen to know that there is a line number program and header at
// offset 0 and that address size is 8 bytes. No need to parse DIEs to grab
// this info off of the compilation units.
const OFFSET: DebugLineOffset = DebugLineOffset(0);
const ADDRESS_SIZE: u8 = 8;

#[bench]
fn bench_parsing_line_number_program_opcodes(b: &mut test::Bencher) {
    let debug_line = read_section("debug_line");
    let debug_line = DebugLine::<LittleEndian>::new(&debug_line);

    b.iter(|| {
        let header = debug_line.header(OFFSET, ADDRESS_SIZE, None, None)
            .expect("Should parse line number program header");

        let mut opcodes = header.opcodes();
        while let Some(opcode) = opcodes.next_opcode(&header).expect("Should parse opcode") {
            test::black_box(opcode);
        }
    });
}

#[bench]
fn bench_executing_line_number_programs(b: &mut test::Bencher) {
    let debug_line = read_section("debug_line");
    let debug_line = DebugLine::<LittleEndian>::new(&debug_line);

    b.iter(|| {
        let header = debug_line.header(OFFSET, ADDRESS_SIZE, None, None)
            .expect("Should parse line number program header");

        let mut rows = header.rows();
        while let Some(row) = rows.next_row()
            .expect("Should parse and execute all rows in the line number program") {
            test::black_box(row);
        }
    });
}

// See comment above `test_parse_self_eh_frame`.
#[cfg(target_pointer_width="64")]
mod cfi {
    extern crate fallible_iterator;
    extern crate gimli;
    extern crate test;

    use super::*;
    use self::fallible_iterator::FallibleIterator;

    use gimli::{BaseAddresses, CieOrFde, EhFrame, FrameDescriptionEntry, LittleEndian,
                UninitializedUnwindContext, UnwindSection, UnwindTable};

    #[bench]
    fn iterate_entries_and_do_not_parse_any_fde(b: &mut test::Bencher) {
        let eh_frame = read_section("eh_frame");
        let eh_frame = EhFrame::<LittleEndian>::new(&eh_frame);

        let bases = BaseAddresses::default()
            .set_cfi(0)
            .set_data(0)
            .set_text(0);

        b.iter(|| {
            let mut entries = eh_frame.entries(&bases);
            while let Some(entry) = entries.next().expect("Should parse CFI entry OK") {
                test::black_box(entry);
            }
        });
    }

    #[bench]
    fn iterate_entries_and_parse_every_fde(b: &mut test::Bencher) {
        let eh_frame = read_section("eh_frame");
        let eh_frame = EhFrame::<LittleEndian>::new(&eh_frame);

        let bases = BaseAddresses::default()
            .set_cfi(0)
            .set_data(0)
            .set_text(0);

        b.iter(|| {
            let mut entries = eh_frame.entries(&bases);
            while let Some(entry) = entries.next().expect("Should parse CFI entry OK") {
                match entry {
                    CieOrFde::Cie(cie) => {
                        test::black_box(cie);
                    }
                    CieOrFde::Fde(partial) => {
                        let fde = partial.parse(|offset| eh_frame.cie_from_offset(&bases, offset))
                            .expect("Should be able to get CIE for FED");
                        test::black_box(fde);
                    }
                };
            }
        });
    }

    #[bench]
    fn iterate_entries_and_parse_every_fde_and_instructions(b: &mut test::Bencher) {
        let eh_frame = read_section("eh_frame");
        let eh_frame = EhFrame::<LittleEndian>::new(&eh_frame);

        let bases = BaseAddresses::default()
            .set_cfi(0)
            .set_data(0)
            .set_text(0);

        b.iter(|| {
            let mut entries = eh_frame.entries(&bases);
            while let Some(entry) = entries.next().expect("Should parse CFI entry OK") {
                match entry {
                    CieOrFde::Cie(cie) => {
                        let mut instrs = cie.instructions();
                        while let Some(i) = instrs.next()
                            .expect("Can parse next CFI instruction OK") {
                            test::black_box(i);
                        }
                    }
                    CieOrFde::Fde(partial) => {
                        let fde = partial.parse(|offset| eh_frame.cie_from_offset(&bases, offset))
                            .expect("Should be able to get CIE for FED");
                        let mut instrs = fde.instructions();
                        while let Some(i) = instrs.next()
                            .expect("Can parse next CFI instruction OK") {
                            test::black_box(i);
                        }
                    }
                };
            }
        });
    }

    #[bench]
    fn iterate_entries_evaluate_every_fde(b: &mut test::Bencher) {
        let eh_frame = read_section("eh_frame");
        let eh_frame = EhFrame::<LittleEndian>::new(&eh_frame);

        let bases = BaseAddresses::default()
            .set_cfi(0)
            .set_data(0)
            .set_text(0);

        let mut ctx = Some(UninitializedUnwindContext::new());

        b.iter(|| {
            let mut entries = eh_frame.entries(&bases);
            while let Some(entry) = entries.next().expect("Should parse CFI entry OK") {
                match entry {
                    CieOrFde::Cie(_) => {}
                    CieOrFde::Fde(partial) => {
                        let fde = partial.parse(|offset| eh_frame.cie_from_offset(&bases, offset))
                            .expect("Should be able to get CIE for FED");

                        let mut context = ctx.take()
                            .unwrap()
                            .initialize(fde.cie())
                            .expect("Should be able to initialize ctx");

                        {
                            let mut table = UnwindTable::new(&mut context, &fde);
                            while let Some(row) = table.next_row()
                                .expect("Should get next unwind table row") {
                                test::black_box(row);
                            }
                        }

                        ctx = Some(context.reset());
                    }
                };
            }
        });
    }

    fn instrs_len<'input>(fde: &FrameDescriptionEntry<'input,
                                                      LittleEndian,
                                                      EhFrame<'input, LittleEndian>>)
                          -> usize {
        fde.instructions().fold(0, |count, _| count + 1).expect("fold over instructions OK")
    }

    fn get_fde_with_longest_cfi_instructions<'input>
        (eh_frame: EhFrame<'input, LittleEndian>)
         -> FrameDescriptionEntry<'input, LittleEndian, EhFrame<'input, LittleEndian>> {
        let bases = BaseAddresses::default()
            .set_cfi(0)
            .set_data(0)
            .set_text(0);

        let mut longest: Option<(usize, FrameDescriptionEntry<_, _>)> = None;

        let mut entries = eh_frame.entries(&bases);
        while let Some(entry) = entries.next().expect("Should parse CFI entry OK") {
            match entry {
                CieOrFde::Cie(_) => {}
                CieOrFde::Fde(partial) => {
                    let fde = partial.parse(|offset| eh_frame.cie_from_offset(&bases, offset))
                        .expect("Should be able to get CIE for FED");

                    let this_len = instrs_len(&fde);

                    let found_new_longest = match longest {
                        None => true,
                        Some((longest_len, ref _fde)) => this_len > longest_len,
                    };

                    if found_new_longest {
                        longest = Some((this_len, fde));
                    }
                }
            };
        }

        longest.expect("At least one FDE in .eh_frame").1
    }

    #[bench]
    fn parse_longest_fde_instructions(b: &mut test::Bencher) {
        let eh_frame = read_section("eh_frame");
        let eh_frame = EhFrame::<LittleEndian>::new(&eh_frame);
        let fde = get_fde_with_longest_cfi_instructions(eh_frame);

        b.iter(|| {
            let mut instrs = fde.instructions();
            while let Some(i) = instrs.next().expect("Should parse instruction OK") {
                test::black_box(i);
            }
        });
    }

    #[bench]
    fn eval_longest_fde_instructions_new_ctx_everytime(b: &mut test::Bencher) {
        let eh_frame = read_section("eh_frame");
        let eh_frame = EhFrame::<LittleEndian>::new(&eh_frame);
        let fde = get_fde_with_longest_cfi_instructions(eh_frame);

        b.iter(|| {
            let mut ctx = UninitializedUnwindContext::new()
                .initialize(fde.cie())
                .expect("Should initialize the ctx OK");

            let mut table = UnwindTable::new(&mut ctx, &fde);
            while let Some(row) = table.next_row().expect("Should get next unwind table row") {
                test::black_box(row);
            }
        });
    }

    #[bench]
    fn eval_longest_fde_instructions_same_ctx(b: &mut test::Bencher) {
        let eh_frame = read_section("eh_frame");
        let eh_frame = EhFrame::<LittleEndian>::new(&eh_frame);
        let fde = get_fde_with_longest_cfi_instructions(eh_frame);

        let mut ctx = Some(UninitializedUnwindContext::new());

        b.iter(|| {
            let mut context = ctx.take()
                .unwrap()
                .initialize(fde.cie())
                .expect("Should be able to initialize ctx");

            {
                let mut table = UnwindTable::new(&mut context, &fde);
                while let Some(row) = table.next_row().expect("Should get next unwind table row") {
                    test::black_box(row);
                }
            }

            ctx = Some(context.reset());
        });
    }
}
