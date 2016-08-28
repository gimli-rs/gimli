#![feature(test)]

extern crate gimli;
extern crate test;

use gimli::{DebugAbbrev, DebugAranges, DebugInfo, DebugLine, DebugLineOffset, DebugPubNames,
            DebugPubTypes, LineNumberProgramHeader, LittleEndian, StateMachine};
use std::env;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

fn read_section(section: &str) -> Vec<u8> {
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

            let mut cursor = unit.entries(&abbrevs);
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
        let header = LineNumberProgramHeader::new(debug_line, OFFSET, ADDRESS_SIZE)
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
        let header = LineNumberProgramHeader::new(debug_line, OFFSET, ADDRESS_SIZE)
            .expect("Should parse line number program header");

        let mut state_machine = StateMachine::new(header);
        while let Some(row) = state_machine.next_row()
            .expect("Should parse and execute all rows in the line number program") {
            test::black_box(row);
        }
    });
}
