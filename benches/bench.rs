#![feature(test)]

extern crate gimli;
extern crate test;

use gimli::{DebugAbbrev, DebugInfo, LittleEndian};

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

        for unit in debug_info.units() {
            let unit = unit.expect("Should parse compilation unit");
            let abbrevs = unit.abbreviations(debug_abbrev)
                .expect("Should parse abbreviations");

            let mut cursor = unit.entries(&abbrevs);

            loop {
                {
                    let entry = cursor.current_ref()
                        .expect("Should have a current entry")
                        .expect("And should parse that entry OK");

                    for attr in entry.attrs() {
                        test::black_box(attr.expect("Should parse entry's attribute"));
                    }
                }

                if let None = cursor.next_dfs().expect("Should parse next dfs") {
                    break;
                }
            }
        }
    });
}
