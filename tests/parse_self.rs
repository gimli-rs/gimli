extern crate gimli;
use gimli::{DebugAbbrev, DebugInfo, LittleEndian};

use std::env;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

fn read_section(section: &str) -> Vec<u8> {
    let mut path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    path.push("./fixtures/self/");
    path.push(section);

    println!("Reading section \"{}\" at path {:?}", section, path);
    assert!(path.is_file());
    let mut file = File::open(path).unwrap();

    let mut buf = Vec::new();
    file.read_to_end(&mut buf).unwrap();
    buf
}

#[test]
fn test_parse_self_debug_info() {
    let debug_info = read_section("debug_info");
    let debug_info = DebugInfo::<LittleEndian>::new(&debug_info);

    let debug_abbrev = read_section("debug_abbrev");
    let debug_abbrev = DebugAbbrev::<LittleEndian>::new(&debug_abbrev);

    for unit in debug_info.units() {
        let unit = unit.expect("Should parse compilation unit");
        let abbrevs = unit.abbreviations(debug_abbrev)
            .expect("Should parse abbreviations");

        let mut cursor = unit.entries(&abbrevs);

        while cursor.next_dfs().expect("Should parse next dfs").is_some() {
            let entry = cursor.current().expect("Should have a current entry");

            for attr in entry.attrs() {
                attr.expect("Should parse entry's attribute");
            }
        }
    }
}
