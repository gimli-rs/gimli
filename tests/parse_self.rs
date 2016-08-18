extern crate byteorder;
extern crate gimli;

use gimli::{AttributeValue, DebugAbbrev, DebugAranges, DebugInfo, DebugLine,
            DW_AT_stmt_list, LineNumberProgramHeader, LittleEndian, StateMachine};
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

            let mut attrs = entry.attrs();
            while let Some(_) = attrs.next().expect("Should parse entry's attribute") {
            }
        }
    }
}

#[test]
fn test_parse_self_debug_line() {
    let debug_info = read_section("debug_info");
    let debug_info = DebugInfo::<LittleEndian>::new(&debug_info);

    let debug_abbrev = read_section("debug_abbrev");
    let debug_abbrev = DebugAbbrev::<LittleEndian>::new(&debug_abbrev);

    let debug_line = read_section("debug_line");
    let debug_line = DebugLine::<LittleEndian>::new(&debug_line);

    for unit in debug_info.units() {
        let unit = unit.expect("Should parse the unit OK");

        let abbrevs = unit.abbreviations(debug_abbrev)
            .expect("Should parse abbreviations");

        let mut cursor = unit.entries(&abbrevs);
        cursor.next_dfs().expect("Should parse next dfs");

        let unit_entry = cursor.current()
            .expect("Should have a root entry");

        if let Some(AttributeValue::DebugLineRef(offset)) = unit_entry.attr_value(DW_AT_stmt_list) {
            let header = LineNumberProgramHeader::new(debug_line, offset, unit.address_size())
                .expect("should parse line number program header");

            let mut state_machine = StateMachine::new(&header);
            while let Some(_) = state_machine.next_row()
                .expect("Should parse and execute all rows in the line number program") {
            }
        }
    }
}

#[test]
fn test_parse_self_debug_aranges() {
    let debug_aranges = read_section("debug_aranges");
    let debug_aranges = DebugAranges::<LittleEndian>::new(&debug_aranges);

    let mut aranges = debug_aranges.aranges();
    while let Some(_) = aranges.next_arange().expect("Should parse arange OK") {
        // Not really anything else we can check right now.
    }
}
