extern crate byteorder;
extern crate gimli;

use byteorder::ByteOrder;
use gimli::{AttributeValue, DebugAbbrev, DebugInfo, DebugLine, DebugLineOffset, DW_AT_stmt_list,
            LineNumberProgramHeader, LittleEndian};
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

        if let Some(value) = unit_entry.attr_value(DW_AT_stmt_list) {
            // For whatever reason, rustc generated DW_FORM_data4 typed
            // attributes for DW_AT_stmt_list attributes, when it seems to me
            // like the more correct choice would be DW_FORM_sec_offset (the
            // spec seems to agree -- see pages 214-215). Because of this, we
            // have to turn the data into an offset.
            let offset = match value {
                AttributeValue::Data(data) => LittleEndian::read_u32(data),
                otherwise => panic!("unexpected value form: {:?}", otherwise),
            };
            let offset = DebugLineOffset(offset as u64);

            LineNumberProgramHeader::new(debug_line, offset)
                .expect("should parse line number program header");
        }
    }
}
