extern crate gimli;

use gimli::{AttributeValue, DebugAbbrev, DebugAranges, DebugInfo, DebugLine, DebugPubNames,
            DebugPubTypes, DebugStr, LittleEndian};
use std::env;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

fn read_section(section: &str) -> Vec<u8> {
    let mut path = PathBuf::new();
    if let Ok(dir) = env::var("CARGO_MANIFEST_DIR") {
        path.push(dir);
    }
    path.push("fixtures/self");
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

    let mut iter = debug_info.units();
    while let Some(unit) = iter.next().expect("Should parse compilation unit") {
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

    let debug_str = read_section("debug_str");
    let debug_str = DebugStr::<LittleEndian>::new(&debug_str);

    let mut iter = debug_info.units();
    while let Some(unit) = iter.next().expect("Should parse compilation unit") {
        let abbrevs = unit.abbreviations(debug_abbrev)
            .expect("Should parse abbreviations");

        let mut cursor = unit.entries(&abbrevs);
        cursor.next_dfs().expect("Should parse next dfs");

        let unit_entry = cursor.current()
            .expect("Should have a root entry");

        let comp_dir = unit_entry.attr(gimli::DW_AT_comp_dir)
            .and_then(|attr| attr.string_value(&debug_str));
        let comp_name = unit_entry.attr(gimli::DW_AT_name)
            .and_then(|attr| attr.string_value(&debug_str));

        if let Some(AttributeValue::DebugLineRef(offset)) =
               unit_entry.attr_value(gimli::DW_AT_stmt_list) {
            let header = debug_line.header(offset, unit.address_size(), comp_dir, comp_name)
                .expect("should parse line number program header");

            let mut rows = header.rows();
            while let Some(_) = rows.next_row()
                .expect("Should parse and execute all rows in the line number program") {
            }
        }
    }
}

#[test]
fn test_parse_self_debug_aranges() {
    let debug_aranges = read_section("debug_aranges");
    let debug_aranges = DebugAranges::<LittleEndian>::new(&debug_aranges);

    let mut aranges = debug_aranges.items();
    while let Some(_) = aranges.next().expect("Should parse arange OK") {
        // Not really anything else we can check right now.
    }
}

#[test]
fn test_parse_self_debug_pubnames() {
    let debug_pubnames = read_section("debug_pubnames");
    let debug_pubnames = DebugPubNames::<LittleEndian>::new(&debug_pubnames);

    let mut pubnames = debug_pubnames.items();
    while let Some(_) = pubnames.next().expect("Should parse pubname OK") {
        // Not really anything else we can check right now.
    }
}

#[test]
fn test_parse_self_debug_pubtypes() {
    let debug_pubtypes = read_section("debug_pubtypes");
    let debug_pubtypes = DebugPubTypes::<LittleEndian>::new(&debug_pubtypes);

    let mut pubtypes = debug_pubtypes.items();
    while let Some(_) = pubtypes.next().expect("Should parse pubtype OK") {
        // Not really anything else we can check right now.
    }
}

// Because `.eh_frame` doesn't contain address sizes, we need to assume the
// native word size, so this test is only valid on 64-bit machines (as the
// `.eh_frame` fixture data was created on a 64-bit machine).
#[cfg(target_pointer_width="64")]
#[test]
fn test_parse_self_eh_frame() {
    use gimli::{BaseAddresses, CieOrFde, EhFrame, UnwindSection};

    let eh_frame = read_section("eh_frame");
    let eh_frame = EhFrame::<LittleEndian>::new(&eh_frame);

    let bases = BaseAddresses::default()
        .set_cfi(0)
        .set_data(0)
        .set_text(0);
    let mut entries = eh_frame.entries(&bases);
    while let Some(entry) = entries.next().expect("Should parse CFI entry OK") {
        match entry {
            CieOrFde::Cie(cie) => {
                let mut instrs = cie.instructions();
                while let Some(_) = instrs.next().expect("Can parse next CFI instruction OK") {
                    // TODO FITZGEN
                }
            }
            CieOrFde::Fde(partial) => {
                let fde = partial.parse(|offset| eh_frame.cie_from_offset(&bases, offset))
                    .expect("Should be able to get CIE for FDE");

                let mut instrs = fde.instructions();
                while let Some(_) = instrs.next().expect("Can parse next CFI instruction OK") {
                    // TODO FITZGEN
                }
            }
        }
    }
}
