extern crate gimli;

use std::env;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use gimli::read;
use gimli::write::{self, Address, EndianVec};
use gimli::LittleEndian;

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
fn test_convert_debug_info() {
    // Convert existing sections
    let debug_abbrev = read_section("debug_abbrev");
    let debug_abbrev = read::DebugAbbrev::new(&debug_abbrev, LittleEndian);

    let debug_info = read_section("debug_info");
    let debug_info = read::DebugInfo::new(&debug_info, LittleEndian);

    let debug_line = read_section("debug_line");
    let debug_line = read::DebugLine::new(&debug_line, LittleEndian);

    let debug_str = read_section("debug_str");
    let debug_str = read::DebugStr::new(&debug_str, LittleEndian);

    let debug_ranges = read_section("debug_ranges");
    let debug_ranges = read::DebugRanges::new(&debug_ranges, LittleEndian);

    let debug_rnglists = read::DebugRngLists::new(&[], LittleEndian);

    let ranges = gimli::RangeLists::new(debug_ranges, debug_rnglists);

    let dwarf = read::Dwarf {
        debug_abbrev,
        debug_info,
        debug_line,
        debug_str,
        ranges,
        ..Default::default()
    };

    let mut line_strings = write::LineStringTable::default();
    let mut strings = write::StringTable::default();
    let units = write::UnitTable::from(&dwarf, &mut line_strings, &mut strings, &|address| {
        Some(Address::Absolute(address))
    })
    .expect("Should convert compilation units");
    assert_eq!(units.count(), 23);
    let entries: usize = (0..units.count())
        .map(|i| units.get(units.id(i)).count())
        .sum();
    assert_eq!(entries, 29_560);
    assert_eq!(line_strings.count(), 0);
    assert_eq!(strings.count(), 3921);

    // Write to new sections
    let debug_line_str_offsets = write::DebugLineStrOffsets::none();

    let mut write_debug_str = write::DebugStr::from(EndianVec::new(LittleEndian));
    let debug_str_offsets = strings
        .write(&mut write_debug_str)
        .expect("Should write strings");
    let debug_str_data = write_debug_str.slice();
    assert_eq!(debug_str_offsets.count(), 3921);
    assert_eq!(debug_str_data.len(), 144_731);

    let mut write_debug_abbrev = write::DebugAbbrev::from(EndianVec::new(LittleEndian));
    let mut write_debug_info = write::DebugInfo::from(EndianVec::new(LittleEndian));
    let mut write_debug_line = write::DebugLine::from(EndianVec::new(LittleEndian));
    let mut write_debug_ranges = write::DebugRanges::from(EndianVec::new(LittleEndian));
    let mut write_debug_rnglists = write::DebugRngLists::from(EndianVec::new(LittleEndian));
    units
        .write(
            &mut write_debug_abbrev,
            &mut write_debug_info,
            &mut write_debug_line,
            &mut write_debug_ranges,
            &mut write_debug_rnglists,
            &debug_line_str_offsets,
            &debug_str_offsets,
        )
        .expect("Should write units");
    let debug_info_data = write_debug_info.slice();
    let debug_abbrev_data = write_debug_abbrev.slice();
    let debug_line_data = write_debug_line.slice();
    let debug_ranges_data = write_debug_ranges.slice();
    assert_eq!(debug_info_data.len(), 394_930);
    assert_eq!(debug_abbrev_data.len(), 1282);
    assert_eq!(debug_line_data.len(), 105_797);
    assert_eq!(debug_ranges_data.len(), 155_712);

    // Convert new sections
    let debug_abbrev = read::DebugAbbrev::new(debug_abbrev_data, LittleEndian);
    let debug_info = read::DebugInfo::new(debug_info_data, LittleEndian);
    let debug_line = read::DebugLine::new(debug_line_data, LittleEndian);
    let debug_str = read::DebugStr::new(debug_str_data, LittleEndian);
    let debug_ranges = read::DebugRanges::new(debug_ranges_data, LittleEndian);
    let debug_rnglists = read::DebugRngLists::new(&[], LittleEndian);

    let ranges = gimli::RangeLists::new(debug_ranges, debug_rnglists);

    let dwarf = read::Dwarf {
        debug_abbrev,
        debug_info,
        debug_line,
        debug_str,
        ranges,
        ..Default::default()
    };

    let mut line_strings = write::LineStringTable::default();
    let mut strings = write::StringTable::default();
    let units = write::UnitTable::from(&dwarf, &mut line_strings, &mut strings, &|address| {
        Some(Address::Absolute(address))
    })
    .expect("Should convert compilation units");
    assert_eq!(units.count(), 23);
    let entries: usize = (0..units.count())
        .map(|i| units.get(units.id(i)).count())
        .sum();
    assert_eq!(entries, 29_560);
    assert_eq!(strings.count(), 3921);
}
