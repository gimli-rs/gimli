extern crate gimli;

use gimli::{AttributeValue, DebugAbbrev, DebugAranges, DebugInfo, DebugLine, DebugLoc,
            DebugPubNames, DebugPubTypes, DebugRanges, DebugStr, Expression, Format, LittleEndian,
            Operation, Reader};
use std::env;
use std::collections::hash_map::HashMap;
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

fn parse_expression<R: Reader>(expr: Expression<R>, address_size: u8, format: Format) {
    let mut pc = expr.0.clone();
    while !pc.is_empty() {
        Operation::parse(&mut pc, &expr.0, address_size, format).expect("Should parse operation");
    }

    // Also attempt to evaluate some of it.
    let mut eval = expr.evaluation(address_size, format);
    eval.set_initial_value(0);
    eval.evaluate().expect("Should evaluate expression");
}

#[test]
fn test_parse_self_debug_info() {
    let debug_info = read_section("debug_info");
    let debug_info = DebugInfo::new(&debug_info, LittleEndian);

    let debug_abbrev = read_section("debug_abbrev");
    let debug_abbrev = DebugAbbrev::new(&debug_abbrev, LittleEndian);

    let mut iter = debug_info.units();
    while let Some(unit) = iter.next().expect("Should parse compilation unit") {
        let abbrevs = unit.abbreviations(&debug_abbrev)
            .expect("Should parse abbreviations");

        let mut cursor = unit.entries(&abbrevs);

        while cursor.next_dfs().expect("Should parse next dfs").is_some() {
            let entry = cursor.current().expect("Should have a current entry");

            let mut attrs = entry.attrs();
            while let Some(attr) = attrs.next().expect("Should parse entry's attribute") {
                if let AttributeValue::Exprloc(expression) = attr.value() {
                    parse_expression(expression, unit.address_size(), unit.format());
                }
            }
        }
    }
}

#[test]
fn test_parse_self_debug_line() {
    let debug_info = read_section("debug_info");
    let debug_info = DebugInfo::new(&debug_info, LittleEndian);

    let debug_abbrev = read_section("debug_abbrev");
    let debug_abbrev = DebugAbbrev::new(&debug_abbrev, LittleEndian);

    let debug_line = read_section("debug_line");
    let debug_line = DebugLine::new(&debug_line, LittleEndian);

    let debug_str = read_section("debug_str");
    let debug_str = DebugStr::new(&debug_str, LittleEndian);

    let mut iter = debug_info.units();
    while let Some(unit) = iter.next().expect("Should parse compilation unit") {
        let abbrevs = unit.abbreviations(&debug_abbrev)
            .expect("Should parse abbreviations");

        let mut cursor = unit.entries(&abbrevs);
        cursor.next_dfs().expect("Should parse next dfs");

        let unit_entry = cursor.current().expect("Should have a root entry");

        let comp_dir = unit_entry
            .attr(gimli::DW_AT_comp_dir)
            .expect("Should parse comp_dir attribute")
            .and_then(|attr| attr.string_value(&debug_str));
        let comp_name = unit_entry
            .attr(gimli::DW_AT_name)
            .expect("Should parse name attribute")
            .and_then(|attr| attr.string_value(&debug_str));

        if let Some(AttributeValue::DebugLineRef(offset)) = unit_entry
            .attr_value(gimli::DW_AT_stmt_list)
            .expect("Should parse stmt_list")
        {
            let program = debug_line
                .program(offset, unit.address_size(), comp_dir, comp_name)
                .expect("should parse line number program header");

            let mut results = Vec::new();
            let mut rows = program.rows();
            while let Some((_, row)) = rows.next_row().expect(
                "Should parse and execute all rows in the line number program",
            ) {
                results.push(*row);
            }
            results.reverse();

            let program = debug_line
                .program(offset, unit.address_size(), comp_dir, comp_name)
                .expect("should parse line number program header");
            let (program, sequences) = program
                .sequences()
                .expect("should parse and execute the entire line number program");
            assert!(!sequences.is_empty()); // Should be at least one sequence.
            for sequence in sequences {
                let mut rows = program.resume_from(&sequence);
                while let Some((_, row)) = rows.next_row()
                    .expect("Should parse and execute all rows after resuming")
                {
                    let other_row = results.pop().unwrap();
                    assert!(row.address() >= sequence.start);
                    assert!(row.address() <= sequence.end);
                    assert_eq!(row.address(), other_row.address());
                    assert_eq!(row.line(), other_row.line());
                }
            }
            assert!(results.is_empty());
        }
    }
}

#[test]
fn test_parse_self_debug_loc() {
    let debug_info = read_section("debug_info");
    let debug_info = DebugInfo::new(&debug_info, LittleEndian);

    let debug_abbrev = read_section("debug_abbrev");
    let debug_abbrev = DebugAbbrev::new(&debug_abbrev, LittleEndian);

    let debug_loc = read_section("debug_loc");
    let debug_loc = DebugLoc::new(&debug_loc, LittleEndian);

    let mut iter = debug_info.units();
    while let Some(unit) = iter.next().expect("Should parse compilation unit") {
        let abbrevs = unit.abbreviations(&debug_abbrev)
            .expect("Should parse abbreviations");

        let mut cursor = unit.entries(&abbrevs);
        cursor.next_dfs().expect("Should parse next dfs");

        let mut low_pc = 0;

        {
            let unit_entry = cursor.current().expect("Should have a root entry");
            let low_pc_attr = unit_entry
                .attr_value(gimli::DW_AT_low_pc)
                .expect("Should parse low_pc");
            if let Some(gimli::AttributeValue::Addr(address)) = low_pc_attr {
                low_pc = address;
            }
        }

        while cursor.next_dfs().expect("Should parse next dfs").is_some() {
            let entry = cursor.current().expect("Should have a current entry");
            let mut attrs = entry.attrs();
            while let Some(attr) = attrs.next().expect("Should parse entry's attribute") {
                if let AttributeValue::DebugLocRef(offset) = attr.value() {
                    let mut locs = debug_loc
                        .locations(offset, unit.address_size(), low_pc)
                        .expect("Should parse locations OK");
                    while let Some(loc) = locs.next().expect("Should parse next location") {
                        assert!(loc.range.begin <= loc.range.end);
                        parse_expression(loc.data, unit.address_size(), unit.format());
                    }
                }
            }
        }
    }
}

#[test]
fn test_parse_self_debug_ranges() {
    let debug_info = read_section("debug_info");
    let debug_info = DebugInfo::new(&debug_info, LittleEndian);

    let debug_abbrev = read_section("debug_abbrev");
    let debug_abbrev = DebugAbbrev::new(&debug_abbrev, LittleEndian);

    let debug_ranges = read_section("debug_ranges");
    let debug_ranges = DebugRanges::new(&debug_ranges, LittleEndian);

    let mut iter = debug_info.units();
    while let Some(unit) = iter.next().expect("Should parse compilation unit") {
        let abbrevs = unit.abbreviations(&debug_abbrev)
            .expect("Should parse abbreviations");

        let mut cursor = unit.entries(&abbrevs);
        cursor.next_dfs().expect("Should parse next dfs");

        let mut low_pc = 0;

        {
            let unit_entry = cursor.current().expect("Should have a root entry");
            let low_pc_attr = unit_entry
                .attr_value(gimli::DW_AT_low_pc)
                .expect("Should parse low_pc");
            if let Some(gimli::AttributeValue::Addr(address)) = low_pc_attr {
                low_pc = address;
            }
        }

        while cursor.next_dfs().expect("Should parse next dfs").is_some() {
            let entry = cursor.current().expect("Should have a current entry");
            let mut attrs = entry.attrs();
            while let Some(attr) = attrs.next().expect("Should parse entry's attribute") {
                if let AttributeValue::DebugRangesRef(offset) = attr.value() {
                    let mut ranges = debug_ranges
                        .ranges(offset, unit.address_size(), low_pc)
                        .expect("Should parse ranges OK");
                    while let Some(range) = ranges.next().expect("Should parse next range") {
                        assert!(range.begin <= range.end);
                    }
                }
            }
        }
    }
}

#[test]
fn test_parse_self_debug_aranges() {
    let debug_aranges = read_section("debug_aranges");
    let debug_aranges = DebugAranges::new(&debug_aranges, LittleEndian);

    let mut aranges = debug_aranges.items();
    while let Some(_) = aranges.next().expect("Should parse arange OK") {
        // Not really anything else we can check right now.
    }
}

#[test]
fn test_parse_self_debug_pubnames() {
    let debug_info = read_section("debug_info");
    let debug_info = DebugInfo::new(&debug_info, LittleEndian);

    let debug_abbrev = read_section("debug_abbrev");
    let debug_abbrev = DebugAbbrev::new(&debug_abbrev, LittleEndian);

    let debug_pubnames = read_section("debug_pubnames");
    let debug_pubnames = DebugPubNames::new(&debug_pubnames, LittleEndian);

    let mut units = HashMap::new();
    let mut abbrevs = HashMap::new();
    let mut pubnames = debug_pubnames.items();
    while let Some(entry) = pubnames.next().expect("Should parse pubname OK") {
        let unit_offset = entry.unit_header_offset();
        let unit = units.entry(unit_offset).or_insert_with(|| {
            debug_info
                .header_from_offset(unit_offset)
                .expect("Should parse unit header OK")
        });
        let abbrev_offset = unit.debug_abbrev_offset();
        let abbrevs = abbrevs.entry(abbrev_offset).or_insert_with(|| {
            debug_abbrev
                .abbreviations(abbrev_offset)
                .expect("Should parse abbreviations OK")
        });
        let mut cursor = unit.entries_at_offset(abbrevs, entry.die_offset())
            .expect("DIE offset should be valid");
        assert!(cursor.next_dfs().expect("Should parse DIE").is_some());
    }
}

#[test]
fn test_parse_self_debug_pubtypes() {
    let debug_info = read_section("debug_info");
    let debug_info = DebugInfo::new(&debug_info, LittleEndian);

    let debug_abbrev = read_section("debug_abbrev");
    let debug_abbrev = DebugAbbrev::new(&debug_abbrev, LittleEndian);

    let debug_pubtypes = read_section("debug_pubtypes");
    let debug_pubtypes = DebugPubTypes::new(&debug_pubtypes, LittleEndian);

    let mut units = HashMap::new();
    let mut abbrevs = HashMap::new();
    let mut pubtypes = debug_pubtypes.items();
    while let Some(entry) = pubtypes.next().expect("Should parse pubtype OK") {
        let unit_offset = entry.unit_header_offset();
        let unit = units.entry(unit_offset).or_insert_with(|| {
            debug_info
                .header_from_offset(unit_offset)
                .expect("Should parse unit header OK")
        });
        let abbrev_offset = unit.debug_abbrev_offset();
        let abbrevs = abbrevs.entry(abbrev_offset).or_insert_with(|| {
            debug_abbrev
                .abbreviations(abbrev_offset)
                .expect("Should parse abbreviations OK")
        });
        let mut cursor = unit.entries_at_offset(abbrevs, entry.die_offset())
            .expect("DIE offset should be valid");
        assert!(cursor.next_dfs().expect("Should parse DIE").is_some());
    }
}

// Because `.eh_frame` doesn't contain address sizes, we need to assume the
// native word size, so this test is only valid on 64-bit machines (as the
// `.eh_frame` fixture data was created on a 64-bit machine).
#[cfg(target_pointer_width = "64")]
#[test]
fn test_parse_self_eh_frame() {
    use gimli::{BaseAddresses, CieOrFde, EhFrame, UnwindSection};

    let eh_frame = read_section("eh_frame");
    let eh_frame = EhFrame::new(&eh_frame, LittleEndian);

    let bases = BaseAddresses::default().set_cfi(0).set_data(0).set_text(0);
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
                let fde = partial
                    .parse(|offset| eh_frame.cie_from_offset(&bases, offset))
                    .expect("Should be able to get CIE for FDE");

                let mut instrs = fde.instructions();
                while let Some(_) = instrs.next().expect("Can parse next CFI instruction OK") {
                    // TODO FITZGEN
                }
            }
        }
    }
}
