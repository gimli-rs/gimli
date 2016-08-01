extern crate gimli;
use gimli::{AttributeValue, DebugAbbrev, DebugInfo, DebuggingInformationEntry, Endianity,
            EntriesCursor, LittleEndian, UnitHeader};
use std::ffi;

#[cfg(test)]
fn assert_entry_name<Endian>(entry: &DebuggingInformationEntry<Endian>, name: &str)
    where Endian: Endianity
{
    let value = entry.attr_value(gimli::DW_AT_name)
        .expect("Should have found the name attribute");

    let mut with_null: Vec<u8> = name.as_bytes().into();
    with_null.push(0);

    assert_eq!(value,
               AttributeValue::String(ffi::CStr::from_bytes_with_nul(&with_null).unwrap()));
}

#[cfg(test)]
fn assert_current_name<Endian>(cursor: &EntriesCursor<Endian>, name: &str)
    where Endian: Endianity
{
    let entry = cursor.current().expect("Should have an entry result");
    assert_entry_name(entry, name);
}

#[cfg(test)]
fn assert_next_entry<Endian>(cursor: &mut EntriesCursor<Endian>, name: &str)
    where Endian: Endianity
{
    cursor.next_entry()
        .expect("Should parse next entry")
        .expect("Should have an entry");
    assert_current_name(cursor, name);
}

#[cfg(test)]
fn assert_next_entry_null<Endian>(cursor: &mut EntriesCursor<Endian>)
    where Endian: Endianity
{
    cursor.next_entry()
        .expect("Should parse next entry")
        .expect("Should have an entry");
    assert!(cursor.current().is_none());
}

#[cfg(test)]
fn assert_next_dfs<Endian>(cursor: &mut EntriesCursor<Endian>, name: &str, depth: isize)
    where Endian: Endianity
{
    {
        let (val, entry) = cursor.next_dfs()
            .expect("Should parse next dfs")
            .expect("Should not be done with traversal");
        assert_eq!(val, depth);
        assert_entry_name(entry, name);
    }
    assert_current_name(cursor, name);
}

#[cfg(test)]
fn assert_next_sibling<Endian>(cursor: &mut EntriesCursor<Endian>, name: &str)
    where Endian: Endianity
{
    {
        let entry = cursor.next_sibling()
            .expect("Should parse next sibling")
            .expect("Should not be done with traversal");
        assert_entry_name(entry, name);
    }
    assert_current_name(cursor, name);
}

#[cfg(test)]
fn assert_valid_sibling_ptr<Endian>(unit: &UnitHeader<Endian>, cursor: &EntriesCursor<Endian>)
    where Endian: Endianity
{
    let sibling_ptr =
        cursor.current().expect("Should have current entry").attr_value(gimli::DW_AT_sibling);
    match sibling_ptr {
        Some(AttributeValue::UnitRef(offset)) => {
            unit.range_from(offset..);
        }
        _ => panic!("Invalid sibling pointer {:?}", sibling_ptr),
    }
}

#[cfg(test)]
#[cfg_attr(rustfmt, rustfmt_skip)]
const ENTRIES_CURSOR_TESTS_ABBREV_BUF: [u8; 8] = [
    // Code
    0x01,

    // DW_TAG_subprogram
    0x2e,

    // DW_CHILDREN_yes
    0x01,

    // Begin attributes

        // Attribute name = DW_AT_name
        0x03,
        // Attribute form = DW_FORM_string
        0x08,

    // End attributes
    0x00,
    0x00,

    // Null terminator
    0x00
];

#[cfg(test)]
#[cfg_attr(rustfmt, rustfmt_skip)]
const ENTRIES_CURSOR_TESTS_DEBUG_INFO_BUF: [u8; 71] = [
    // Compilation unit header

    // 32-bit unit length = 67
    0x43, 0x00, 0x00, 0x00,
    // Version 4
    0x04, 0x00,
    // debug_abbrev_offset
    0x00, 0x00, 0x00, 0x00,
    // Address size
    0x04,

    // DIEs

    // Abbreviation code
    0x01,
    // Attribute of form DW_FORM_string = "001\0"
    0x30, 0x30, 0x31, 0x00,

    // Children

        // Abbreviation code
        0x01,
        // Attribute of form DW_FORM_string = "002\0"
        0x30, 0x30, 0x32, 0x00,

        // Children

            // Abbreviation code
            0x01,
            // Attribute of form DW_FORM_string = "003\0"
            0x30, 0x30, 0x33, 0x00,

            // Children

            // End of children
            0x00,

        // End of children
        0x00,

        // Abbreviation code
        0x01,
        // Attribute of form DW_FORM_string = "004\0"
        0x30, 0x30, 0x34, 0x00,

        // Children

            // Abbreviation code
            0x01,
            // Attribute of form DW_FORM_string = "005\0"
            0x30, 0x30, 0x35, 0x00,

            // Children

            // End of children
            0x00,

            // Abbreviation code
            0x01,
            // Attribute of form DW_FORM_string = "006\0"
            0x30, 0x30, 0x36, 0x00,

            // Children

            // End of children
            0x00,

        // End of children
        0x00,

        // Abbreviation code
        0x01,
        // Attribute of form DW_FORM_string = "007\0"
        0x30, 0x30, 0x37, 0x00,

        // Children

            // Abbreviation code
            0x01,
            // Attribute of form DW_FORM_string = "008\0"
            0x30, 0x30, 0x38, 0x00,

            // Children

                // Abbreviation code
                0x01,
                // Attribute of form DW_FORM_string = "009\0"
                0x30, 0x30, 0x39, 0x00,

                // Children

                // End of children
                0x00,

            // End of children
            0x00,

        // End of children
        0x00,

        // Abbreviation code
        0x01,
        // Attribute of form DW_FORM_string = "010\0"
        0x30, 0x31, 0x30, 0x00,

        // Children

        // End of children
        0x00,

    // End of children
    0x00
];

#[test]
#[cfg_attr(rustfmt, rustfmt_skip)]
fn test_cursor_next_entry_incomplete() {
    // Set short length in unit header.
    let info_buf = &mut ENTRIES_CURSOR_TESTS_DEBUG_INFO_BUF;
    info_buf[0] = 0x12;
    let debug_info = DebugInfo::<LittleEndian>::new(info_buf);

    let unit = debug_info.units().next()
        .expect("should have a unit result")
        .expect("and it should be ok");

    let abbrevs_buf = &ENTRIES_CURSOR_TESTS_ABBREV_BUF;
    let debug_abbrev = DebugAbbrev::<LittleEndian>::new(abbrevs_buf);

    let abbrevs = unit.abbreviations(debug_abbrev)
        .expect("Should parse abbreviations");

    let mut cursor = unit.entries(&abbrevs);

    assert_next_entry(&mut cursor, "001");
    assert_next_entry(&mut cursor, "002");

    {
        // Entry code is present, but none of the attributes.
        cursor.next_entry()
            .expect("Should parse next entry")
            .expect("Should have an entry");
        let entry = cursor.current().expect("Should have an entry result");
        assert!(entry.attrs().next().is_err());
    }

    assert!(cursor.next_entry().is_err());
    assert!(cursor.next_entry().is_err());
}

#[test]
#[cfg_attr(rustfmt, rustfmt_skip)]
fn test_cursor_next_entry() {
    let info_buf = &ENTRIES_CURSOR_TESTS_DEBUG_INFO_BUF;
    let debug_info = DebugInfo::<LittleEndian>::new(info_buf);

    let unit = debug_info.units().next()
        .expect("should have a unit result")
        .expect("and it should be ok");

    let abbrevs_buf = &ENTRIES_CURSOR_TESTS_ABBREV_BUF;
    let debug_abbrev = DebugAbbrev::<LittleEndian>::new(abbrevs_buf);

    let abbrevs = unit.abbreviations(debug_abbrev)
        .expect("Should parse abbreviations");

    let mut cursor = unit.entries(&abbrevs);

    assert_next_entry(&mut cursor, "001");
    assert_next_entry(&mut cursor, "002");
    assert_next_entry(&mut cursor, "003");
    assert_next_entry_null(&mut cursor);
    assert_next_entry_null(&mut cursor);
    assert_next_entry(&mut cursor, "004");
    assert_next_entry(&mut cursor, "005");
    assert_next_entry_null(&mut cursor);
    assert_next_entry(&mut cursor, "006");
    assert_next_entry_null(&mut cursor);
    assert_next_entry_null(&mut cursor);
    assert_next_entry(&mut cursor, "007");
    assert_next_entry(&mut cursor, "008");
    assert_next_entry(&mut cursor, "009");
    assert_next_entry_null(&mut cursor);
    assert_next_entry_null(&mut cursor);
    assert_next_entry_null(&mut cursor);
    assert_next_entry(&mut cursor, "010");
    assert_next_entry_null(&mut cursor);
    assert_next_entry_null(&mut cursor);

    assert!(cursor.next_entry().expect("Should parse next entry").is_none());
    assert!(cursor.current().is_none());
}

#[test]
#[cfg_attr(rustfmt, rustfmt_skip)]
fn test_cursor_next_dfs() {
    let info_buf = &ENTRIES_CURSOR_TESTS_DEBUG_INFO_BUF;
    let debug_info = DebugInfo::<LittleEndian>::new(info_buf);

    let unit = debug_info.units().next()
        .expect("should have a unit result")
        .expect("and it should be ok");

    let abbrevs_buf = &ENTRIES_CURSOR_TESTS_ABBREV_BUF;
    let debug_abbrev = DebugAbbrev::<LittleEndian>::new(abbrevs_buf);

    let abbrevs = unit.abbreviations(debug_abbrev)
        .expect("Should parse abbreviations");

    let mut cursor = unit.entries(&abbrevs);

    assert_next_dfs(&mut cursor, "001", 0);
    assert_next_dfs(&mut cursor, "002", 1);
    assert_next_dfs(&mut cursor, "003", 1);
    assert_next_dfs(&mut cursor, "004", -1);
    assert_next_dfs(&mut cursor, "005", 1);
    assert_next_dfs(&mut cursor, "006", 0);
    assert_next_dfs(&mut cursor, "007", -1);
    assert_next_dfs(&mut cursor, "008", 1);
    assert_next_dfs(&mut cursor, "009", 1);
    assert_next_dfs(&mut cursor, "010", -2);

    assert!(cursor.next_dfs().expect("Should parse next dfs").is_none());
    assert!(cursor.current().is_none());
}

#[test]
#[cfg_attr(rustfmt, rustfmt_skip)]
fn test_cursor_next_sibling_no_sibling_ptr() {
    let info_buf = &ENTRIES_CURSOR_TESTS_DEBUG_INFO_BUF;
    let debug_info = DebugInfo::<LittleEndian>::new(info_buf);

    let unit = debug_info.units().next()
        .expect("should have a unit result")
        .expect("and it should be ok");

    let abbrevs_buf = &ENTRIES_CURSOR_TESTS_ABBREV_BUF;
    let debug_abbrev = DebugAbbrev::<LittleEndian>::new(abbrevs_buf);

    let abbrevs = unit.abbreviations(debug_abbrev)
        .expect("Should parse abbreviations");

    let mut cursor = unit.entries(&abbrevs);

    assert_next_dfs(&mut cursor, "001", 0);

    // Down to the first child of the root entry.

    assert_next_dfs(&mut cursor, "002", 1);

    // Now iterate all children of the root via `next_sibling`.

    assert_next_sibling(&mut cursor, "004");
    assert_next_sibling(&mut cursor, "007");
    assert_next_sibling(&mut cursor, "010");

    // There should be no more siblings.

    assert!(cursor.next_sibling().expect("Should parse next sibling").is_none());
    assert!(cursor.current().is_none());
}

#[test]
fn test_cursor_next_sibling_continuation() {
    let info_buf = &ENTRIES_CURSOR_TESTS_DEBUG_INFO_BUF;
    let debug_info = DebugInfo::<LittleEndian>::new(info_buf);

    let unit = debug_info.units()
        .next()
        .expect("should have a unit result")
        .expect("and it should be ok");

    let abbrevs_buf = &ENTRIES_CURSOR_TESTS_ABBREV_BUF;
    let debug_abbrev = DebugAbbrev::<LittleEndian>::new(abbrevs_buf);

    let abbrevs = unit.abbreviations(debug_abbrev)
        .expect("Should parse abbreviations");

    let mut cursor = unit.entries(&abbrevs);

    assert_next_dfs(&mut cursor, "001", 0);

    // Down to the first child of the root entry.

    assert_next_dfs(&mut cursor, "002", 1);

    // Get the next sibling, then iterate its children

    assert_next_sibling(&mut cursor, "004");
    assert_next_dfs(&mut cursor, "005", 1);
    assert_next_sibling(&mut cursor, "006");
    assert!(cursor.next_sibling().expect("Should parse next sibling").is_none());
    assert!(cursor.next_sibling().expect("Should parse next sibling").is_none());
    assert!(cursor.next_sibling().expect("Should parse next sibling").is_none());
    assert!(cursor.next_sibling().expect("Should parse next sibling").is_none());

    // And we should be able to continue with the children of the root entry.

    assert_next_dfs(&mut cursor, "007", -1);
    assert_next_sibling(&mut cursor, "010");

    // There should be no more siblings.

    assert!(cursor.next_sibling().expect("Should parse next sibling").is_none());
    assert!(cursor.current().is_none());
}

#[test]
#[cfg_attr(rustfmt, rustfmt_skip)]
fn test_cursor_next_sibling_with_sibling_ptr() {
    let info_buf = [
        // Compilation unit header

        // 32-bit unit length = 56
        0x38, 0x00, 0x00, 0x00,
        // Version 4
        0x04, 0x00,
        // debug_abbrev_offset
        0x00, 0x00, 0x00, 0x00,
        // Address size
        0x04,

        // DIEs

        // Abbreviation code
        0x01,

        // DW_AT_name of form DW_FORM_string = "001\0"
        0x30, 0x30, 0x31, 0x00,
        // DW_AT_sibling of form DW_FORM_ref1
        0x00,

        // Children

            // Abbreviation code
            0x01,

            // DW_AT_name of form DW_FORM_string = "002\0"
            0x30, 0x30, 0x32, 0x00,
            // Valid DW_AT_sibling pointer of form DW_FORM_ref1 = 31
            0x1f,

            // Children

                // Abbreviation code
                0x01,

                // DW_AT_name of form DW_FORM_string = "003\0"
                0x30, 0x30, 0x33, 0x00,
                // DW_AT_sibling of form DW_FORM_ref1
                0x00,

                // No children
                0x00,

            // End children
            0x00,

            // Abbreviation code
            0x01,

            // DW_AT_name of form DW_FORM_string = "004\0"
            0x30, 0x30, 0x34, 0x00,
            // Invalid DW_AT_sibling of form DW_FORM_ref1 = 255
            0xff,

            // Children

                // Abbreviation code
                0x01,

                // DW_AT_name of form DW_FORM_string = "005\0"
                0x30, 0x30, 0x35, 0x00,
                // DW_AT_sibling of form DW_FORM_ref1
                0x00,

                // No children
                0x00,

            // End children
            0x00,

            // Abbreviation code
            0x01,

            // DW_AT_name of form DW_FORM_string = "006\0"
            0x30, 0x30, 0x36, 0x00,
            // DW_AT_sibling of form DW_FORM_ref1
            0x00,

            // Children

                // Abbreviation code
                0x01,

                // DW_AT_name of form DW_FORM_string = "007\0"
                0x30, 0x30, 0x37, 0x00,
                // DW_AT_sibling of form DW_FORM_ref1
                0x00,

                // No children
                0x00,

            // End children
            0x00,

        // End children
        0x00,
    ];

    let debug_info = DebugInfo::<LittleEndian>::new(&info_buf);

    let unit = debug_info.units().next()
        .expect("should have a unit result")
        .expect("and it should be ok");

    let abbrev_buf = [
        // Code
        0x01,

        // DW_TAG_subprogram
        0x2e,

        // DW_CHILDREN_yes
        0x01,

        // Begin attributes

        // Attribute name = DW_AT_name
        0x03,
        // Attribute form = DW_FORM_string
        0x08,

        // Attribute name = DW_AT_sibling
        0x01,
        // Attribute form = DW_FORM_ref1
        0x11,

        // End attributes
        0x00,
        0x00,

        // Null terminator
        0x00
    ];

    let debug_abbrev = DebugAbbrev::<LittleEndian>::new(&abbrev_buf);

    let abbrevs = unit.abbreviations(debug_abbrev)
        .expect("Should parse abbreviations");

    let mut cursor = unit.entries(&abbrevs);

    assert_next_dfs(&mut cursor, "001", 0);

    // Down to the first child of the root.

    assert_next_dfs(&mut cursor, "002", 1);

    // Now iterate all children of the root via `next_sibling`.

    assert_valid_sibling_ptr(&unit, &cursor);
    assert_next_sibling(&mut cursor, "004");

    assert_next_sibling(&mut cursor, "006");

    // There should be no more siblings.

    assert!(cursor.next_sibling().expect("Should parse next sibling").is_none());
    assert!(cursor.current().is_none());
}
