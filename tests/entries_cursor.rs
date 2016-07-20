extern crate gimli;
use gimli::{AttributeValue, DebugAbbrev, DebugInfo, DebuggingInformationEntry, Endianity, LittleEndian};

#[cfg(test)]
fn assert_entry_with_name<'input, 'abbrev, 'unit, Endian>(entry: DebuggingInformationEntry<'input,
                                                                                           'abbrev,
                                                                                           'unit,
                                                                                           Endian>,
                                                          name: &'static str)
    where Endian: Endianity
{
    let attr = entry.attrs()
        .find(|attr| attr.is_ok() && attr.unwrap().name() == gimli::DW_AT_name)
        .expect("Should have found the name attribute")
        .expect("and it should parse ok");

    let mut with_null: Vec<u8> = name.as_bytes().into();
    with_null.push(0);

    assert_eq!(attr.value(), AttributeValue::String(&with_null));
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
fn test_cursor_next_dfs() {
    let info_buf = &ENTRIES_CURSOR_TESTS_DEBUG_INFO_BUF;
    let debug_info = DebugInfo::<LittleEndian>::new(info_buf);

    let unit = debug_info.compilation_units().next()
        .expect("should have a unit result")
        .expect("and it should be ok");

    let abbrevs_buf = &ENTRIES_CURSOR_TESTS_ABBREV_BUF;
    let debug_abbrev = DebugAbbrev::<LittleEndian>::new(abbrevs_buf);

    let abbrevs = unit.abbreviations(debug_abbrev)
        .expect("Should parse abbreviations");

    let mut cursor = unit.entries(&abbrevs);

    let entry = cursor.current()
        .expect("Should have an entry result")
        .expect("and it should be ok");
    assert_entry_with_name(entry, "001");

    assert_eq!(cursor.next_dfs().expect("Should not be done with traversal"), 1);
    let entry = cursor.current()
        .expect("Should have an entry result")
        .expect("and it should be ok");
    assert_entry_with_name(entry, "002");

    assert_eq!(cursor.next_dfs().expect("Should not be done with traversal"), 1);
    let entry = cursor.current()
        .expect("Should have an entry result")
        .expect("and it should be ok");
    assert_entry_with_name(entry, "003");

    assert_eq!(cursor.next_dfs().expect("Should not be done with traversal"), -1);
    let entry = cursor.current()
        .expect("Should have an entry result")
        .expect("and it should be ok");
    assert_entry_with_name(entry, "004");

    assert_eq!(cursor.next_dfs().expect("Should not be done with traversal"), 1);
    let entry = cursor.current()
        .expect("Should have an entry result")
        .expect("and it should be ok");
    assert_entry_with_name(entry, "005");

    assert_eq!(cursor.next_dfs().expect("Should not be done with traversal"), 0);
    let entry = cursor.current()
        .expect("Should have an entry result")
        .expect("and it should be ok");
    assert_entry_with_name(entry, "006");

    assert_eq!(cursor.next_dfs().expect("Should not be done with traversal"), -1);
    let entry = cursor.current()
        .expect("Should have an entry result")
        .expect("and it should be ok");
    assert_entry_with_name(entry, "007");

    assert_eq!(cursor.next_dfs().expect("Should not be done with traversal"), 1);
    let entry = cursor.current()
        .expect("Should have an entry result")
        .expect("and it should be ok");
    assert_entry_with_name(entry, "008");

    assert_eq!(cursor.next_dfs().expect("Should not be done with traversal"), 1);
    let entry = cursor.current()
        .expect("Should have an entry result")
        .expect("and it should be ok");
    assert_entry_with_name(entry, "009");

    assert_eq!(cursor.next_dfs().expect("Should not be done with traversal"), -2);
    let entry = cursor.current()
        .expect("Should have an entry result")
        .expect("and it should be ok");
    assert_entry_with_name(entry, "010");

    assert!(cursor.next_dfs().is_none());
    assert!(cursor.current().is_none());
}

#[test]
#[cfg_attr(rustfmt, rustfmt_skip)]
fn test_cursor_next_sibling_no_sibling_ptr() {
    let info_buf = &ENTRIES_CURSOR_TESTS_DEBUG_INFO_BUF;
    let debug_info = DebugInfo::<LittleEndian>::new(info_buf);

    let unit = debug_info.compilation_units().next()
        .expect("should have a unit result")
        .expect("and it should be ok");

    let abbrevs_buf = &ENTRIES_CURSOR_TESTS_ABBREV_BUF;
    let debug_abbrev = DebugAbbrev::<LittleEndian>::new(abbrevs_buf);

    let abbrevs = unit.abbreviations(debug_abbrev)
        .expect("Should parse abbreviations");

    let mut cursor = unit.entries(&abbrevs);

    let entry = cursor.current()
        .expect("Should have an entry result")
        .expect("and it should be ok");
    assert_entry_with_name(entry, "001");

    // Down to the first child of the root entry.

    assert_eq!(cursor.next_dfs().expect("Should not be done with traversal"), 1);
    let entry = cursor.current()
        .expect("Should have an entry result")
        .expect("and it should be ok");
    assert_entry_with_name(entry, "002");

    // Now iterate all children of the root via `next_sibling`.

    cursor.next_sibling().expect("Should not be done with traversal");
    let entry = cursor.current()
        .expect("Should have an entry result")
        .expect("and it should be ok");
    assert_entry_with_name(entry, "004");

    cursor.next_sibling().expect("Should not be done with traversal");
    let entry = cursor.current()
        .expect("Should have an entry result")
        .expect("and it should be ok");
    assert_entry_with_name(entry, "007");

    cursor.next_sibling().expect("Should not be done with traversal");
    let entry = cursor.current()
        .expect("Should have an entry result")
        .expect("and it should be ok");
    assert_entry_with_name(entry, "010");

    // And now the cursor should be exhausted.

    assert!(cursor.next_sibling().is_none());
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

    let unit = debug_info.compilation_units().next()
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

    let root = cursor.current()
        .expect("Should have an entry result")
        .expect("and it should be ok");
    assert_entry_with_name(root, "001");

    // Down to the first child of the root.

    assert_eq!(cursor.next_dfs().expect("Should not be done with traversal"), 1);
    let entry = cursor.current()
        .expect("Should have an entry result")
        .expect("and it should be ok");
    assert_entry_with_name(entry, "002");

    // Now iterate all children of the root via `next_sibling`.

    cursor.next_sibling().expect("Should handle valid DW_AT_sibling pointer");
    let entry = cursor.current()
        .expect("Should have an entry result")
        .expect("and it should be ok");
    assert_entry_with_name(entry, "004");

    cursor.next_sibling().expect("Should handle invalid DW_AT_sibling pointer");
    let entry = cursor.current()
        .expect("Should have an entry result")
        .expect("and it should be ok");
    assert_entry_with_name(entry, "006");

    // And now the cursor should be exhausted.

    assert!(cursor.next_sibling().is_none());
    assert!(cursor.current().is_none());
}

