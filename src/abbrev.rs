//! Functions for parsing DWARF debugging abbreviations.

#![deny(missing_docs)]

use constants;
use endianity::Endianity;
use parser::{Error, ParseResult, Format};
use parser::{parse_unsigned_leb, parse_u8};
use section::{SectionData, SectionOffset};
use unit::UnitHeader;
use std::collections::hash_map;

/// The type of a `.debug_abbrev` section, used to match offsets with data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebugAbbrevSection {}

/// An offset into the `.debug_abbrev` section.
pub type DebugAbbrevOffset = SectionOffset<DebugAbbrevSection>;

/// The `DebugAbbrev` struct represents the abbreviations describing
/// `DebuggingInformationEntry`s' attribute names and forms found in the
/// `.debug_abbrev` section.
pub type DebugAbbrev<'input, Endian> = SectionData<'input, Endian, DebugAbbrevSection>;

impl<'input, Endian> DebugAbbrev<'input, Endian>
    where Endian: Endianity
{
    /// Parse the abbreviations at the given `offset` within this
    /// `.debug_abbrev` section.
    ///
    /// The `offset` should generally be retrieved from a unit header.
    pub fn abbreviations(&self,
                         debug_abbrev_offset: DebugAbbrevOffset)
                         -> ParseResult<Abbreviations> {
        let input: &[u8] = self.data().into();
        Abbreviations::parse(&input[debug_abbrev_offset.0 as usize..]).map(|(_, abbrevs)| abbrevs)
    }
}

/// A set of type abbreviations.
///
/// Construct an `Abbreviations` instance with the
/// [`abbreviations()`](struct.UnitHeader.html#method.abbreviations)
/// method.
#[derive(Debug, Default, Clone)]
pub struct Abbreviations {
    abbrevs: hash_map::HashMap<u64, Abbreviation>,
}

impl Abbreviations {
    /// Construct a new, empty set of abbreviations.
    fn empty() -> Abbreviations {
        Abbreviations { abbrevs: hash_map::HashMap::new() }
    }

    /// Insert an abbreviation into the set.
    ///
    /// Returns `Ok` if it is the first abbreviation in the set with its code,
    /// `Err` if the code is a duplicate and there already exists an
    /// abbreviation in the set with the given abbreviation's code.
    fn insert(&mut self, abbrev: Abbreviation) -> Result<(), ()> {
        match self.abbrevs.entry(abbrev.code) {
            hash_map::Entry::Occupied(_) => Err(()),
            hash_map::Entry::Vacant(entry) => {
                entry.insert(abbrev);
                Ok(())
            }
        }
    }

    /// Get the abbreviation associated with the given code.
    #[inline]
    pub fn get(&self, code: u64) -> Option<&Abbreviation> {
        self.abbrevs.get(&code)
    }

    /// Parse a series of abbreviations, terminated by a null abbreviation.
    fn parse(mut input: &[u8]) -> ParseResult<(&[u8], Abbreviations)> {
        let mut abbrevs = Abbreviations::empty();

        loop {
            let (rest, abbrev) = try!(Abbreviation::parse(input));
            input = rest;

            match abbrev {
                None => break,
                Some(abbrev) => {
                    if let Err(_) = abbrevs.insert(abbrev) {
                        return Err(Error::DuplicateAbbreviationCode);
                    }
                }
            }
        }

        Ok((input, abbrevs))
    }
}

/// An abbreviation describes the shape of a `DebuggingInformationEntry`'s type:
/// its code, tag type, whether it has children, and its set of attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Abbreviation {
    code: u64,
    tag: constants::DwTag,
    has_children: constants::DwChildren,
    attributes: Vec<AttributeSpecification>,
}

impl Abbreviation {
    /// Construct a new `Abbreviation`.
    ///
    /// ### Panics
    ///
    /// Panics if `code` is `0`.
    pub fn new(code: u64,
               tag: constants::DwTag,
               has_children: constants::DwChildren,
               attributes: Vec<AttributeSpecification>)
               -> Abbreviation {
        assert!(code != 0);
        Abbreviation {
            code: code,
            tag: tag,
            has_children: has_children,
            attributes: attributes,
        }
    }

    /// Get this abbreviation's code.
    #[inline]
    pub fn code(&self) -> u64 {
        self.code
    }

    /// Get this abbreviation's tag.
    #[inline]
    pub fn tag(&self) -> constants::DwTag {
        self.tag
    }

    /// Return true if this abbreviation's type has children, false otherwise.
    #[inline]
    pub fn has_children(&self) -> bool {
        self.has_children == constants::DW_CHILDREN_yes
    }

    /// Get this abbreviation's attributes.
    #[inline]
    pub fn attributes(&self) -> &[AttributeSpecification] {
        &self.attributes[..]
    }

    /// Parse an abbreviation's tag.
    fn parse_tag(input: &[u8]) -> ParseResult<(&[u8], constants::DwTag)> {
        let (rest, val) = try!(parse_unsigned_leb(input));
        if val == 0 {
            Err(Error::AbbreviationTagZero)
        } else {
            Ok((rest, constants::DwTag(val)))
        }
    }

    /// Parse an abbreviation's "does the type have children?" byte.
    fn parse_has_children(input: &[u8]) -> ParseResult<(&[u8], constants::DwChildren)> {
        let (rest, val) = try!(parse_u8(input));
        let val = constants::DwChildren(val);
        if val == constants::DW_CHILDREN_no || val == constants::DW_CHILDREN_yes {
            Ok((rest, val))
        } else {
            Err(Error::BadHasChildren)
        }
    }

    /// Parse a series of attribute specifications, terminated by a null attribute
    /// specification.
    fn parse_attributes(mut input: &[u8]) -> ParseResult<(&[u8], Vec<AttributeSpecification>)> {
        let mut attrs = Vec::new();

        loop {
            let (rest, attr) = try!(AttributeSpecification::parse(input));
            input = rest;

            match attr {
                None => break,
                Some(attr) => attrs.push(attr),
            };
        }

        Ok((input, attrs))
    }

    /// Parse an abbreviation. Return `None` for the null abbreviation, `Some`
    /// for an actual abbreviation.
    fn parse(input: &[u8]) -> ParseResult<(&[u8], Option<Abbreviation>)> {
        let (rest, code) = try!(parse_unsigned_leb(input));
        if code == 0 {
            return Ok((rest, None));
        }

        let (rest, tag) = try!(Self::parse_tag(rest));
        let (rest, has_children) = try!(Self::parse_has_children(rest));
        let (rest, attributes) = try!(Self::parse_attributes(rest));
        let abbrev = Abbreviation::new(code, tag, has_children, attributes);
        Ok((rest, Some(abbrev)))
    }
}

/// The description of an attribute in an abbreviated type. It is a pair of name
/// and form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttributeSpecification {
    name: constants::DwAt,
    form: constants::DwForm,
}

impl AttributeSpecification {
    /// Construct a new `AttributeSpecification` from the given name and form.
    pub fn new(name: constants::DwAt, form: constants::DwForm) -> AttributeSpecification {
        AttributeSpecification {
            name: name,
            form: form,
        }
    }

    /// Get the attribute's name.
    #[inline]
    pub fn name(&self) -> constants::DwAt {
        self.name
    }

    /// Get the attribute's form.
    #[inline]
    pub fn form(&self) -> constants::DwForm {
        self.form
    }

    /// Return the size of the attribute, in bytes.
    ///
    /// Note that because some attributes are variably sized, the size cannot
    /// always be known without parsing, in which case we return `None`.
    pub fn size<Endian>(&self, header: &UnitHeader<Endian>) -> Option<usize>
        where Endian: Endianity
    {
        match self.form {
            constants::DW_FORM_addr => Some(header.address_size() as usize),

            constants::DW_FORM_flag |
            constants::DW_FORM_flag_present |
            constants::DW_FORM_data1 |
            constants::DW_FORM_ref1 => Some(1),

            constants::DW_FORM_data2 |
            constants::DW_FORM_ref2 => Some(2),

            constants::DW_FORM_data4 |
            constants::DW_FORM_ref4 => Some(4),

            constants::DW_FORM_data8 |
            constants::DW_FORM_ref8 => Some(8),

            constants::DW_FORM_sec_offset |
            constants::DW_FORM_ref_addr |
            constants::DW_FORM_ref_sig8 |
            constants::DW_FORM_strp => {
                match header.format() {
                    Format::Dwarf32 => Some(4),
                    Format::Dwarf64 => Some(8),
                }
            }

            constants::DW_FORM_block |
            constants::DW_FORM_block1 |
            constants::DW_FORM_block2 |
            constants::DW_FORM_block4 |
            constants::DW_FORM_exprloc |
            constants::DW_FORM_ref_udata |
            constants::DW_FORM_string |
            constants::DW_FORM_sdata |
            constants::DW_FORM_udata |
            constants::DW_FORM_indirect => None,

            // We don't know the size of unknown forms.
            _ => None,
        }
    }

    /// Parse an attribute's form.
    fn parse_form(input: &[u8]) -> ParseResult<(&[u8], constants::DwForm)> {
        let (rest, val) = try!(parse_unsigned_leb(input));
        if val == 0 {
            Err(Error::AttributeFormZero)
        } else {
            Ok((rest, constants::DwForm(val)))
        }
    }

    /// Parse an attribute specification. Returns `None` for the null attribute
    /// specification, `Some` for an actual attribute specification.
    fn parse(input: &[u8]) -> ParseResult<(&[u8], Option<AttributeSpecification>)> {
        let (rest, name) = try!(parse_unsigned_leb(input));
        if name == 0 {
            // Parse the null attribute specification.
            let (rest, form) = try!(parse_unsigned_leb(rest));
            return if form == 0 {
                Ok((rest, None))
            } else {
                Err(Error::ExpectedZero)
            };
        }

        let name = constants::DwAt(name);
        let (rest, form) = try!(Self::parse_form(rest));
        let spec = AttributeSpecification::new(name, form);
        Ok((rest, Some(spec)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use constants;
    use parser::Error;
    use endianity::LittleEndian;

    #[test]
    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn test_debug_abbrev_ok() {
        let buf = [
            // Extra
            0x01,
            0x02,
            0x03,
            0x04,

            // Code
            0x02,
            // DW_TAG_subprogram
            0x2e,
            // DW_CHILDREN_no
            0x00,
            // Begin attributes
                // Attribute name = DW_AT_name
                0x03,
                // Attribute form = DW_FORM_string
                0x08,
            // End attributes
            0x00,
            0x00,

            // Code
            0x01,
            // DW_TAG_compile_unit
            0x11,
            // DW_CHILDREN_yes
            0x01,
            // Begin attributes
                // Attribute name = DW_AT_producer
                0x25,
                // Attribute form = DW_FORM_strp
                0x0e,
                // Attribute name = DW_AT_language
                0x13,
                // Attribute form = DW_FORM_data2
                0x05,
            // End attributes
            0x00,
            0x00,

            // Null terminator
            0x00,

            // Extra
            0x05,
            0x06,
            0x07,
            0x08
        ];

        let abbrev1 = Abbreviation::new(
            1, constants::DW_TAG_compile_unit, constants::DW_CHILDREN_yes,
            vec![
                AttributeSpecification::new(constants::DW_AT_producer, constants::DW_FORM_strp),
                AttributeSpecification::new(constants::DW_AT_language, constants::DW_FORM_data2),
            ]);

        let abbrev2 = Abbreviation::new(
            2, constants::DW_TAG_subprogram, constants::DW_CHILDREN_no,
            vec![
                AttributeSpecification::new(constants::DW_AT_name, constants::DW_FORM_string),
            ]);

        let debug_abbrev = DebugAbbrev::<LittleEndian>::new(&buf);
        let debug_abbrev_offset = DebugAbbrevOffset::new(4);
        let abbrevs = debug_abbrev.abbreviations(debug_abbrev_offset)
            .expect("Should parse abbreviations");
        assert_eq!(abbrevs.get(1), Some(&abbrev1));
        assert_eq!(abbrevs.get(2), Some(&abbrev2));
    }

    #[test]
    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn test_parse_abbreviations_ok() {
        let buf = [
            // Code
            0x02,
            // DW_TAG_subprogram
            0x2e,
            // DW_CHILDREN_no
            0x00,
            // Begin attributes
                // Attribute name = DW_AT_name
                0x03,
                // Attribute form = DW_FORM_string
                0x08,
            // End attributes
            0x00,
            0x00,

            // Code
            0x01,
            // DW_TAG_compile_unit
            0x11,
            // DW_CHILDREN_yes
            0x01,
            // Begin attributes
                // Attribute name = DW_AT_producer
                0x25,
                // Attribute form = DW_FORM_strp
                0x0e,
                // Attribute name = DW_AT_language
                0x13,
                // Attribute form = DW_FORM_data2
                0x05,
            // End attributes
            0x00,
            0x00,

            // Null terminator
            0x00,

            // Extra
            0x01,
            0x02,
            0x03,
            0x04
        ];

        let abbrev1 = Abbreviation::new(
            1, constants::DW_TAG_compile_unit, constants::DW_CHILDREN_yes,
            vec![
                AttributeSpecification::new(constants::DW_AT_producer, constants::DW_FORM_strp),
                AttributeSpecification::new(constants::DW_AT_language, constants::DW_FORM_data2),
            ]);

        let abbrev2 = Abbreviation::new(
            2, constants::DW_TAG_subprogram, constants::DW_CHILDREN_no,
            vec![
                AttributeSpecification::new(constants::DW_AT_name, constants::DW_FORM_string),
            ]);

        let (rest, abbrevs) = Abbreviations::parse(&buf).expect("Should parse abbreviations");
        assert_eq!(abbrevs.get(1), Some(&abbrev1));
        assert_eq!(abbrevs.get(2), Some(&abbrev2));
        assert_eq!(rest, [0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn test_parse_abbreviations_duplicate() {
        let buf = [
            // Code
            0x01,
            // DW_TAG_subprogram
            0x2e,
            // DW_CHILDREN_no
            0x00,
            // Begin attributes
                // Attribute name = DW_AT_name
                0x03,
                // Attribute form = DW_FORM_string
                0x08,
            // End attributes
            0x00,
            0x00,

            // Code
            0x01,
            // DW_TAG_compile_unit
            0x11,
            // DW_CHILDREN_yes
            0x01,
            // Begin attributes
                // Attribute name = DW_AT_producer
                0x25,
                // Attribute form = DW_FORM_strp
                0x0e,
                // Attribute name = DW_AT_language
                0x13,
                // Attribute form = DW_FORM_data2
                0x05,
            // End attributes
            0x00,
            0x00,

            // Null terminator
            0x00,

            // Extra
            0x01,
            0x02,
            0x03,
            0x04
        ];

        match Abbreviations::parse(&buf) {
            Err(Error::DuplicateAbbreviationCode) => {}
            otherwise => panic!("Unexpected result: {:?}", otherwise),
        };
    }

    #[test]
    fn test_parse_abbreviation_tag_ok() {
        let buf = [0x01, 0x02];
        let (rest, tag) = Abbreviation::parse_tag(&buf).expect("Should parse tag");
        assert_eq!(tag, constants::DW_TAG_array_type);
        assert_eq!(rest, &buf[1..]);
    }

    #[test]
    fn test_parse_abbreviation_tag_zero() {
        let buf = [0x00];
        match Abbreviation::parse_tag(&buf) {
            Err(Error::AbbreviationTagZero) => {}
            otherwise => panic!("Unexpected result: {:?}", otherwise),
        };
    }

    #[test]
    fn test_parse_abbreviation_has_children() {
        let buf = [0x00, 0x01, 0x02];
        let (rest, val) = Abbreviation::parse_has_children(&buf).expect("Should parse children");
        assert_eq!(val, constants::DW_CHILDREN_no);
        let (rest, val) = Abbreviation::parse_has_children(rest).expect("Should parse children");
        assert_eq!(val, constants::DW_CHILDREN_yes);
        match Abbreviation::parse_has_children(rest) {
            Err(Error::BadHasChildren) => {}
            otherwise => panic!("Unexpected result: {:?}", otherwise),
        };
    }

    #[test]
    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn test_parse_abbreviation_ok() {
        let buf = [
            // Code
            0x01,
            // DW_TAG_subprogram
            0x2e,
            // DW_CHILDREN_no
            0x00,
            // Begin attributes
                // Attribute name = DW_AT_name
                0x03,
                // Attribute form = DW_FORM_string
                0x08,
            // End attributes
            0x00,
            0x00,

            // Extra
            0x01,
            0x02,
            0x03,
            0x04
        ];

        let expect = Some(
            Abbreviation::new(
                1,
                constants::DW_TAG_subprogram,
                constants::DW_CHILDREN_no,
                vec![
                    AttributeSpecification::new(constants::DW_AT_name,
                                                constants::DW_FORM_string),
                ]
            )
        );

        let (rest, abbrev) = Abbreviation::parse(&buf).expect("Should parse abbreviation");
        assert_eq!(abbrev, expect);
        assert_eq!(rest, [0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn test_parse_null_abbreviation_ok() {
        let buf = [
            // Code
            0x00,

            // Extra
            0x01,
            0x02,
            0x03,
            0x04
        ];

        let (rest, abbrev) = Abbreviation::parse(&buf).expect("Should parse null abbreviation");
        assert!(abbrev.is_none());
        assert_eq!(rest, [0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_parse_attribute_form_ok() {
        let buf = [0x01, 0x02];
        let (rest, tag) = AttributeSpecification::parse_form(&buf).expect("Should parse form");
        assert_eq!(tag, constants::DW_FORM_addr);
        assert_eq!(rest, &buf[1..]);
    }

    #[test]
    fn test_parse_attribute_form_zero() {
        let buf = [0x00];
        match AttributeSpecification::parse_form(&buf) {
            Err(Error::AttributeFormZero) => {}
            otherwise => panic!("Unexpected result: {:?}", otherwise),
        };
    }

    #[test]
    fn test_parse_null_attribute_specification_ok() {
        let buf = [0x00, 0x00, 0x01];
        let (rest, attr) = AttributeSpecification::parse(&buf)
            .expect("Should parse null attribute specification");
        assert!(attr.is_none());
        assert_eq!(rest, [0x01]);
    }

    #[test]
    fn test_parse_attribute_specifications_name_zero() {
        let buf = [0x00, 0x01, 0x00, 0x00];
        match AttributeSpecification::parse(&buf) {
            Err(Error::ExpectedZero) => {}
            otherwise => panic!("Unexpected result: {:?}", otherwise),
        };
    }

    #[test]
    fn test_parse_attribute_specifications_form_zero() {
        let buf = [0x01, 0x00, 0x00, 0x00];
        match AttributeSpecification::parse(&buf) {
            Err(Error::AttributeFormZero) => {}
            otherwise => panic!("Unexpected result: {:?}", otherwise),
        };
    }
}
