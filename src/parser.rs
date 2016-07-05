//! Functions for parsing DWARF debugging information.

use leb128;
pub use nom::IResult as ParseResult;
use nom::{self, Err, ErrorKind, le_u8, le_u16, le_u32, le_u64, length_value, Needed};
use std::cell::Cell;
use std::fmt;
use std::collections::hash_map;

/// An offset into the `.debug_types` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugTypesOffset(pub u64);

/// An offset into the `.debug_str` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugStrOffset(pub u64);

/// An offset into the `.debug_abbrev` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugAbbrevOffset(pub u64);

/// An offset into the `.debug_info` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugInfoOffset(pub u64);

/// An offset into the `.debug_line` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugLineOffset(pub u64);

/// An offset into the `.debug_loc` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugLocOffset(pub u64);

/// An offset into the `.debug_macinfo` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugMacinfoOffset(pub u64);

/// An offset into the current compilation or type unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnitOffset(pub u64);

/// The `DebugInfo` struct represents the DWARF debugging information found in
/// the `.debug_info` section.
pub struct DebugInfo<'a> {
    debug_info_section: &'a [u8],
}

impl<'a> DebugInfo<'a> {
    /// Construct a new `DebugInfo` instance from the data in the `.debug_info`
    /// section.
    ///
    /// It is the caller's responsibility to read the `.debug_info` section and
    /// present it as a `&[u8]` slice. That means using some ELF loader on
    /// Linux, a Mach-O loader on OSX, etc.
    ///
    /// ```
    /// use gimli::DebugInfo;
    ///
    /// # let buf = [0x00, 0x01, 0x02, 0x03];
    /// # let read_debug_info_section_somehow = || &buf;
    /// let debug_info = DebugInfo::new(read_debug_info_section_somehow());
    /// ```
    pub fn new(debug_info_section: &'a [u8]) -> DebugInfo<'a> {
        DebugInfo { debug_info_section: debug_info_section }
    }

    /// Iterate the compilation units in this `.debug_info` section.
    ///
    /// ```
    /// use gimli::{DebugInfo, ParseResult};
    ///
    /// # let buf = [];
    /// # let read_debug_info_section_somehow = || &buf;
    /// let debug_info = DebugInfo::new(read_debug_info_section_somehow());
    ///
    /// for parse_result in debug_info.compilation_units() {
    ///     match parse_result {
    ///         ParseResult::Done(_, unit) =>
    ///             println!("unit's length is {}", unit.unit_length()),
    ///         _ =>
    ///             panic!(),
    ///     }
    /// }
    /// ```
    pub fn compilation_units(&self) -> CompilationUnitsIter {
        CompilationUnitsIter { input: self.debug_info_section }
    }
}

/// An iterator over the compilation units of a `.debug_info` section.
///
/// See the [documentation on
/// `DebugInfo::compilation_units`](./struct.DebugInfo.html#method.compilation_units)
/// for more detail.
pub struct CompilationUnitsIter<'a> {
    input: &'a [u8],
}

impl<'a> Iterator for CompilationUnitsIter<'a> {
    type Item = ParseResult<&'a [u8], CompilationUnit<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.input.is_empty() {
            None
        } else {
            match parse_compilation_unit_header(self.input) {
                ParseResult::Done(rest, header) => {
                    let unit_len = header.length_including_self() as usize;
                    if self.input.len() < unit_len {
                        self.input = &self.input[..0];
                    } else {
                        self.input = &self.input[unit_len..];
                    }
                    Some(ParseResult::Done(rest, header))
                }
                otherwise => {
                    self.input = &self.input[..0];
                    Some(otherwise)
                }
            }
        }
    }
}

#[test]
#[cfg_attr(rustfmt, rustfmt_skip)]
fn test_compilation_units() {
    let buf = [
        // First compilation unit.

        // Enable 64-bit DWARF.
        0xff, 0xff, 0xff, 0xff,
        // Unit length = 43
        0x2b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // Version 4
        0x04, 0x00,
        // debug_abbrev_offset
        0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
        // address size
        0x08,

        // Placeholder data for first compilation unit's DIEs.
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,

        // Second compilation unit

        // 32-bit unit length = 39
        0x27, 0x00, 0x00, 0x00,
        // Version 4
        0x04, 0x00,
        // debug_abbrev_offset
        0x05, 0x06, 0x07, 0x08,
        // Address size
        0x04,

        // Placeholder data for second compilation unit's DIEs.
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
    ];

    let debug_info = DebugInfo::new(&buf);
    let mut units = debug_info.compilation_units();

    match units.next() {
        Some(ParseResult::Done(_, header)) => {
            let expected = CompilationUnit::new(0x000000000000002b,
                                                4,
                                                DebugAbbrevOffset(0x0102030405060708),
                                                8,
                                                Format::Dwarf64,
                                                &buf[23..23+32]);
            assert_eq!(header, expected);

        }
        _ => assert!(false),
    }

    match units.next() {
        Some(ParseResult::Done(_, header)) => {
            let expected =
                CompilationUnit::new(0x00000027,
                                     4,
                                     DebugAbbrevOffset(0x08070605),
                                     4,
                                     Format::Dwarf32,
                                     &buf[buf.len()-32..]);
            assert_eq!(header, expected);
        }
        _ => assert!(false),
    }

    assert!(units.next().is_none());
}

/// A parse error.
#[derive(Debug)]
pub enum Error {
    /// A malformed LEB128 value.
    Leb(leb128::read::Error),

    /// An error from a primitive parser.
    Primitive(u32),

    /// Zero is an illegal value for an abbreviation code.
    AbbreviationCodeZero,

    /// The abbreviation's tag is not a known variant of `AbbreviationTag` (aka
    /// `DW_TAG_*`).
    InvalidAbbreviationTag,

    /// The abbreviation's "does the abbreviated type have children?" byte was
    /// not one of `DW_CHILDREN_yes` or `DW_CHILDREN_no`.
    InvalidAbbreviationHasChildren,

    /// The abbreviation's attribute name is not a valid variant of
    /// `AttributeName` (aka `DW_AT_*`).
    InvalidAttributeName,

    /// The abbreviation's attribute form is not a valid variant of
    /// `AttributeForm` (aka `DW_FORM_*`).
    InvalidAttributeForm,

    /// Expected a zero byte, but did not find one.
    ExpectedZero,

    /// An abbreviation attempted to declare a code that is already in use by an
    /// earlier abbreviation definition.
    DuplicateAbbreviationCode,

    /// Found a compilation unit length within the range of reserved values, but
    /// whose specific value we do not know what to do with.
    UnknownReservedCompilationUnitLength,

    /// The reported DWARF version is a version we do not know how to parse.
    UnknownDwarfVersion,

    /// The compilation unit's specified length is invalid (for example, it is
    /// shorter than the length of the compilation unit header's attributes).
    InvalidUnitLength,

    /// We found a reference to an unknown abbreviation code.
    UnknownAbbreviationCode,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "gimli::parser::Error")
    }
}

impl ::std::error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::Leb(_) => "Error parsing LEB128 value",
            Error::Primitive(_) => "Error parsing primitive value",
            Error::AbbreviationCodeZero => {
                "Abbreviation declared its code to be the reserved code 0"
            }
            Error::InvalidAbbreviationTag => "The abbreviation tag is invalid",
            Error::InvalidAbbreviationHasChildren => {
                "The \"does-the-abbreviated-type-have-children?\" byte is not DW_CHILDREN_yes or \
                 DW_CHILDREN_no"
            }
            Error::InvalidAttributeName => "The abbreviation's attribute name is invalid",
            Error::InvalidAttributeForm => "The abbreviation's attribute form is invalid",
            Error::ExpectedZero => "Expected zero",
            Error::DuplicateAbbreviationCode => {
                "Found an abbreviation with a code that has already been used"
            }
            Error::UnknownReservedCompilationUnitLength => {
                "Unknown reserved compilation unit length value found"
            }
            Error::UnknownDwarfVersion => {
                "The DWARF version is a version that we do not know how to parse"
            }
            Error::InvalidUnitLength => "Invalid unit length",
            Error::UnknownAbbreviationCode => "Found a reference to an unknown abbreviation code",
        }
    }

    fn cause(&self) -> Option<&::std::error::Error> {
        match *self {
            Error::Leb(ref e) => Some(e),
            Error::Primitive(_) |
            Error::AbbreviationCodeZero |
            Error::InvalidAbbreviationTag |
            Error::InvalidAbbreviationHasChildren |
            Error::InvalidAttributeName |
            Error::InvalidAttributeForm |
            Error::ExpectedZero |
            Error::DuplicateAbbreviationCode |
            Error::UnknownReservedCompilationUnitLength |
            Error::UnknownDwarfVersion |
            Error::InvalidUnitLength |
            Error::UnknownAbbreviationCode => None,
        }
    }
}

impl From<u32> for Error {
    fn from(e: u32) -> Self {
        Error::Primitive(e)
    }
}

macro_rules! try_parse_result (
    ($input:expr, $result:expr) => (
        match $result {
            ParseResult::Done(rest, out) => (rest, out),
            ParseResult::Error(e) => return ParseResult::Error(raise_err($input, e)),
            ParseResult::Incomplete(i) => return ParseResult::Incomplete(i)
        }
    );
);

/// Parse an unsigned LEB128 encoded integer.
fn parse_unsigned_leb(mut input: &[u8]) -> ParseResult<&[u8], u64, Error> {
    match leb128::read::unsigned(&mut input) {
        Ok(val) => ParseResult::Done(input, val),
        Err(leb128::read::Error::UnexpectedEndOfData) => ParseResult::Incomplete(Needed::Unknown),
        Err(e) => ParseResult::Error(Err::Position(ErrorKind::Custom(Error::Leb(e)), input)),
    }
}

/// Parse a signed LEB128 encoded integer.
fn parse_signed_leb(mut input: &[u8]) -> ParseResult<&[u8], i64, Error> {
    match leb128::read::signed(&mut input) {
        Ok(val) => ParseResult::Done(input, val),
        Err(leb128::read::Error::UnexpectedEndOfData) => ParseResult::Incomplete(Needed::Unknown),
        Err(e) => ParseResult::Error(Err::Position(ErrorKind::Custom(Error::Leb(e)), input)),
    }
}

/// Parse an abbreviation's code.
fn parse_abbreviation_code(input: &[u8]) -> ParseResult<&[u8], u64, Error> {
    match parse_unsigned_leb(input) {
        ParseResult::Done(input, val) => {
            if val == 0 {
                ParseResult::Error(Err::Position(ErrorKind::Custom(Error::AbbreviationCodeZero),
                                                 input))
            } else {
                ParseResult::Done(input, val)
            }
        }
        res => res,
    }
}

/// Abbreviation tag types, aka `DW_TAG_whatever` in the standard.
///
/// DWARF standard 4, section 7.5.4, page 154
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum AbbreviationTag {
    ArrayType = 0x01,
    ClassType = 0x02,
    EntryPoint = 0x03,
    EnumerationType = 0x04,
    FormalParameter = 0x05,
    ImportedDeclaration = 0x08,
    Label = 0x0a,
    LexicalBlock = 0x0b,
    Member = 0x0d,
    PointerType = 0x0f,
    ReferenceType = 0x10,
    CompileUnit = 0x11,
    StringType = 0x12,
    StructureType = 0x13,
    SubroutineType = 0x15,
    Typedef = 0x16,
    UnionType = 0x17,
    UnspecifiedParameters = 0x18,
    Variant = 0x19,
    CommonBlock = 0x1a,
    CommonInclusion = 0x1b,
    Inheritance = 0x1c,
    InlinedSubroutine = 0x1d,
    Module = 0x1e,
    PtrToMemberType = 0x1f,
    SetType = 0x20,
    SubrangeType = 0x21,
    WithStmt = 0x22,
    AccessDeclaration = 0x23,
    BaseType = 0x24,
    CatchBlock = 0x25,
    ConstType = 0x26,
    Constant = 0x27,
    Enumerator = 0x28,
    FileType = 0x29,
    Friend = 0x2a,
    Namelist = 0x2b,
    NamelistItem = 0x2c,
    PackedType = 0x2d,
    Subprogram = 0x2e,
    TemplateTypeParameter = 0x2f,
    TemplateValueParameter = 0x30,
    ThrownType = 0x31,
    TryBlock = 0x32,
    VariantPart = 0x33,
    Variable = 0x34,
    VolatileType = 0x35,
    DwarfProcedure = 0x36,
    RestrictType = 0x37,
    InterfaceType = 0x38,
    Namespace = 0x39,
    ImportedModule = 0x3a,
    UnspecifiedType = 0x3b,
    PartialUnit = 0x3c,
    ImportedUnit = 0x3d,
    Condition = 0x3f,
    SharedType = 0x40,
    TypeUnit = 0x41,
    RvalueReferenceType = 0x42,
    TemplateAlias = 0x43,
    LoUser = 0x4080,
    HiUser = 0xffff,
}

/// Parse an abbreviation's tag.
#[allow(cyclomatic_complexity)]
fn parse_abbreviation_tag(input: &[u8]) -> ParseResult<&[u8], AbbreviationTag, Error> {
    match parse_unsigned_leb(input) {
        ParseResult::Done(input, val) if AbbreviationTag::ArrayType as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::ArrayType)
        }

        ParseResult::Done(input, val) if AbbreviationTag::ClassType as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::ClassType)
        }

        ParseResult::Done(input, val) if AbbreviationTag::EntryPoint as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::EntryPoint)
        }

        ParseResult::Done(input, val) if AbbreviationTag::EnumerationType as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::EnumerationType)
        }

        ParseResult::Done(input, val) if AbbreviationTag::FormalParameter as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::FormalParameter)
        }

        ParseResult::Done(input, val) if AbbreviationTag::ImportedDeclaration as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::ImportedDeclaration)
        }

        ParseResult::Done(input, val) if AbbreviationTag::Label as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::Label)
        }

        ParseResult::Done(input, val) if AbbreviationTag::LexicalBlock as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::LexicalBlock)
        }

        ParseResult::Done(input, val) if AbbreviationTag::Member as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::Member)
        }

        ParseResult::Done(input, val) if AbbreviationTag::PointerType as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::PointerType)
        }

        ParseResult::Done(input, val) if AbbreviationTag::ReferenceType as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::ReferenceType)
        }

        ParseResult::Done(input, val) if AbbreviationTag::CompileUnit as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::CompileUnit)
        }

        ParseResult::Done(input, val) if AbbreviationTag::StringType as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::StringType)
        }

        ParseResult::Done(input, val) if AbbreviationTag::StructureType as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::StructureType)
        }

        ParseResult::Done(input, val) if AbbreviationTag::SubroutineType as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::SubroutineType)
        }

        ParseResult::Done(input, val) if AbbreviationTag::Typedef as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::Typedef)
        }

        ParseResult::Done(input, val) if AbbreviationTag::UnionType as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::UnionType)
        }

        ParseResult::Done(input, val) if AbbreviationTag::UnspecifiedParameters as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::UnspecifiedParameters)
        }

        ParseResult::Done(input, val) if AbbreviationTag::Variant as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::Variant)
        }

        ParseResult::Done(input, val) if AbbreviationTag::CommonBlock as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::CommonBlock)
        }

        ParseResult::Done(input, val) if AbbreviationTag::CommonInclusion as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::CommonInclusion)
        }

        ParseResult::Done(input, val) if AbbreviationTag::Inheritance as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::Inheritance)
        }

        ParseResult::Done(input, val) if AbbreviationTag::InlinedSubroutine as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::InlinedSubroutine)
        }

        ParseResult::Done(input, val) if AbbreviationTag::Module as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::Module)
        }

        ParseResult::Done(input, val) if AbbreviationTag::PtrToMemberType as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::PtrToMemberType)
        }

        ParseResult::Done(input, val) if AbbreviationTag::SetType as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::SetType)
        }

        ParseResult::Done(input, val) if AbbreviationTag::SubrangeType as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::SubrangeType)
        }

        ParseResult::Done(input, val) if AbbreviationTag::WithStmt as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::WithStmt)
        }

        ParseResult::Done(input, val) if AbbreviationTag::AccessDeclaration as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::AccessDeclaration)
        }

        ParseResult::Done(input, val) if AbbreviationTag::BaseType as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::BaseType)
        }

        ParseResult::Done(input, val) if AbbreviationTag::CatchBlock as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::CatchBlock)
        }

        ParseResult::Done(input, val) if AbbreviationTag::ConstType as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::ConstType)
        }

        ParseResult::Done(input, val) if AbbreviationTag::Constant as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::Constant)
        }

        ParseResult::Done(input, val) if AbbreviationTag::Enumerator as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::Enumerator)
        }

        ParseResult::Done(input, val) if AbbreviationTag::FileType as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::FileType)
        }

        ParseResult::Done(input, val) if AbbreviationTag::Friend as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::Friend)
        }

        ParseResult::Done(input, val) if AbbreviationTag::Namelist as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::Namelist)
        }

        ParseResult::Done(input, val) if AbbreviationTag::NamelistItem as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::NamelistItem)
        }

        ParseResult::Done(input, val) if AbbreviationTag::PackedType as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::PackedType)
        }

        ParseResult::Done(input, val) if AbbreviationTag::Subprogram as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::Subprogram)
        }

        ParseResult::Done(input, val) if AbbreviationTag::TemplateTypeParameter as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::TemplateTypeParameter)
        }

        ParseResult::Done(input, val) if AbbreviationTag::TemplateValueParameter as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::TemplateValueParameter)
        }

        ParseResult::Done(input, val) if AbbreviationTag::ThrownType as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::ThrownType)
        }

        ParseResult::Done(input, val) if AbbreviationTag::TryBlock as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::TryBlock)
        }

        ParseResult::Done(input, val) if AbbreviationTag::VariantPart as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::VariantPart)
        }

        ParseResult::Done(input, val) if AbbreviationTag::Variable as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::Variable)
        }

        ParseResult::Done(input, val) if AbbreviationTag::VolatileType as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::VolatileType)
        }

        ParseResult::Done(input, val) if AbbreviationTag::RestrictType as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::RestrictType)
        }

        ParseResult::Done(input, val) if AbbreviationTag::InterfaceType as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::InterfaceType)
        }

        ParseResult::Done(input, val) if AbbreviationTag::Namespace as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::Namespace)
        }

        ParseResult::Done(input, val) if AbbreviationTag::ImportedModule as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::ImportedModule)
        }

        ParseResult::Done(input, val) if AbbreviationTag::UnspecifiedType as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::UnspecifiedType)
        }

        ParseResult::Done(input, val) if AbbreviationTag::PartialUnit as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::PartialUnit)
        }

        ParseResult::Done(input, val) if AbbreviationTag::ImportedUnit as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::ImportedUnit)
        }

        ParseResult::Done(input, val) if AbbreviationTag::Condition as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::Condition)
        }

        ParseResult::Done(input, val) if AbbreviationTag::SharedType as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::SharedType)
        }

        ParseResult::Done(input, val) if AbbreviationTag::TypeUnit as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::TypeUnit)
        }

        ParseResult::Done(input, val) if AbbreviationTag::RvalueReferenceType as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::RvalueReferenceType)
        }

        ParseResult::Done(input, val) if AbbreviationTag::TemplateAlias as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::TemplateAlias)
        }

        ParseResult::Done(input, val) if AbbreviationTag::LoUser as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::LoUser)
        }

        ParseResult::Done(input, val) if AbbreviationTag::HiUser as u64 == val => {
            ParseResult::Done(input, AbbreviationTag::HiUser)
        }

        ParseResult::Done(input, _) => {
            ParseResult::Error(Err::Position(ErrorKind::Custom(Error::InvalidAbbreviationTag),
                                             input))
        }

        ParseResult::Incomplete(needed) => ParseResult::Incomplete(needed),

        ParseResult::Error(error) => ParseResult::Error(error),
    }
}

/// Whether an abbreviation's type has children or not, aka
/// `DW_CHILDREN_{yes,no}` in the standard.
///
/// DWARF standard 4, section 7.5.4, page 154
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbbreviationHasChildren {
    /// The type has children.
    Yes = 0x0,

    /// The type does not have children.
    No = 0x1,
}

/// Parse an abbreviation's "does the type have children?" byte.
fn parse_abbreviation_has_children(input: &[u8])
                                   -> ParseResult<&[u8], AbbreviationHasChildren, Error> {
    match le_u8(input) {
        ParseResult::Done(input, val) if AbbreviationHasChildren::Yes as u8 == val => {
            ParseResult::Done(input, AbbreviationHasChildren::Yes)
        }

        ParseResult::Done(input, val) if AbbreviationHasChildren::No as u8 == val => {
            ParseResult::Done(input, AbbreviationHasChildren::No)
        }

        ParseResult::Done(input, _) =>
            ParseResult::Error(
                Err::Position(ErrorKind::Custom(Error::InvalidAbbreviationHasChildren), input)),

        ParseResult::Incomplete(needed) => ParseResult::Incomplete(needed),

        ParseResult::Error(_) => {
            ParseResult::Error(Err::Code(ErrorKind::Custom(Error::InvalidAbbreviationHasChildren)))
        }
    }
}

/// The set of possible attribute names, aka `DW_AT_whatever` in the standard.
///
/// DWARF standard 4, section 7.5.4, page 155
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum AttributeName {
    Sibling = 0x1,
    Location = 0x2,
    Name = 0x3,
    Ordering = 0x9,
    ByteSize = 0xb,
    BitOffset = 0xc,
    BitSize = 0x0d,
    StmtList = 0x10,
    LowPc = 0x11,
    HighPc = 0x12,
    Language = 0x13,
    Discr = 0x15,
    DiscrValue = 0x16,
    Visibility = 0x17,
    Import = 0x18,
    StringLength = 0x19,
    CommonReference = 0x1a,
    CompDir = 0x1b,
    ConstValue = 0x1c,
    ContainingType = 0x1d,
    DefaultValue = 0x1e,
    Inline = 0x20,
    IsOptional = 0x21,
    LowerBound = 0x22,
    Producer = 0x25,
    Prototyped = 0x27,
    ReturnAddr = 0x2a,
    StartScope = 0x2c,
    BitStride = 0x2e,
    UpperBound = 0x2f,
    AbstractOrigin = 0x31,
    Accessibility = 0x32,
    AddressClass = 0x33,
    Artificial = 0x34,
    BaseTypes = 0x35,
    CallingConvention = 0x36,
    Count = 0x37,
    DataMemberLocation = 0x38,
    DeclColumn = 0x39,
    DeclFile = 0x3a,
    DeclLine = 0x3b,
    Declaration = 0x3c,
    DiscrList = 0x3d,
    Encoding = 0x3e,
    External = 0x3f,
    FrameBase = 0x40,
    Friend = 0x41,
    IdentifierCase = 0x42,
    MacroInfo = 0x43,
    NamelistItem = 0x44,
    Priority = 0x45,
    Segment = 0x46,
    Specification = 0x47,
    StaticLink = 0x48,
    Type = 0x49,
    UseLocation = 0x4a,
    VariableParameter = 0x4b,
    Virtuality = 0x4c,
    VtableElemLocation = 0x4d,
    Allocated = 0x4e,
    Associated = 0x4f,
    DataLocation = 0x50,
    ByteStride = 0x51,
    EntryPc = 0x52,
    UseUtf8 = 0x53,
    Extension = 0x54,
    Ranges = 0x55,
    Trampoline = 0x56,
    CallColumn = 0x57,
    CallFile = 0x58,
    CallLine = 0x59,
    Description = 0x5a,
    BinaryScale = 0x5b,
    DecimalScale = 0x5c,
    Small = 0x5d,
    DecimalSign = 0x5e,
    DigitCount = 0x5f,
    PictureString = 0x60,
    Mutable = 0x61,
    ThreadsScaled = 0x62,
    Explicit = 0x63,
    ObjectPointer = 0x64,
    Endianity = 0x65,
    Elemental = 0x66,
    Pure = 0x67,
    Recursive = 0x68,
    Signature = 0x69,
    MainSubprogram = 0x6a,
    DataBitOffset = 0x6b,
    ConstExpr = 0x6c,
    EnumClass = 0x6d,
    LinkageName = 0x6e,
    LoUser = 0x2000,
    HiUser = 0x3fff,
}

/// Parse an attribute's name.
#[allow(cyclomatic_complexity)]
fn parse_attribute_name(input: &[u8]) -> ParseResult<&[u8], AttributeName, Error> {
    match parse_unsigned_leb(input) {
        ParseResult::Done(input, val) if AttributeName::Sibling as u64 == val => {
            ParseResult::Done(input, AttributeName::Sibling)
        }

        ParseResult::Done(input, val) if AttributeName::Location as u64 == val => {
            ParseResult::Done(input, AttributeName::Location)
        }

        ParseResult::Done(input, val) if AttributeName::Name as u64 == val => {
            ParseResult::Done(input, AttributeName::Name)
        }

        ParseResult::Done(input, val) if AttributeName::Ordering as u64 == val => {
            ParseResult::Done(input, AttributeName::Ordering)
        }

        ParseResult::Done(input, val) if AttributeName::ByteSize as u64 == val => {
            ParseResult::Done(input, AttributeName::ByteSize)
        }

        ParseResult::Done(input, val) if AttributeName::BitOffset as u64 == val => {
            ParseResult::Done(input, AttributeName::BitOffset)
        }

        ParseResult::Done(input, val) if AttributeName::BitSize as u64 == val => {
            ParseResult::Done(input, AttributeName::BitSize)
        }

        ParseResult::Done(input, val) if AttributeName::StmtList as u64 == val => {
            ParseResult::Done(input, AttributeName::StmtList)
        }

        ParseResult::Done(input, val) if AttributeName::LowPc as u64 == val => {
            ParseResult::Done(input, AttributeName::LowPc)
        }

        ParseResult::Done(input, val) if AttributeName::HighPc as u64 == val => {
            ParseResult::Done(input, AttributeName::HighPc)
        }

        ParseResult::Done(input, val) if AttributeName::Language as u64 == val => {
            ParseResult::Done(input, AttributeName::Language)
        }

        ParseResult::Done(input, val) if AttributeName::Discr as u64 == val => {
            ParseResult::Done(input, AttributeName::Discr)
        }

        ParseResult::Done(input, val) if AttributeName::DiscrValue as u64 == val => {
            ParseResult::Done(input, AttributeName::DiscrValue)
        }

        ParseResult::Done(input, val) if AttributeName::Visibility as u64 == val => {
            ParseResult::Done(input, AttributeName::Visibility)
        }

        ParseResult::Done(input, val) if AttributeName::Import as u64 == val => {
            ParseResult::Done(input, AttributeName::Import)
        }

        ParseResult::Done(input, val) if AttributeName::StringLength as u64 == val => {
            ParseResult::Done(input, AttributeName::StringLength)
        }

        ParseResult::Done(input, val) if AttributeName::CommonReference as u64 == val => {
            ParseResult::Done(input, AttributeName::CommonReference)
        }

        ParseResult::Done(input, val) if AttributeName::CompDir as u64 == val => {
            ParseResult::Done(input, AttributeName::CompDir)
        }

        ParseResult::Done(input, val) if AttributeName::ConstValue as u64 == val => {
            ParseResult::Done(input, AttributeName::ConstValue)
        }

        ParseResult::Done(input, val) if AttributeName::ContainingType as u64 == val => {
            ParseResult::Done(input, AttributeName::ContainingType)
        }

        ParseResult::Done(input, val) if AttributeName::DefaultValue as u64 == val => {
            ParseResult::Done(input, AttributeName::DefaultValue)
        }

        ParseResult::Done(input, val) if AttributeName::Inline as u64 == val => {
            ParseResult::Done(input, AttributeName::Inline)
        }

        ParseResult::Done(input, val) if AttributeName::IsOptional as u64 == val => {
            ParseResult::Done(input, AttributeName::IsOptional)
        }

        ParseResult::Done(input, val) if AttributeName::LowerBound as u64 == val => {
            ParseResult::Done(input, AttributeName::LowerBound)
        }

        ParseResult::Done(input, val) if AttributeName::Producer as u64 == val => {
            ParseResult::Done(input, AttributeName::Producer)
        }

        ParseResult::Done(input, val) if AttributeName::Prototyped as u64 == val => {
            ParseResult::Done(input, AttributeName::Prototyped)
        }

        ParseResult::Done(input, val) if AttributeName::ReturnAddr as u64 == val => {
            ParseResult::Done(input, AttributeName::ReturnAddr)
        }

        ParseResult::Done(input, val) if AttributeName::StartScope as u64 == val => {
            ParseResult::Done(input, AttributeName::StartScope)
        }

        ParseResult::Done(input, val) if AttributeName::BitStride as u64 == val => {
            ParseResult::Done(input, AttributeName::BitStride)
        }

        ParseResult::Done(input, val) if AttributeName::UpperBound as u64 == val => {
            ParseResult::Done(input, AttributeName::UpperBound)
        }

        ParseResult::Done(input, val) if AttributeName::AbstractOrigin as u64 == val => {
            ParseResult::Done(input, AttributeName::AbstractOrigin)
        }

        ParseResult::Done(input, val) if AttributeName::Accessibility as u64 == val => {
            ParseResult::Done(input, AttributeName::Accessibility)
        }

        ParseResult::Done(input, val) if AttributeName::AddressClass as u64 == val => {
            ParseResult::Done(input, AttributeName::AddressClass)
        }

        ParseResult::Done(input, val) if AttributeName::Artificial as u64 == val => {
            ParseResult::Done(input, AttributeName::Artificial)
        }

        ParseResult::Done(input, val) if AttributeName::BaseTypes as u64 == val => {
            ParseResult::Done(input, AttributeName::BaseTypes)
        }

        ParseResult::Done(input, val) if AttributeName::CallingConvention as u64 == val => {
            ParseResult::Done(input, AttributeName::CallingConvention)
        }

        ParseResult::Done(input, val) if AttributeName::Count as u64 == val => {
            ParseResult::Done(input, AttributeName::Count)
        }

        ParseResult::Done(input, val) if AttributeName::DataMemberLocation as u64 == val => {
            ParseResult::Done(input, AttributeName::DataMemberLocation)
        }

        ParseResult::Done(input, val) if AttributeName::DeclColumn as u64 == val => {
            ParseResult::Done(input, AttributeName::DeclColumn)
        }

        ParseResult::Done(input, val) if AttributeName::DeclFile as u64 == val => {
            ParseResult::Done(input, AttributeName::DeclFile)
        }

        ParseResult::Done(input, val) if AttributeName::DeclLine as u64 == val => {
            ParseResult::Done(input, AttributeName::DeclLine)
        }

        ParseResult::Done(input, val) if AttributeName::Declaration as u64 == val => {
            ParseResult::Done(input, AttributeName::Declaration)
        }

        ParseResult::Done(input, val) if AttributeName::DiscrList as u64 == val => {
            ParseResult::Done(input, AttributeName::DiscrList)
        }

        ParseResult::Done(input, val) if AttributeName::Encoding as u64 == val => {
            ParseResult::Done(input, AttributeName::Encoding)
        }

        ParseResult::Done(input, val) if AttributeName::External as u64 == val => {
            ParseResult::Done(input, AttributeName::External)
        }

        ParseResult::Done(input, val) if AttributeName::FrameBase as u64 == val => {
            ParseResult::Done(input, AttributeName::FrameBase)
        }

        ParseResult::Done(input, val) if AttributeName::Friend as u64 == val => {
            ParseResult::Done(input, AttributeName::Friend)
        }

        ParseResult::Done(input, val) if AttributeName::IdentifierCase as u64 == val => {
            ParseResult::Done(input, AttributeName::IdentifierCase)
        }

        ParseResult::Done(input, val) if AttributeName::MacroInfo as u64 == val => {
            ParseResult::Done(input, AttributeName::MacroInfo)
        }

        ParseResult::Done(input, val) if AttributeName::NamelistItem as u64 == val => {
            ParseResult::Done(input, AttributeName::NamelistItem)
        }

        ParseResult::Done(input, val) if AttributeName::Priority as u64 == val => {
            ParseResult::Done(input, AttributeName::Priority)
        }

        ParseResult::Done(input, val) if AttributeName::Segment as u64 == val => {
            ParseResult::Done(input, AttributeName::Segment)
        }

        ParseResult::Done(input, val) if AttributeName::Specification as u64 == val => {
            ParseResult::Done(input, AttributeName::Specification)
        }

        ParseResult::Done(input, val) if AttributeName::StaticLink as u64 == val => {
            ParseResult::Done(input, AttributeName::StaticLink)
        }

        ParseResult::Done(input, val) if AttributeName::Type as u64 == val => {
            ParseResult::Done(input, AttributeName::Type)
        }

        ParseResult::Done(input, val) if AttributeName::UseLocation as u64 == val => {
            ParseResult::Done(input, AttributeName::UseLocation)
        }

        ParseResult::Done(input, val) if AttributeName::VariableParameter as u64 == val => {
            ParseResult::Done(input, AttributeName::VariableParameter)
        }

        ParseResult::Done(input, val) if AttributeName::Virtuality as u64 == val => {
            ParseResult::Done(input, AttributeName::Virtuality)
        }

        ParseResult::Done(input, val) if AttributeName::VtableElemLocation as u64 == val => {
            ParseResult::Done(input, AttributeName::VtableElemLocation)
        }

        ParseResult::Done(input, val) if AttributeName::Allocated as u64 == val => {
            ParseResult::Done(input, AttributeName::Allocated)
        }

        ParseResult::Done(input, val) if AttributeName::Associated as u64 == val => {
            ParseResult::Done(input, AttributeName::Associated)
        }

        ParseResult::Done(input, val) if AttributeName::DataLocation as u64 == val => {
            ParseResult::Done(input, AttributeName::DataLocation)
        }

        ParseResult::Done(input, val) if AttributeName::ByteStride as u64 == val => {
            ParseResult::Done(input, AttributeName::ByteStride)
        }

        ParseResult::Done(input, val) if AttributeName::EntryPc as u64 == val => {
            ParseResult::Done(input, AttributeName::EntryPc)
        }

        ParseResult::Done(input, val) if AttributeName::UseUtf8 as u64 == val => {
            ParseResult::Done(input, AttributeName::UseUtf8)
        }

        ParseResult::Done(input, val) if AttributeName::Extension as u64 == val => {
            ParseResult::Done(input, AttributeName::Extension)
        }

        ParseResult::Done(input, val) if AttributeName::Ranges as u64 == val => {
            ParseResult::Done(input, AttributeName::Ranges)
        }

        ParseResult::Done(input, val) if AttributeName::Trampoline as u64 == val => {
            ParseResult::Done(input, AttributeName::Trampoline)
        }

        ParseResult::Done(input, val) if AttributeName::CallColumn as u64 == val => {
            ParseResult::Done(input, AttributeName::CallColumn)
        }

        ParseResult::Done(input, val) if AttributeName::CallFile as u64 == val => {
            ParseResult::Done(input, AttributeName::CallFile)
        }

        ParseResult::Done(input, val) if AttributeName::CallLine as u64 == val => {
            ParseResult::Done(input, AttributeName::CallLine)
        }

        ParseResult::Done(input, val) if AttributeName::Description as u64 == val => {
            ParseResult::Done(input, AttributeName::Description)
        }

        ParseResult::Done(input, val) if AttributeName::BinaryScale as u64 == val => {
            ParseResult::Done(input, AttributeName::BinaryScale)
        }

        ParseResult::Done(input, val) if AttributeName::DecimalScale as u64 == val => {
            ParseResult::Done(input, AttributeName::DecimalScale)
        }

        ParseResult::Done(input, val) if AttributeName::Small as u64 == val => {
            ParseResult::Done(input, AttributeName::Small)
        }

        ParseResult::Done(input, val) if AttributeName::DecimalSign as u64 == val => {
            ParseResult::Done(input, AttributeName::DecimalSign)
        }

        ParseResult::Done(input, val) if AttributeName::DigitCount as u64 == val => {
            ParseResult::Done(input, AttributeName::DigitCount)
        }

        ParseResult::Done(input, val) if AttributeName::PictureString as u64 == val => {
            ParseResult::Done(input, AttributeName::PictureString)
        }

        ParseResult::Done(input, val) if AttributeName::Mutable as u64 == val => {
            ParseResult::Done(input, AttributeName::Mutable)
        }

        ParseResult::Done(input, val) if AttributeName::ThreadsScaled as u64 == val => {
            ParseResult::Done(input, AttributeName::ThreadsScaled)
        }

        ParseResult::Done(input, val) if AttributeName::Explicit as u64 == val => {
            ParseResult::Done(input, AttributeName::Explicit)
        }

        ParseResult::Done(input, val) if AttributeName::ObjectPointer as u64 == val => {
            ParseResult::Done(input, AttributeName::ObjectPointer)
        }

        ParseResult::Done(input, val) if AttributeName::Endianity as u64 == val => {
            ParseResult::Done(input, AttributeName::Endianity)
        }

        ParseResult::Done(input, val) if AttributeName::Elemental as u64 == val => {
            ParseResult::Done(input, AttributeName::Elemental)
        }

        ParseResult::Done(input, val) if AttributeName::Pure as u64 == val => {
            ParseResult::Done(input, AttributeName::Pure)
        }

        ParseResult::Done(input, val) if AttributeName::Recursive as u64 == val => {
            ParseResult::Done(input, AttributeName::Recursive)
        }

        ParseResult::Done(input, val) if AttributeName::Signature as u64 == val => {
            ParseResult::Done(input, AttributeName::Signature)
        }

        ParseResult::Done(input, val) if AttributeName::MainSubprogram as u64 == val => {
            ParseResult::Done(input, AttributeName::MainSubprogram)
        }

        ParseResult::Done(input, val) if AttributeName::DataBitOffset as u64 == val => {
            ParseResult::Done(input, AttributeName::DataBitOffset)
        }

        ParseResult::Done(input, val) if AttributeName::ConstExpr as u64 == val => {
            ParseResult::Done(input, AttributeName::ConstExpr)
        }

        ParseResult::Done(input, val) if AttributeName::EnumClass as u64 == val => {
            ParseResult::Done(input, AttributeName::EnumClass)
        }

        ParseResult::Done(input, val) if AttributeName::LinkageName as u64 == val => {
            ParseResult::Done(input, AttributeName::LinkageName)
        }

        ParseResult::Done(input, val) if AttributeName::LoUser as u64 == val => {
            ParseResult::Done(input, AttributeName::LoUser)
        }

        ParseResult::Done(input, val) if AttributeName::HiUser as u64 == val => {
            ParseResult::Done(input, AttributeName::HiUser)
        }

        ParseResult::Done(input, _) => {
            ParseResult::Error(Err::Position(ErrorKind::Custom(Error::InvalidAttributeName), input))
        }

        ParseResult::Incomplete(needed) => ParseResult::Incomplete(needed),

        ParseResult::Error(error) => ParseResult::Error(error),
    }
}

/// The type and encoding of an attribute, aka `DW_FORM_whatever` in the
/// standard.
///
/// DWARF standard 4, section 7.5.4, page 160
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum AttributeForm {
    Addr = 0x01,
    Block2 = 0x03,
    Block4 = 0x04,
    Data2 = 0x05,
    Data4 = 0x06,
    Data8 = 0x07,
    String = 0x08,
    Block = 0x09,
    Block1 = 0x0a,
    Data1 = 0x0b,
    Flag = 0x0c,
    Sdata = 0x0d,
    Strp = 0x0e,
    Udata = 0x0f,
    RefAddr = 0x10,
    Ref1 = 0x11,
    Ref2 = 0x12,
    Ref4 = 0x13,
    Ref8 = 0x14,
    RefUdata = 0x15,
    Indirect = 0x16,
    SecOffset = 0x17,
    Exprloc = 0x18,
    FlagPresent = 0x19,
    RefSig8 = 0x20,
}

/// Parse an attribute's form.
#[allow(cyclomatic_complexity)]
fn parse_attribute_form(input: &[u8]) -> ParseResult<&[u8], AttributeForm, Error> {
    match parse_unsigned_leb(input) {
        ParseResult::Done(input, val) if AttributeForm::Addr as u64 == val => {
            ParseResult::Done(input, AttributeForm::Addr)
        }

        ParseResult::Done(input, val) if AttributeForm::Block2 as u64 == val => {
            ParseResult::Done(input, AttributeForm::Block2)
        }

        ParseResult::Done(input, val) if AttributeForm::Block4 as u64 == val => {
            ParseResult::Done(input, AttributeForm::Block4)
        }

        ParseResult::Done(input, val) if AttributeForm::Data2 as u64 == val => {
            ParseResult::Done(input, AttributeForm::Data2)
        }

        ParseResult::Done(input, val) if AttributeForm::Data4 as u64 == val => {
            ParseResult::Done(input, AttributeForm::Data4)
        }

        ParseResult::Done(input, val) if AttributeForm::Data8 as u64 == val => {
            ParseResult::Done(input, AttributeForm::Data8)
        }

        ParseResult::Done(input, val) if AttributeForm::String as u64 == val => {
            ParseResult::Done(input, AttributeForm::String)
        }

        ParseResult::Done(input, val) if AttributeForm::Block as u64 == val => {
            ParseResult::Done(input, AttributeForm::Block)
        }

        ParseResult::Done(input, val) if AttributeForm::Block1 as u64 == val => {
            ParseResult::Done(input, AttributeForm::Block1)
        }

        ParseResult::Done(input, val) if AttributeForm::Data1 as u64 == val => {
            ParseResult::Done(input, AttributeForm::Data1)
        }

        ParseResult::Done(input, val) if AttributeForm::Flag as u64 == val => {
            ParseResult::Done(input, AttributeForm::Flag)
        }

        ParseResult::Done(input, val) if AttributeForm::Sdata as u64 == val => {
            ParseResult::Done(input, AttributeForm::Sdata)
        }

        ParseResult::Done(input, val) if AttributeForm::Strp as u64 == val => {
            ParseResult::Done(input, AttributeForm::Strp)
        }

        ParseResult::Done(input, val) if AttributeForm::Udata as u64 == val => {
            ParseResult::Done(input, AttributeForm::Udata)
        }

        ParseResult::Done(input, val) if AttributeForm::RefAddr as u64 == val => {
            ParseResult::Done(input, AttributeForm::RefAddr)
        }

        ParseResult::Done(input, val) if AttributeForm::Ref1 as u64 == val => {
            ParseResult::Done(input, AttributeForm::Ref1)
        }

        ParseResult::Done(input, val) if AttributeForm::Ref2 as u64 == val => {
            ParseResult::Done(input, AttributeForm::Ref2)
        }

        ParseResult::Done(input, val) if AttributeForm::Ref4 as u64 == val => {
            ParseResult::Done(input, AttributeForm::Ref4)
        }

        ParseResult::Done(input, val) if AttributeForm::Ref8 as u64 == val => {
            ParseResult::Done(input, AttributeForm::Ref8)
        }

        ParseResult::Done(input, val) if AttributeForm::RefUdata as u64 == val => {
            ParseResult::Done(input, AttributeForm::RefUdata)
        }

        ParseResult::Done(input, val) if AttributeForm::Indirect as u64 == val => {
            ParseResult::Done(input, AttributeForm::Indirect)
        }

        ParseResult::Done(input, val) if AttributeForm::SecOffset as u64 == val => {
            ParseResult::Done(input, AttributeForm::SecOffset)
        }

        ParseResult::Done(input, val) if AttributeForm::Exprloc as u64 == val => {
            ParseResult::Done(input, AttributeForm::Exprloc)
        }

        ParseResult::Done(input, val) if AttributeForm::FlagPresent as u64 == val => {
            ParseResult::Done(input, AttributeForm::FlagPresent)
        }

        ParseResult::Done(input, val) if AttributeForm::RefSig8 as u64 == val => {
            ParseResult::Done(input, AttributeForm::RefSig8)
        }

        ParseResult::Done(input, _) => {
            ParseResult::Error(Err::Position(ErrorKind::Custom(Error::InvalidAttributeForm), input))
        }

        ParseResult::Incomplete(needed) => ParseResult::Incomplete(needed),

        ParseResult::Error(error) => ParseResult::Error(error),
    }
}

/// The description of an attribute in an abbreviated type. It is a pair of name
/// and form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttributeSpecification {
    name: AttributeName,
    form: AttributeForm,
}

impl AttributeSpecification {
    /// Construct a new `AttributeSpecification` from the given name and form.
    pub fn new(name: AttributeName, form: AttributeForm) -> AttributeSpecification {
        AttributeSpecification {
            name: name,
            form: form,
        }
    }

    /// Get the attribute's name.
    pub fn name(&self) -> AttributeName {
        self.name
    }

    /// Get the attribute's form.
    pub fn form(&self) -> AttributeForm {
        self.form
    }

    /// Return the size of the attribute, in bytes.
    ///
    /// Note that because some attributes are variably sized, the size cannot
    /// always be known without parsing, in which case we return `None`.
    pub fn size(&self, header: &CompilationUnit) -> Option<usize> {
        match self.form {
            AttributeForm::Addr => Some(header.address_size() as usize),

            AttributeForm::Flag |
            AttributeForm::FlagPresent |
            AttributeForm::Data1 |
            AttributeForm::Ref1 => Some(1),

            AttributeForm::Data2 |
            AttributeForm::Ref2 => Some(2),

            AttributeForm::Data4 |
            AttributeForm::Ref4 => Some(4),

            AttributeForm::Data8 |
            AttributeForm::Ref8 => Some(8),

            AttributeForm::SecOffset |
            AttributeForm::RefAddr |
            AttributeForm::RefSig8 |
            AttributeForm::Strp => {
                match header.format() {
                    Format::Dwarf32 => Some(4),
                    Format::Dwarf64 => Some(8),
                }
            }

            AttributeForm::Block |
            AttributeForm::Block1 |
            AttributeForm::Block2 |
            AttributeForm::Block4 |
            AttributeForm::Exprloc |
            AttributeForm::RefUdata |
            AttributeForm::String |
            AttributeForm::Sdata |
            AttributeForm::Udata |
            AttributeForm::Indirect => None,
        }
    }
}

/// Parse a non-null attribute specification.
fn parse_attribute_specification(input: &[u8]) -> ParseResult<&[u8], AttributeSpecification, Error> {
    chain!(input,
           name: parse_attribute_name ~
           form: parse_attribute_form,
           || AttributeSpecification::new(name, form))
}

/// Parse the null attribute specification.
fn parse_null_attribute_specification(input: &[u8]) -> ParseResult<&[u8], (), Error> {
    let (input1, name) = try_parse!(input, parse_unsigned_leb);
    if name != 0 {
        return ParseResult::Error(Err::Position(ErrorKind::Custom(Error::ExpectedZero), input));
    }

    let (input2, form) = try_parse!(input1, parse_unsigned_leb);
    if form != 0 {
        return ParseResult::Error(Err::Position(ErrorKind::Custom(Error::ExpectedZero), input1));
    }

    ParseResult::Done(input2, ())
}

/// Parse a series of attribute specifications, terminated by a null attribute
/// specification.
fn parse_attribute_specifications(mut input: &[u8])
                                  -> ParseResult<&[u8], Vec<AttributeSpecification>, Error> {
    // There has to be a better way to keep parsing attributes until we see two
    // 0 LEB128s, but take_until!/take_while! aren't quite expressive enough for
    // this case.

    let mut results = Vec::new();

    loop {
        let (input1, attribute) = try_parse!(
            input,
            alt!(parse_null_attribute_specification => { |_| None } |
                 parse_attribute_specification      => { |a| Some(a) }));

        input = input1;

        match attribute {
            None => break,
            Some(attr) => results.push(attr),
        };
    }

    ParseResult::Done(input, results)
}

/// An abbreviation describes the shape of a DIE type: its code, tag type,
/// whether it has children, and its set of attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Abbreviation {
    code: u64,
    tag: AbbreviationTag,
    has_children: AbbreviationHasChildren,
    attributes: Vec<AttributeSpecification>,
}

impl Abbreviation {
    /// Construct a new `Abbreviation`.
    ///
    /// ### Panics
    ///
    /// Panics if `code` is `0`.
    pub fn new(code: u64,
               tag: AbbreviationTag,
               has_children: AbbreviationHasChildren,
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
    pub fn code(&self) -> u64 {
        self.code
    }

    /// Get this abbreviation's tag.
    pub fn tag(&self) -> AbbreviationTag {
        self.tag
    }

    /// Return true if this abbreviation's type has children, false otherwise.
    pub fn has_children(&self) -> bool {
        match self.has_children {
            AbbreviationHasChildren::Yes => true,
            AbbreviationHasChildren::No => false,
        }
    }

    /// Get this abbreviation's attributes.
    pub fn attributes(&self) -> &[AttributeSpecification] {
        &self.attributes[..]
    }
}

/// Parse a non-null abbreviation.
fn parse_abbreviation(input: &[u8]) -> ParseResult<&[u8], Abbreviation, Error> {
    chain!(input,
           code: parse_abbreviation_code ~
           tag: parse_abbreviation_tag ~
           has_children: parse_abbreviation_has_children ~
           attributes: parse_attribute_specifications,
           || Abbreviation::new(code, tag, has_children, attributes))
}

/// Parse a null abbreviation.
fn parse_null_abbreviation(input: &[u8]) -> ParseResult<&[u8], (), Error> {
    let (input1, name) = try_parse!(input, parse_unsigned_leb);
    if name == 0 {
        ParseResult::Done(input1, ())
    } else {
        ParseResult::Error(Err::Position(ErrorKind::Custom(Error::ExpectedZero), input))
    }

}

/// A set of type abbreviations.
#[derive(Debug, Default, Clone)]
pub struct Abbreviations {
    abbrevs: hash_map::HashMap<u64, Abbreviation>,
}

impl Abbreviations {
    /// Construct a new, empty set of abbreviations.
    pub fn new() -> Abbreviations {
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
    fn get(&self, code: u64) -> Option<&Abbreviation> {
        self.abbrevs.get(&code)
    }
}

/// Parse a series of abbreviations, terminated by a null abbreviation.
pub fn parse_abbreviations(mut input: &[u8]) -> ParseResult<&[u8], Abbreviations, Error> {
    // Again with the super funky keep-parsing-X-while-we-can't-parse-a-Y
    // thing... This should definitely be abstracted out.

    let mut results = Abbreviations::new();

    loop {
        let (input1, abbrev) = try_parse!(input,
                                          alt!(parse_null_abbreviation => { |_| None } |
                                               parse_abbreviation      => { |a| Some(a) }));

        match abbrev {
            None => break,
            Some(abbrev) => {
                match results.insert(abbrev) {
                    Ok(_) => input = input1,
                    Err(_) =>
                        return ParseResult::Error(
                            Err::Position(
                                ErrorKind::Custom(Error::DuplicateAbbreviationCode),
                                input)),
                }
            }
        }
    }

    ParseResult::Done(input, results)
}

trait Raise<T> {
    fn raise(original: Self, lowered_result: T) -> Self;
}

/// Any type U that implements `TranslateInput<T>` can be lowered to T and then
/// later raised back to U. This is useful for lowering types that are a
/// composition of a `&[u8]` and some extra data down to `&[u8]` to use nom's
/// builtin parsers and then raise the result and input back up to the original
/// composition input type.
trait TranslateInput<T>: Raise<T> + Into<T> {}

/// Whether the format of a compilation unit is 32- or 64-bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(enum_variant_names)]
pub enum Format {
    /// 64-bit DWARF
    Dwarf64,
    /// 32-bit DWARF
    Dwarf32,
}

/// The input to parsing various compilation unit header information.
#[derive(Debug, Clone, Copy)]
pub struct FormatInput<'a>(&'a [u8], Format);

impl<'a> nom::InputLength for FormatInput<'a> {
    fn input_len(&self) -> usize {
        self.0.len()
    }
}

impl<'a> FormatInput<'a> {
    /// Construct a new `FormatInput`.
    pub fn new(input: &'a [u8], format: Format) -> FormatInput<'a> {
        FormatInput(input, format)
    }
}

impl<'a> Into<&'a [u8]> for FormatInput<'a> {
    fn into(self) -> &'a [u8] {
        self.0
    }
}

impl<'a> Raise<&'a [u8]> for FormatInput<'a> {
    fn raise(original: Self, lowered: &'a [u8]) -> Self {
        FormatInput(lowered, original.1)
    }
}

impl<'a> TranslateInput<&'a [u8]> for FormatInput<'a> {}

impl<'a> Raise<FormatInput<'a>> for &'a [u8] {
    fn raise(_: Self, lowered: FormatInput<'a>) -> &'a [u8] {
        lowered.0
    }
}

impl<T> Raise<T> for T {
    fn raise(_: Self, lowered: Self) -> Self {
        lowered
    }
}

impl<T> TranslateInput<T> for T {}

/// Use a parser for some lower input type on a higher input type that is a
/// composition of the lower input type and whatever extra data. Specifically,
/// we use this so that we can use parsers on inputs of `&[u8]` with inputs of
/// `FormatInput`, etc.
fn translate<LowerOutput,
             HigherOutput,
             LowerError,
             HigherError,
             LowerInput,
             HigherInput,
             LowerParser>
    (input: HigherInput,
     parser: LowerParser)
     -> ParseResult<HigherInput, HigherOutput, HigherError>
    where HigherInput: TranslateInput<LowerInput> + Clone,
          LowerParser: Fn(LowerInput) -> ParseResult<LowerInput, LowerOutput, LowerError>,
          HigherOutput: From<LowerOutput>,
          HigherError: From<LowerError>
{
    let lowered_input = input.clone().into();
    let lowered_result = parser(lowered_input);
    raise_result(input, lowered_result)
}

fn raise_err<LowerInput, HigherInput, LowerError, HigherError>(original: HigherInput,
                                                               err: Err<LowerInput, LowerError>)
                                                               -> Err<HigherInput, HigherError>
    where HigherInput: Raise<LowerInput> + Clone,
          HigherError: From<LowerError>
{
    fn raise_error_kind<LowerError, HigherError>(code: ErrorKind<LowerError>)
                                                 -> ErrorKind<HigherError>
        where HigherError: From<LowerError>
    {
        // MATCH ALL THE THINGS!!!!
        match code {
            ErrorKind::Custom(e) => ErrorKind::Custom(e.into()),
            ErrorKind::Tag => ErrorKind::Tag,
            ErrorKind::MapRes => ErrorKind::MapRes,
            ErrorKind::MapOpt => ErrorKind::MapOpt,
            ErrorKind::Alt => ErrorKind::Alt,
            ErrorKind::IsNot => ErrorKind::IsNot,
            ErrorKind::IsA => ErrorKind::IsA,
            ErrorKind::SeparatedList => ErrorKind::SeparatedList,
            ErrorKind::SeparatedNonEmptyList => ErrorKind::SeparatedNonEmptyList,
            ErrorKind::Many1 => ErrorKind::Many1,
            ErrorKind::Count => ErrorKind::Count,
            ErrorKind::TakeUntilAndConsume => ErrorKind::TakeUntilAndConsume,
            ErrorKind::TakeUntil => ErrorKind::TakeUntil,
            ErrorKind::TakeUntilEitherAndConsume => ErrorKind::TakeUntilEitherAndConsume,
            ErrorKind::TakeUntilEither => ErrorKind::TakeUntilEither,
            ErrorKind::LengthValue => ErrorKind::LengthValue,
            ErrorKind::TagClosure => ErrorKind::TagClosure,
            ErrorKind::Alpha => ErrorKind::Alpha,
            ErrorKind::Digit => ErrorKind::Digit,
            ErrorKind::HexDigit => ErrorKind::HexDigit,
            ErrorKind::AlphaNumeric => ErrorKind::AlphaNumeric,
            ErrorKind::Space => ErrorKind::Space,
            ErrorKind::MultiSpace => ErrorKind::MultiSpace,
            ErrorKind::LengthValueFn => ErrorKind::LengthValueFn,
            ErrorKind::Eof => ErrorKind::Eof,
            ErrorKind::ExprOpt => ErrorKind::ExprOpt,
            ErrorKind::ExprRes => ErrorKind::ExprRes,
            ErrorKind::CondReduce => ErrorKind::CondReduce,
            ErrorKind::Switch => ErrorKind::Switch,
            ErrorKind::TagBits => ErrorKind::TagBits,
            ErrorKind::OneOf => ErrorKind::OneOf,
            ErrorKind::NoneOf => ErrorKind::NoneOf,
            ErrorKind::Char => ErrorKind::Char,
            ErrorKind::CrLf => ErrorKind::CrLf,
            ErrorKind::RegexpMatch => ErrorKind::RegexpMatch,
            ErrorKind::RegexpMatches => ErrorKind::RegexpMatches,
            ErrorKind::RegexpFind => ErrorKind::RegexpFind,
            ErrorKind::RegexpCapture => ErrorKind::RegexpCapture,
            ErrorKind::RegexpCaptures => ErrorKind::RegexpCaptures,
            ErrorKind::TakeWhile1 => ErrorKind::TakeWhile1,
            ErrorKind::Complete => ErrorKind::Complete,
            ErrorKind::Fix => ErrorKind::Fix,
            ErrorKind::Escaped => ErrorKind::Escaped,
            ErrorKind::EscapedTransform => ErrorKind::EscapedTransform,
            ErrorKind::TagStr => ErrorKind::TagStr,
            ErrorKind::IsNotStr => ErrorKind::IsNotStr,
            ErrorKind::IsAStr => ErrorKind::IsAStr,
            ErrorKind::TakeWhile1Str => ErrorKind::TakeWhile1Str,
            ErrorKind::NonEmpty => ErrorKind::NonEmpty,
            ErrorKind::ManyMN => ErrorKind::ManyMN,
            ErrorKind::TakeUntilAndConsumeStr => ErrorKind::TakeUntilAndConsumeStr,
            ErrorKind::TakeUntilStr => ErrorKind::TakeUntilStr,
            ErrorKind::Many0 => ErrorKind::Many0,
            ErrorKind::OctDigit => ErrorKind::OctDigit,
        }
    }

    match err {
        Err::Code(code) => Err::Code(raise_error_kind(code)),
        Err::Node(code, boxed_err) => {
            Err::Node(raise_error_kind(code),
                      Box::new(raise_err(original, *boxed_err)))
        }
        Err::Position(code, position) => {
            Err::Position(raise_error_kind(code), Raise::raise(original, position))
        }
        Err::NodePosition(code, position, boxed_err) => {
            Err::NodePosition(raise_error_kind(code),
                              Raise::raise(original.clone(), position),
                              Box::new(raise_err(original, *boxed_err)))
        }
    }
}

fn raise_result<LowerOutput, HigherOutput, LowerInput, HigherInput, LowerError, HigherError>
    (original: HigherInput,
     lowered: ParseResult<LowerInput, LowerOutput, LowerError>)
     -> ParseResult<HigherInput, HigherOutput, HigherError>
    where HigherInput: Raise<LowerInput> + Clone,
          HigherOutput: From<LowerOutput>,
          HigherError: From<LowerError>
{
    match lowered {
        ParseResult::Incomplete(needed) => ParseResult::Incomplete(needed),
        ParseResult::Done(rest, val) => ParseResult::Done(Raise::raise(original, rest), val.into()),
        ParseResult::Error(err) => ParseResult::Error(raise_err(original, err)),
    }
}

const MAX_DWARF_32_UNIT_LENGTH: u64 = 0xfffffff0;

const DWARF_64_INITIAL_UNIT_LENGTH: u64 = 0xffffffff;

named!(parse_u32_as_u64<&[u8], u64>,
       chain!(val: le_u32, || val as u64));

/// Parse the compilation unit header's length.
fn parse_unit_length(input: &[u8]) -> ParseResult<&[u8], (u64, Format), Error> {
    match parse_u32_as_u64(input) {
        ParseResult::Done(rest, val) if val < MAX_DWARF_32_UNIT_LENGTH => {
            ParseResult::Done(rest, (val, Format::Dwarf32))
        }

        ParseResult::Done(rest, val) if val == DWARF_64_INITIAL_UNIT_LENGTH => {
            match le_u64(rest) {
                ParseResult::Done(rest, val) => ParseResult::Done(rest, (val, Format::Dwarf64)),
                otherwise => raise_result(rest, otherwise.map(|_| unreachable!())),
            }
        }

        ParseResult::Done(_, _) =>
            ParseResult::Error(Err::Position(
                ErrorKind::Custom(Error::UnknownReservedCompilationUnitLength), input)),

        otherwise => raise_result(input, otherwise.map(|_| unreachable!())),
    }
}

#[test]
fn test_parse_unit_length_32_ok() {
    let buf = [0x12, 0x34, 0x56, 0x78];

    match parse_unit_length(&buf) {
        ParseResult::Done(rest, (length, format)) => {
            assert_eq!(rest.len(), 0);
            assert_eq!(format, Format::Dwarf32);
            assert_eq!(0x78563412, length);
        }
        _ => assert!(false),
    }
}

#[test]
#[cfg_attr(rustfmt, rustfmt_skip)]
fn test_parse_unit_lengtph_64_ok() {
    let buf = [
        // Dwarf_64_INITIAL_UNIT_LENGTH
        0xff, 0xff, 0xff, 0xff,
        // Actual length
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xff
    ];

    match parse_unit_length(&buf) {
        ParseResult::Done(rest, (length, format)) => {
            assert_eq!(rest.len(), 0);
            assert_eq!(format, Format::Dwarf64);
            assert_eq!(0xffdebc9a78563412, length);
        }
        _ => assert!(false),
    }
}

#[test]
fn test_parse_unit_length_unknown_reserved_value() {
    let buf = [0xfe, 0xff, 0xff, 0xff];

    match parse_unit_length(&buf) {
        ParseResult::Error(Err::Position(
            ErrorKind::Custom(Error::UnknownReservedCompilationUnitLength),
            _)) =>
            assert!(true),
        _ => assert!(false),
    };
}

#[test]
fn test_parse_unit_length_incomplete() {
    let buf = [0xff, 0xff, 0xff]; // Need at least 4 bytes.

    match parse_unit_length(&buf) {
        ParseResult::Incomplete(_) => assert!(true),
        _ => assert!(false),
    };
}

#[test]
#[cfg_attr(rustfmt, rustfmt_skip)]
fn test_parse_unit_length_64_incomplete() {
    let buf = [
        // DWARF_64_INITIAL_UNIT_LENGTH
        0xff, 0xff, 0xff, 0xff,
        // Actual length is not long enough.
        0x12, 0x34, 0x56, 0x78
    ];

    match parse_unit_length(&buf) {
        ParseResult::Incomplete(_) => assert!(true),
        _ => assert!(false),
    };
}

/// Parse the DWARF version from the compilation unit header.
fn parse_version(input: &[u8]) -> ParseResult<&[u8], u16, Error> {
    match le_u16(input) {
        // DWARF 1 was very different, and is obsolete, so isn't supported by
        // this reader.
        ParseResult::Done(rest, val) if 2 <= val && val <= 4 => ParseResult::Done(rest, val),

        ParseResult::Done(_, _) => {
            ParseResult::Error(Err::Position(ErrorKind::Custom(Error::UnknownDwarfVersion), input))
        }

        otherwise => raise_result(input, otherwise),
    }
}

#[test]
fn test_compilation_unit_version_ok() {
    // Version 4 and two extra bytes
    let buf = [0x04, 0x00, 0xff, 0xff];

    match parse_version(&buf) {
        ParseResult::Done(rest, val) => {
            assert_eq!(val, 4);
            assert_eq!(rest, &[0xff, 0xff]);
        }
        _ => assert!(false),
    };
}

#[test]
fn test_compilation_unit_version_unknown_version() {
    let buf = [0xab, 0xcd];

    match parse_version(&buf) {
        ParseResult::Error(Err::Position(ErrorKind::Custom(Error::UnknownDwarfVersion), _)) => {
            assert!(true)
        }
        _ => assert!(false),
    };

    let buf = [0x1, 0x0];

    match parse_version(&buf) {
        ParseResult::Error(Err::Position(ErrorKind::Custom(Error::UnknownDwarfVersion), _)) => {
            assert!(true)
        }
        _ => assert!(false),
    };
}

#[test]
fn test_compilation_unit_version_incomplete() {
    let buf = [0x04];

    match parse_version(&buf) {
        ParseResult::Incomplete(_) => assert!(true),
        _ => assert!(false),
    };
}

/// Parse the `debug_abbrev_offset` in the compilation unit header.
fn parse_debug_abbrev_offset(input: FormatInput)
                             -> ParseResult<FormatInput, DebugAbbrevOffset, Error> {
    let offset = match input.1 {
        Format::Dwarf32 => translate(input, parse_u32_as_u64),
        Format::Dwarf64 => translate(input, le_u64),
    };
    offset.map(DebugAbbrevOffset)
}

#[test]
fn test_parse_debug_abbrev_offset_32() {
    let buf = [0x01, 0x02, 0x03, 0x04];

    match parse_debug_abbrev_offset(FormatInput(&buf, Format::Dwarf32)) {
        ParseResult::Done(_, val) => assert_eq!(val, DebugAbbrevOffset(0x04030201)),
        _ => assert!(false),
    };
}

#[test]
fn test_parse_debug_abbrev_offset_32_incomplete() {
    let buf = [0x01, 0x02];

    match parse_debug_abbrev_offset(FormatInput(&buf, Format::Dwarf32)) {
        ParseResult::Incomplete(_) => assert!(true),
        _ => assert!(false),
    };
}

#[test]
fn test_parse_debug_abbrev_offset_64() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    match parse_debug_abbrev_offset(FormatInput(&buf, Format::Dwarf64)) {
        ParseResult::Done(_, val) => assert_eq!(val, DebugAbbrevOffset(0x0807060504030201)),
        _ => assert!(false),
    };
}

#[test]
fn test_parse_debug_abbrev_offset_64_incomplete() {
    let buf = [0x01, 0x02];

    match parse_debug_abbrev_offset(FormatInput(&buf, Format::Dwarf64)) {
        ParseResult::Incomplete(_) => assert!(true),
        _ => assert!(false),
    };
}

/// Parse the size of addresses (in bytes) on the target architecture.
fn parse_address_size(input: &[u8]) -> ParseResult<&[u8], u8, Error> {
    translate(input, le_u8)
}

#[test]
fn test_parse_address_size_ok() {
    let buf = [0x04];

    match parse_address_size(&buf) {
        ParseResult::Done(_, val) => assert_eq!(val, 4),
        _ => assert!(false),
    };
}

/// The header of a compilation unit's debugging information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompilationUnit<'a> {
    unit_length: u64,
    version: u16,
    debug_abbrev_offset: DebugAbbrevOffset,
    address_size: u8,
    format: Format,
    entries_buf: &'a [u8],
}

/// Static methods.
impl<'a> CompilationUnit<'a> {
    /// Construct a new `CompilationUnit`.
    pub fn new(unit_length: u64,
               version: u16,
               debug_abbrev_offset: DebugAbbrevOffset,
               address_size: u8,
               format: Format,
               entries_buf: &'a [u8])
               -> CompilationUnit {
        CompilationUnit {
            unit_length: unit_length,
            version: version,
            debug_abbrev_offset: debug_abbrev_offset,
            address_size: address_size,
            format: format,
            entries_buf: entries_buf,
        }
    }

    /// Return the serialized size of the `unit_length` attribute for the given
    /// DWARF format.
    pub fn size_of_unit_length(format: Format) -> usize {
        match format {
            Format::Dwarf32 => 4,
            Format::Dwarf64 => 12,
        }
    }

    /// Return the serialized size of the compilation unit header for the given
    /// DWARF format.
    pub fn size_of_header(format: Format) -> usize {
        let unit_length_size = Self::size_of_unit_length(format);
        let version_size = 2;
        let debug_abbrev_offset_size = match format {
            Format::Dwarf32 => 4,
            Format::Dwarf64 => 8,
        };
        let address_size_size = 1;

        unit_length_size + version_size + debug_abbrev_offset_size + address_size_size
    }
}

/// Instance methods.
impl<'a> CompilationUnit<'a> {
    /// Get the length of the debugging info for this compilation unit, not
    /// including the byte length of the encoded length itself.
    pub fn unit_length(&self) -> u64 {
        self.unit_length
    }

    /// Get the length of the debugging info for this compilation unit,
    /// uncluding the byte length of the encoded length itself.
    pub fn length_including_self(&self) -> u64 {
        match self.format {
            // Length of the 32-bit header plus the unit length.
            Format::Dwarf32 => 4 + self.unit_length,
            // Length of the 4 byte 0xffffffff value to enable 64-bit mode plus
            // the actual 64-bit length.
            Format::Dwarf64 => 4 + 8 + self.unit_length,
        }
    }

    /// Get the DWARF version of the debugging info for this compilation unit.
    pub fn version(&self) -> u16 {
        self.version
    }

    /// The offset into the `.debug_abbrev` section for this compilation unit's
    /// debugging information entries.
    pub fn debug_abbrev_offset(&self) -> DebugAbbrevOffset {
        self.debug_abbrev_offset
    }

    /// The size of addresses (in bytes) in this compilation unit.
    pub fn address_size(&self) -> u8 {
        self.address_size
    }

    /// Whether this compilation unit is encoded in 64- or 32-bit DWARF.
    pub fn format(&self) -> Format {
        self.format
    }

    /// Navigate this compilation unit's Debugging Information Entries (DIEs).
    pub fn entries<'b>(&'a self, abbreviations: &'b Abbreviations) -> EntriesCursor<'a, 'b> {
        EntriesCursor {
            unit: self,
            position: 0,
            abbreviations: abbreviations,
        }
    }
}

/// Parse a compilation unit header.
pub fn parse_compilation_unit_header(input: &[u8]) -> ParseResult<&[u8], CompilationUnit, Error> {
    let (rest, (unit_length, format)) = try_parse_result!(input, parse_unit_length(input));
    let (rest, version) = try_parse!(rest, parse_version);
    let (rest, offset) = try_parse_result!(rest,
                                           parse_debug_abbrev_offset(FormatInput(rest, format)));
    let (rest, address_size) = try_parse!(rest.0, parse_address_size);

    if unit_length as usize + CompilationUnit::size_of_unit_length(format) <
       CompilationUnit::size_of_header(format) {
        return ParseResult::Error(Err::Position(ErrorKind::Custom(Error::InvalidUnitLength),
                                                input));
    }
    let end = unit_length as usize + CompilationUnit::size_of_unit_length(format) -
              CompilationUnit::size_of_header(format);
    if end > rest.len() {
        return ParseResult::Incomplete(Needed::Size(end - rest.len()));
    }

    println!("end = {}", end);
    println!("rest.len() = {}", rest.len());
    let entries_buf = &rest[..end];
    ParseResult::Done(rest,
                      CompilationUnit::new(unit_length,
                                           version,
                                           offset,
                                           address_size,
                                           format,
                                           entries_buf))
}

#[test]
#[cfg_attr(rustfmt, rustfmt_skip)]
fn test_parse_compilation_unit_header_32_ok() {
    let buf = [
        // 32-bit unit length
        0x07, 0x00, 0x00, 0x00,
        // Version 4
        0x04, 0x00,
        // Debug_abbrev_offset
        0x05, 0x06, 0x07, 0x08,
        // Address size
        0x04
    ];

    match parse_compilation_unit_header(&buf) {
        ParseResult::Done(_, header) => {
            assert_eq!(header,
                       CompilationUnit::new(7,
                                            4,
                                            DebugAbbrevOffset(0x08070605),
                                            4,
                                            Format::Dwarf32,
                                            &[]))
        }
        _ => assert!(false),
    }
}

#[test]
#[cfg_attr(rustfmt, rustfmt_skip)]
fn test_parse_compilation_unit_header_64_ok() {
    let buf = [
        // Enable 64-bit
        0xff, 0xff, 0xff, 0xff,
        // Unit length = 11
        0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // Version 4
        0x04, 0x00,
        // debug_abbrev_offset
        0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
        // Address size
        0x08
    ];

    match parse_compilation_unit_header(&buf) {
        ParseResult::Done(_, header) => {
            let expected = CompilationUnit::new(11,
                                                4,
                                                DebugAbbrevOffset(0x0102030405060708),
                                                8,
                                                Format::Dwarf64,
                                                &[]);
            assert_eq!(header, expected)
        }
        _ => assert!(false),
    }
}

/// A Debugging Information Entry (DIE).
///
/// DIEs have a set of attributes and optionally have children DIEs as well.
#[derive(Clone, Debug)]
pub struct DebuggingInformationEntry<'a, 'b, 'c> {
    attrs_slice: &'a [u8],
    children_slice: Cell<Option<&'a [u8]>>,
    code: u64,
    abbrev: &'b Abbreviation,
    unit: &'c CompilationUnit<'c>,
}

impl<'a, 'b, 'c> DebuggingInformationEntry<'a, 'b, 'c> {
    /// Get this DIE's code.
    pub fn code(&self) -> u64 {
        self.code
    }

    /// Iterate over this DIE's set of attributes.
    pub fn attrs(&self) -> AttrsIter<'a, 'b, 'c> {
        AttrsIter {
            input: self.attrs_slice,
            attributes: &self.abbrev.attributes[..],
            unit: self.unit,
        }
    }
}

/// The value of an attribute in a DIE.
#[derive(Clone, Copy, Debug)]
pub enum AttributeValue<'a> {
    /// A slice that is CompilationUnitHeader::address_size bytes long.
    Addr(&'a [u8]),

    /// A slice of an arbitrary number of bytes.
    Block(&'a [u8]),

    /// A one, two, four, or eight byte constant data value. How to interpret
    /// the bytes depends on context.
    ///
    /// From section 7 of the standard: "Depending on context, it may be a
    /// signed integer, an unsigned integer, a floating-point constant, or
    /// anything else."
    Data(&'a [u8]),

    /// A signed integer constant.
    Sdata(i64),

    /// An unsigned integer constant.
    Udata(u64),

    /// "The information bytes contain a DWARF expression (see Section 2.5) or
    /// location description (see Section 2.6)."
    Exprloc(&'a [u8]),

    /// A boolean typically used to describe the presence or absence of another
    /// attribute.
    Flag(bool),

    /// An offset into another section. Which section this is an offset into
    /// depends on context.
    SecOffset(u64),

    /// An offset into the current compilation unit.
    UnitRef(UnitOffset),

    /// An offset into the current `.debug_info` section, but possibly a
    /// different compilation unit from the current one.
    DebugInfoRef(DebugInfoOffset),

    /// An offset into the `.debug_types` section.
    DebugTypesRef(DebugTypesOffset),

    /// An offset into the `.debug_str` section.
    DebugStrRef(DebugStrOffset),

    /// A null terminated C string, including the final null byte. Not
    /// guaranteed to be UTF-8 or anything like that.
    String(&'a [u8]),
}

/// An attribute in a DIE, consisting of a name and associated value.
#[derive(Copy, Clone, Debug)]
pub struct Attribute<'a> {
    name: AttributeName,
    value: AttributeValue<'a>,
}

impl<'a> Attribute<'a> {
    /// Get this attribute's name.
    pub fn name(&self) -> AttributeName {
        self.name
    }

    /// Get this attribute's value.
    pub fn value(&self) -> AttributeValue {
        self.value
    }
}

/// The input to parsing an attribute.
#[derive(Clone, Copy, Debug)]
pub struct AttributeInput<'a, 'b>(&'a [u8], &'b CompilationUnit<'b>, AttributeSpecification);

impl<'a, 'b> Into<&'a [u8]> for AttributeInput<'a, 'b> {
    fn into(self) -> &'a [u8] {
        self.0
    }
}

impl<'a, 'b> Raise<&'a [u8]> for AttributeInput<'a, 'b> {
    fn raise(original: Self, lowered: &'a [u8]) -> Self {
        AttributeInput(lowered, original.1, original.2)
    }
}

impl<'a, 'b> TranslateInput<&'a [u8]> for AttributeInput<'a, 'b> {}

named!(length_u16_value, length_bytes!(le_u16));
named!(length_u32_value, length_bytes!(le_u32));

fn length_leb_value(input: &[u8]) -> ParseResult<&[u8], &[u8], Error> {
    length_bytes!(input, parse_unsigned_leb)
}

fn parse_attribute<'a, 'b>(mut input: AttributeInput<'a, 'b>)
                           -> ParseResult<AttributeInput<'a, 'b>, Attribute<'a>, Error> {
    let mut form = input.2.form;
    loop {
        match form {
            AttributeForm::Addr => {
                return raise_result(input,
                                    take!(input.0, input.1.address_size()).map(|addr| {
                                        Attribute {
                                            name: input.2.name,
                                            value: AttributeValue::Addr(addr),
                                        }
                                    }));
            }
            AttributeForm::Block1 => {
                return raise_result(input,
                                    length_value(input.0).map(|block| {
                                        Attribute {
                                            name: input.2.name,
                                            value: AttributeValue::Block(block),
                                        }
                                    }))
            }
            AttributeForm::Block2 => {
                return raise_result(input,
                                    length_u16_value(input.0).map(|block| {
                                        Attribute {
                                            name: input.2.name,
                                            value: AttributeValue::Block(block),
                                        }
                                    }))
            }
            AttributeForm::Block4 => {
                return raise_result(input,
                                    length_u32_value(input.0).map(|block| {
                                        Attribute {
                                            name: input.2.name,
                                            value: AttributeValue::Block(block),
                                        }
                                    }))
            }
            AttributeForm::Block => {
                return raise_result(input,
                                    length_leb_value(input.0).map(|block| {
                                        Attribute {
                                            name: input.2.name,
                                            value: AttributeValue::Block(block),
                                        }
                                    }))
            }
            AttributeForm::Data1 => {
                return raise_result(input,
                                    take!(input.0, 1).map(|data| {
                                        Attribute {
                                            name: input.2.name,
                                            value: AttributeValue::Data(data),
                                        }
                                    }))
            }
            AttributeForm::Data2 => {
                return raise_result(input,
                                    take!(input.0, 2).map(|data| {
                                        Attribute {
                                            name: input.2.name,
                                            value: AttributeValue::Data(data),
                                        }
                                    }))
            }
            AttributeForm::Data4 => {
                return raise_result(input,
                                    take!(input.0, 4).map(|data| {
                                        Attribute {
                                            name: input.2.name,
                                            value: AttributeValue::Data(data),
                                        }
                                    }))
            }
            AttributeForm::Data8 => {
                return raise_result(input,
                                    take!(input.0, 8).map(|data| {
                                        Attribute {
                                            name: input.2.name,
                                            value: AttributeValue::Data(data),
                                        }
                                    }))
            }
            AttributeForm::Udata => {
                return raise_result(input,
                                    parse_unsigned_leb(input.0).map(|data| {
                                        Attribute {
                                            name: input.2.name,
                                            value: AttributeValue::Udata(data),
                                        }
                                    }))
            }
            AttributeForm::Sdata => {
                return raise_result(input,
                                    parse_signed_leb(input.0).map(|data| {
                                        Attribute {
                                            name: input.2.name,
                                            value: AttributeValue::Sdata(data),
                                        }
                                    }))
            }
            AttributeForm::Exprloc => {
                return raise_result(input,
                                    length_leb_value(input.0).map(|block| {
                                        Attribute {
                                            name: input.2.name,
                                            value: AttributeValue::Exprloc(block),
                                        }
                                    }))
            }
            AttributeForm::Flag => {
                return raise_result(input,
                                    le_u8(input.0).map(|present| {
                                        Attribute {
                                            name: input.2.name,
                                            value: AttributeValue::Flag(present != 0),
                                        }
                                    }))
            }
            AttributeForm::FlagPresent => {
                // FlagPresent is this weird compile time always true thing that
                // isn't actually present in the serialized DIEs, only in the
                // abbreviations.
                return ParseResult::Done(input,
                                         Attribute {
                                             name: input.2.name,
                                             value: AttributeValue::Flag(true),
                                         });
            }
            AttributeForm::SecOffset => {
                return match input.1.format() {
                    Format::Dwarf32 => {
                        raise_result(input,
                                     le_u32(input.0).map(|offset| {
                                         Attribute {
                                             name: input.2.name,
                                             value: AttributeValue::SecOffset(offset as u64),
                                         }
                                     }))
                    }
                    Format::Dwarf64 => {
                        raise_result(input,
                                     le_u64(input.0).map(|offset| {
                                         Attribute {
                                             name: input.2.name,
                                             value: AttributeValue::SecOffset(offset),
                                         }
                                     }))
                    }
                };
            }
            AttributeForm::Ref1 => {
                return raise_result(input,
                                    le_u8(input.0).map(|reference| {
                                        Attribute {
                                     name: input.2.name,
                                     value: AttributeValue::UnitRef(UnitOffset(reference as u64)),
                                 }
                                    }));
            }
            AttributeForm::Ref2 => {
                return raise_result(input,
                                    le_u16(input.0).map(|reference| {
                                        Attribute {
                                     name: input.2.name,
                                     value: AttributeValue::UnitRef(UnitOffset(reference as u64)),
                                 }
                                    }));
            }
            AttributeForm::Ref4 => {
                return raise_result(input,
                                    le_u32(input.0).map(|reference| {
                                        Attribute {
                                     name: input.2.name,
                                     value: AttributeValue::UnitRef(UnitOffset(reference as u64)),
                                 }
                                    }));
            }
            AttributeForm::Ref8 => {
                return raise_result(input,
                                    le_u64(input.0).map(|reference| {
                                        Attribute {
                                            name: input.2.name,
                                            value: AttributeValue::UnitRef(UnitOffset(reference)),
                                        }
                                    }));
            }
            AttributeForm::RefUdata => {
                return raise_result(input,
                                    parse_unsigned_leb(input.0).map(|reference| {
                                        Attribute {
                                            name: input.2.name,
                                            value: AttributeValue::UnitRef(UnitOffset(reference)),
                                        }
                                    }));
            }
            AttributeForm::RefAddr => {
                return match input.1.format() {
                    Format::Dwarf32 => {
                        raise_result(input,
                                     le_u32(input.0).map(|offset| {
                            let offset = DebugInfoOffset(offset as u64);
                            Attribute {
                                name: input.2.name,
                                value: AttributeValue::DebugInfoRef(offset),
                            }
                        }))
                    }
                    Format::Dwarf64 => {
                        raise_result(input,
                                     le_u64(input.0).map(|offset| {
                            let offset = DebugInfoOffset(offset);
                            Attribute {
                                name: input.2.name,
                                value: AttributeValue::DebugInfoRef(offset),
                            }
                        }))
                    }
                };
            }
            AttributeForm::RefSig8 => {
                return raise_result(input,
                                    le_u64(input.0).map(|offset| {
                    let offset = DebugTypesOffset(offset);
                    Attribute {
                        name: input.2.name,
                        value: AttributeValue::DebugTypesRef(offset),
                    }
                }));
            }
            AttributeForm::String => {
                return raise_result(input,
                                    take_until_and_consume!(input.0, &[0]).map(|bytes| {
                                        Attribute {
                                            name: input.2.name,
                                            value: AttributeValue::String(bytes),
                                        }
                                    }));
            }
            AttributeForm::Strp => {
                return match input.1.format() {
                    Format::Dwarf32 => {
                        raise_result(input,
                                     le_u32(input.0).map(|offset| {
                            let offset = DebugStrOffset(offset as u64);
                            Attribute {
                                name: input.2.name,
                                value: AttributeValue::DebugStrRef(offset),
                            }
                        }))
                    }
                    Format::Dwarf64 => {
                        raise_result(input,
                                     le_u64(input.0).map(|offset| {
                            let offset = DebugStrOffset(offset);
                            Attribute {
                                name: input.2.name,
                                value: AttributeValue::DebugStrRef(offset),
                            }
                        }))
                    }
                };
            }
            AttributeForm::Indirect => {
                let (rest, dynamic_form) = try_parse_result!(input,
                                                             parse_attribute_form(input.0));
                form = dynamic_form;
                input = AttributeInput(rest, input.1, input.2);
                continue;
            }
        };
    }
}

/// An iterator over a particular DIE's attributes.
#[derive(Clone, Copy, Debug)]
pub struct AttrsIter<'a, 'b, 'c> {
    input: &'a [u8],
    attributes: &'b [AttributeSpecification],
    unit: &'c CompilationUnit<'c>,
}

impl<'a, 'b, 'c> Iterator for AttrsIter<'a, 'b, 'c> {
    type Item = ParseResult<AttributeInput<'a, 'c>, Attribute<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.attributes.len() == 0 {
            return None;
        }

        let attr = self.attributes[0];
        self.attributes = &self.attributes[1..];
        match parse_attribute(AttributeInput(self.input, self.unit, attr)) {
            ParseResult::Done(rest, attr) => {
                self.input = rest.0;
                Some(ParseResult::Done(rest, attr))
            }
            otherwise => {
                self.attributes = &[];
                Some(otherwise)
            }
        }
    }
}

impl<'a, 'b, 'c> AttrsIter<'a, 'b, 'c> {
    /// Consume all attributes and get the rest of the input that follows (which
    /// are the children, if the DIE's abbreviation dictates that the DIE has
    /// children).
    fn get_rest(mut self) -> &'a [u8] {
        for _ in &mut self {
        }
        self.input
    }
}

/// A cursor into the Debugging Information Entries tree for a compilation unit.
///
/// The `EntriesCursor` can traverse the DIE tree in either DFS order, or skip
/// to the next sibling of the entry the cursor is currently pointing to.
#[derive(Clone, Copy, Debug)]
pub struct EntriesCursor<'a, 'b> {
    unit: &'a CompilationUnit<'a>,
    position: usize,
    abbreviations: &'b Abbreviations,
}

/// When advancing an `EntriesCursor` through a DIE tree in DFS order, this
/// enumeration describes the relationship from the old position to the new one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DfsMovement {
    /// The cursor was moved down to the first child of the old, parent entry.
    DownToChild,
    /// The cursor was moved up to the old entry's parent's next sibling.
    UpToParentSibling,
    /// The old entry did not have any children, and we moved to its next
    /// sibling.
    SidewaysToSibling,
}

impl<'a, 'b> EntriesCursor<'a, 'b> {
    /// Get the entry that the cursor is currently pointing to.
    pub fn current(&mut self) -> Option<ParseResult<&'a [u8], DebuggingInformationEntry, Error>> {
        if self.position < self.unit.entries_buf.len() {
            let input = &self.unit.entries_buf[self.position..];
            match parse_unsigned_leb(input) {
                ParseResult::Done(rest, code) => {
                    if let Some(abbrev) = self.abbreviations.get(code) {
                        Some(ParseResult::Done(rest,
                                               DebuggingInformationEntry {
                                                   attrs_slice: rest,
                                                   children_slice: Cell::new(None),
                                                   code: code,
                                                   abbrev: abbrev,
                                                   unit: self.unit,
                                               }))
                    } else {
                        let custom = ErrorKind::Custom(Error::UnknownAbbreviationCode);
                        Some(ParseResult::Error(Err::Position(custom, input)))
                    }
                }
                ParseResult::Incomplete(needed) => Some(ParseResult::Incomplete(needed)),
                ParseResult::Error(e) => Some(ParseResult::Error(e)),
            }
        } else {
            None
        }
    }

    /// Move the cursor to the next DIE in the tree in DFS order.
    pub fn next_dfs(&mut self) -> Result<DfsMovement, ()> {
        Err(())
    }

    /// Move the cursor to the next sibling DIE of the current one.
    pub fn next_sibling(&mut self) -> Result<(), ()> {
        Err(())
    }
}

/// Parse a type unit header's unique type signature. Callers should handle
/// unique-ness checking.
fn parse_type_signature(input: &[u8]) -> ParseResult<&[u8], u64, Error> {
    translate(input, le_u64)
}

#[test]
fn test_parse_type_signature_ok() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    match parse_type_signature(&buf) {
        ParseResult::Done(_, val) => assert_eq!(val, 0x0807060504030201),
        _ => assert!(false),
    }
}

#[test]
fn test_parse_type_signature_incomplete() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];

    match parse_type_signature(&buf) {
        ParseResult::Incomplete(_) => assert!(true),
        _ => assert!(false),
    }
}

/// Parse a type unit header's type offset.
fn parse_type_offset(input: FormatInput) -> ParseResult<FormatInput, DebugTypesOffset, Error> {
    let result = match input.1 {
        Format::Dwarf32 => translate(input, parse_u32_as_u64),
        Format::Dwarf64 => translate(input, le_u64),
    };
    result.map(DebugTypesOffset)
}

#[test]
fn test_parse_type_offset_32_ok() {
    let buf = [0x12, 0x34, 0x56, 0x78, 0x00];

    match parse_type_offset(FormatInput(&buf, Format::Dwarf32)) {
        ParseResult::Done(rest, offset) => {
            assert_eq!(rest.0.len(), 1);
            assert_eq!(rest.1, Format::Dwarf32);
            assert_eq!(DebugTypesOffset(0x78563412), offset);
        }
        _ => assert!(false),
    }
}

#[test]
fn test_parse_type_offset_64_ok() {
    let buf = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xff, 0x00];

    match parse_type_offset(FormatInput(&buf, Format::Dwarf64)) {
        ParseResult::Done(rest, offset) => {
            assert_eq!(rest.0.len(), 1);
            assert_eq!(rest.1, Format::Dwarf64);
            assert_eq!(DebugTypesOffset(0xffdebc9a78563412), offset);
        }
        _ => assert!(false),
    }
}

#[test]
fn test_parse_type_offset_incomplete() {
    // Need at least 4 bytes.
    let buf = [0xff, 0xff, 0xff];

    match parse_type_offset(FormatInput(&buf, Format::Dwarf32)) {
        ParseResult::Incomplete(_) => assert!(true),
        _ => assert!(false),
    };
}

/// The header of a type unit's debugging information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypeUnit<'a> {
    header: CompilationUnit<'a>,
    type_signature: u64,
    type_offset: DebugTypesOffset,
}

impl<'a> TypeUnit<'a> {
    /// Construct a new `TypeUnit`.
    pub fn new(header: CompilationUnit<'a>,
               type_signature: u64,
               type_offset: DebugTypesOffset)
               -> TypeUnit {
        TypeUnit {
            header: header,
            type_signature: type_signature,
            type_offset: type_offset,
        }
    }

    /// Get the length of the debugging info for this compilation unit.
    pub fn unit_length(&self) -> u64 {
        self.header.unit_length
    }

    /// Get the DWARF version of the debugging info for this compilation unit.
    pub fn version(&self) -> u16 {
        self.header.version
    }

    /// The offset into the `.debug_abbrev` section for this compilation unit's
    /// debugging information entries.
    pub fn debug_abbrev_offset(&self) -> DebugAbbrevOffset {
        self.header.debug_abbrev_offset
    }

    /// The size of addresses (in bytes) in this compilation unit.
    pub fn address_size(&self) -> u8 {
        self.header.address_size
    }

    /// Get the unique type signature for this type unit.
    pub fn type_signature(&self) -> u64 {
        self.type_signature
    }

    /// Get the offset within this type unit where the type is defined.
    pub fn type_offset(&self) -> DebugTypesOffset {
        self.type_offset
    }
}

/// Parse a type unit header.
pub fn parse_type_unit_header(input: &[u8]) -> ParseResult<&[u8], TypeUnit, Error> {
    let (rest, header) = try_parse!(input, parse_compilation_unit_header);
    let (rest, signature) = try_parse!(rest, parse_type_signature);
    let (rest, offset) = try_parse_result!(rest,
                                           parse_type_offset(FormatInput(rest, header.format())));
    ParseResult::Done(rest.0, TypeUnit::new(header, signature, offset))
}

#[test]
#[cfg_attr(rustfmt, rustfmt_skip)]
fn test_parse_type_unit_header_32_ok() {
    let buf = [
        // Enable 64-bit unit length mode.
        0xff, 0xff, 0xff, 0xff,
        // The actual unit length (11).
        0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // Version 4
        0x04, 0x00,
        // debug_abbrev_offset
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
         // Address size
        0x08,
        // Type signature
        0xef, 0xbe, 0xad, 0xde, 0xef, 0xbe, 0xad, 0xde,
        // type offset
        0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78
    ];

    let result = parse_type_unit_header(&buf);
    println!("result = {:#?}", result);

    match result {
        ParseResult::Done(_, header) => {
            assert_eq!(header,
                       TypeUnit::new(CompilationUnit::new(11,
                                                          4,
                                                          DebugAbbrevOffset(0x0807060504030201),
                                                          8,
                                                          Format::Dwarf64,
                                                          &[]),
                                     0xdeadbeefdeadbeef,
                                     DebugTypesOffset(0x7856341278563412)))
        },
        _ => assert!(false),
    }
}
