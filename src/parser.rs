//! Functions for parsing DWARF debugging information.

use byteorder;
use leb128;
use std::cell::{Cell, RefCell};
use std::collections::hash_map;
use std::error;
use std::fmt::{self, Debug};
use std::io;
use std::marker::PhantomData;
use std::mem;
use std::ops::{Deref, Index, Range, RangeFrom, RangeTo};

/// A trait describing the endianity of some buffer.
///
/// All interesting methods are from the `byteorder` crate's `ByteOrder`
/// trait. All methods are static. You shouldn't instantiate concrete objects
/// that implement this trait, it is just used as compile-time phantom data.
pub trait Endianity
    : byteorder::ByteOrder + Debug + Clone + Copy + PartialEq + Eq {
}

/// Little endian byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LittleEndian {}

impl byteorder::ByteOrder for LittleEndian {
    fn read_u16(buf: &[u8]) -> u16 {
        byteorder::LittleEndian::read_u16(buf)
    }
    fn read_u32(buf: &[u8]) -> u32 {
        byteorder::LittleEndian::read_u32(buf)
    }
    fn read_u64(buf: &[u8]) -> u64 {
        byteorder::LittleEndian::read_u64(buf)
    }
    fn read_uint(buf: &[u8], nbytes: usize) -> u64 {
        byteorder::LittleEndian::read_uint(buf, nbytes)
    }
    fn write_u16(buf: &mut [u8], n: u16) {
        byteorder::LittleEndian::write_u16(buf, n)
    }
    fn write_u32(buf: &mut [u8], n: u32) {
        byteorder::LittleEndian::write_u32(buf, n)
    }
    fn write_u64(buf: &mut [u8], n: u64) {
        byteorder::LittleEndian::write_u64(buf, n)
    }
    fn write_uint(buf: &mut [u8], n: u64, nbytes: usize) {
        byteorder::LittleEndian::write_uint(buf, n, nbytes)
    }
}

impl Endianity for LittleEndian {}

/// Big endian byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BigEndian {}

impl byteorder::ByteOrder for BigEndian {
    fn read_u16(buf: &[u8]) -> u16 {
        byteorder::BigEndian::read_u16(buf)
    }
    fn read_u32(buf: &[u8]) -> u32 {
        byteorder::BigEndian::read_u32(buf)
    }
    fn read_u64(buf: &[u8]) -> u64 {
        byteorder::BigEndian::read_u64(buf)
    }
    fn read_uint(buf: &[u8], nbytes: usize) -> u64 {
        byteorder::BigEndian::read_uint(buf, nbytes)
    }
    fn write_u16(buf: &mut [u8], n: u16) {
        byteorder::BigEndian::write_u16(buf, n)
    }
    fn write_u32(buf: &mut [u8], n: u32) {
        byteorder::BigEndian::write_u32(buf, n)
    }
    fn write_u64(buf: &mut [u8], n: u64) {
        byteorder::BigEndian::write_u64(buf, n)
    }
    fn write_uint(buf: &mut [u8], n: u64, nbytes: usize) {
        byteorder::BigEndian::write_uint(buf, n, nbytes)
    }
}

impl Endianity for BigEndian {}

/// An error that occurred when parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// An error parsing an unsigned LEB128 value.
    BadUnsignedLeb128,
    /// An error parsing a signed LEB128 value.
    BadSignedLeb128,
    /// An abbreviation declared that its code is zero, but zero is reserved for
    /// null records.
    AbbreviationCodeZero,
    /// Found an unknown `DW_TAG_*` type.
    UnknownTag,
    /// The abbreviation's has-children byte was not one of
    /// `DW_CHILDREN_{yes,no}`.
    BadHasChildren,
    /// Found an unknown `DW_NAME_*` type.
    UnknownName,
    /// Found an unknown `DW_FORM_*` type.
    UnknownForm,
    /// Expected a zero, found something else.
    ExpectedZero,
    /// Found an abbreviation code that has already been used.
    DuplicateAbbreviationCode,
    /// Found an unknown reserved length value.
    UnknownReservedLength,
    /// Found an unknown DWARF version.
    UnknownVersion,
    /// The unit header's claimed length is too short to even hold the header
    /// itself.
    UnitHeaderLengthTooShort,
    /// Found a record with an unknown abbreviation code.
    UnknownAbbreviation,
    /// Hit the end of input before it was expected.
    UnexpectedEof,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        Debug::fmt(self, f)
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::BadUnsignedLeb128 => "An error parsing an unsigned LEB128 value",
            Error::BadSignedLeb128 => "An error parsing a signed LEB128 value",
            Error::AbbreviationCodeZero => {
                "An abbreviation declared that its code is zero,
                 but zero is reserved for null records"
            }
            Error::UnknownTag => "Found an unknown `DW_TAG_*` type",
            Error::BadHasChildren => {
                "The abbreviation's has-children byte was not one of
                 `DW_CHILDREN_{yes,no}`"
            }
            Error::UnknownName => "Found an unknown `DW_NAME_*` type",
            Error::UnknownForm => "Found an unknown `DW_FORM_*` type",
            Error::ExpectedZero => "Expected a zero, found something else",
            Error::DuplicateAbbreviationCode => {
                "Found an abbreviation code that has already been used"
            }
            Error::UnknownReservedLength => "Found an unknown reserved length value",
            Error::UnknownVersion => "Found an unknown DWARF version",
            Error::UnitHeaderLengthTooShort => {
                "The unit header's claimed length is too short to even hold
                 the header itself"
            }
            Error::UnknownAbbreviation => "Found a record with an unknown abbreviation code",
            Error::UnexpectedEof => "Hit the end of input before it was expected",
        }
    }
}

/// The result of a parse.
pub type ParseResult<T> = Result<T, Error>;

/// A &[u8] slice with compile-time endianity metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EndianBuf<'input, Endian>(&'input [u8], PhantomData<Endian>) where Endian: Endianity;

impl<'input, Endian> EndianBuf<'input, Endian>
    where Endian: Endianity
{
    fn new(buf: &'input [u8]) -> EndianBuf<'input, Endian> {
        EndianBuf(buf, PhantomData)
    }

    // Unfortunately, std::ops::Index *must* return a reference, so we can't
    // implement Index<Range<usize>> to return a new EndianBuf the way we would
    // like to. Instead, we abandon fancy indexing operators and have these
    // plain old methods.

    #[allow(dead_code)]
    fn range_from(&self, idx: RangeFrom<usize>) -> EndianBuf<'input, Endian> {
        EndianBuf(&self.0[idx], self.1)
    }

    fn range_to(&self, idx: RangeTo<usize>) -> EndianBuf<'input, Endian> {
        EndianBuf(&self.0[idx], self.1)
    }
}

impl<'input, Endian> Index<usize> for EndianBuf<'input, Endian>
    where Endian: Endianity
{
    type Output = u8;
    fn index(&self, idx: usize) -> &Self::Output {
        &self.0[idx]
    }
}

impl<'input, Endian> Deref for EndianBuf<'input, Endian>
    where Endian: Endianity
{
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<'input, Endian> Into<&'input [u8]> for EndianBuf<'input, Endian>
    where Endian: Endianity
{
    fn into(self) -> &'input [u8] {
        self.0
    }
}

fn parse_u8(input: &[u8]) -> ParseResult<(&[u8], u8)> {
    if input.len() == 0 {
        Err(Error::UnexpectedEof)
    } else {
        Ok((&input[1..], input[0]))
    }
}

fn parse_u16<'input, Endian>(input: EndianBuf<'input, Endian>)
                             -> ParseResult<(EndianBuf<'input, Endian>, u16)>
    where Endian: Endianity
{
    if input.len() < 2 {
        Err(Error::UnexpectedEof)
    } else {
        Ok((input.range_from(2..), Endian::read_u16(&input)))
    }
}

fn parse_u32<'input, Endian>(input: EndianBuf<'input, Endian>)
                             -> ParseResult<(EndianBuf<'input, Endian>, u32)>
    where Endian: Endianity
{
    if input.len() < 4 {
        Err(Error::UnexpectedEof)
    } else {
        Ok((input.range_from(4..), Endian::read_u32(&input)))
    }
}

fn parse_u64<'input, Endian>(input: EndianBuf<'input, Endian>)
                             -> ParseResult<(EndianBuf<'input, Endian>, u64)>
    where Endian: Endianity
{
    if input.len() < 8 {
        Err(Error::UnexpectedEof)
    } else {
        Ok((input.range_from(8..), Endian::read_u64(&input)))
    }
}

fn parse_u32_as_u64<'input, Endian>(input: EndianBuf<'input, Endian>)
                                    -> ParseResult<(EndianBuf<'input, Endian>, u64)>
    where Endian: Endianity
{
    if input.len() < 4 {
        Err(Error::UnexpectedEof)
    } else {
        Ok((input.range_from(4..), Endian::read_u32(&input) as u64))
    }
}

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub struct UnitOffset(pub u64);

/// The `DebugAbbrev` struct represents the abbreviations describing
/// `DebuggingInformationEntry`s' attribute names and forms found in the
/// `.debug_abbrev` section.
pub struct DebugAbbrev<'input, Endian>
    where Endian: Endianity
{
    debug_abbrev_section: EndianBuf<'input, Endian>,
}

impl<'input, Endian> DebugAbbrev<'input, Endian>
    where Endian: Endianity
{
    /// Construct a new `DebugAbbrev` instance from the data in the `.debug_abbrev`
    /// section.
    ///
    /// It is the caller's responsibility to read the `.debug_abbrev` section and
    /// present it as a `&[u8]` slice. That means using some ELF loader on
    /// Linux, a Mach-O loader on OSX, etc.
    ///
    /// ```
    /// use gimli::{DebugAbbrev, LittleEndian};
    ///
    /// # let buf = [0x00, 0x01, 0x02, 0x03];
    /// # let read_debug_abbrev_section_somehow = || &buf;
    /// let debug_abbrev = DebugAbbrev::<LittleEndian>::new(read_debug_abbrev_section_somehow());
    /// ```
    pub fn new(debug_abbrev_section: &'input [u8]) -> DebugAbbrev<'input, Endian> {
        DebugAbbrev { debug_abbrev_section: EndianBuf(debug_abbrev_section, PhantomData) }
    }

    /// Parse the abbreviations within this `.debug_abbrev` section.
    pub fn abbreviations(&self) -> ParseResult<Abbreviations> {
        parse_abbreviations(self.debug_abbrev_section.0).map(|(_, abbrevs)| abbrevs)
    }
}

/// The `DebugInfo` struct represents the DWARF debugging information found in
/// the `.debug_info` section.
pub struct DebugInfo<'input, Endian>
    where Endian: Endianity
{
    debug_info_section: EndianBuf<'input, Endian>,
}

impl<'input, Endian> DebugInfo<'input, Endian>
    where Endian: Endianity
{
    /// Construct a new `DebugInfo` instance from the data in the `.debug_info`
    /// section.
    ///
    /// It is the caller's responsibility to read the `.debug_info` section and
    /// present it as a `&[u8]` slice. That means using some ELF loader on
    /// Linux, a Mach-O loader on OSX, etc.
    ///
    /// ```
    /// use gimli::{DebugInfo, LittleEndian};
    ///
    /// # let buf = [0x00, 0x01, 0x02, 0x03];
    /// # let read_debug_info_section_somehow = || &buf;
    /// let debug_info = DebugInfo::<LittleEndian>::new(read_debug_info_section_somehow());
    /// ```
    pub fn new(debug_info_section: &'input [u8]) -> DebugInfo<'input, Endian> {
        DebugInfo { debug_info_section: EndianBuf(debug_info_section, PhantomData) }
    }

    /// Iterate the compilation units in this `.debug_info` section.
    ///
    /// ```
    /// use gimli::{DebugInfo, LittleEndian};
    ///
    /// # let buf = [];
    /// # let read_debug_info_section_somehow = || &buf;
    /// let debug_info = DebugInfo::<LittleEndian>::new(read_debug_info_section_somehow());
    ///
    /// for parse_result in debug_info.compilation_units() {
    ///     let unit = parse_result.unwrap();
    ///     println!("unit's length is {}", unit.unit_length());
    /// }
    /// ```
    pub fn compilation_units(&self) -> CompilationUnitsIter<'input, Endian> {
        CompilationUnitsIter { input: self.debug_info_section }
    }
}

/// An iterator over the compilation units of a `.debug_info` section.
///
/// See the [documentation on
/// `DebugInfo::compilation_units`](./struct.DebugInfo.html#method.compilation_units)
/// for more detail.
pub struct CompilationUnitsIter<'input, Endian>
    where Endian: Endianity
{
    input: EndianBuf<'input, Endian>,
}

impl<'input, Endian> Iterator for CompilationUnitsIter<'input, Endian>
    where Endian: Endianity
{
    type Item = ParseResult<CompilationUnit<'input, Endian>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.input.is_empty() {
            None
        } else {
            match parse_compilation_unit_header(self.input) {
                Ok((_, header)) => {
                    let unit_len = header.length_including_self() as usize;
                    if self.input.len() < unit_len {
                        self.input = self.input.range_to(..0);
                    } else {
                        self.input = self.input.range_from(unit_len..);
                    }
                    Some(Ok(header))
                }
                Err(e) => {
                    self.input = self.input.range_to(..0);
                    Some(Err(e))
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

    let debug_info = DebugInfo::<LittleEndian>::new(&buf);
    let mut units = debug_info.compilation_units();

    match units.next() {
        Some(Ok(header)) => {
            let expected = CompilationUnit::<LittleEndian>::new(0x000000000000002b,
                                                4,
                                                DebugAbbrevOffset(0x0102030405060708),
                                                8,
                                                Format::Dwarf64,
                                                &buf[23..23+32]);
            assert_eq!(header, expected);

        }
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    }

    match units.next() {
        Some(Ok(header)) => {
            let expected =
                CompilationUnit::new(0x00000027,
                                     4,
                                     DebugAbbrevOffset(0x08070605),
                                     4,
                                     Format::Dwarf32,
                                     &buf[buf.len()-32..]);
            assert_eq!(header, expected);
        }
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    }

    assert!(units.next().is_none());
}

/// Parse an unsigned LEB128 encoded integer.
fn parse_unsigned_leb(mut input: &[u8]) -> ParseResult<(&[u8], u64)> {
    match leb128::read::unsigned(&mut input) {
        Ok(val) => Ok((input, val)),
        Err(leb128::read::Error::IoError(ref e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
            Err(Error::UnexpectedEof)
        }
        Err(_) => Err(Error::BadUnsignedLeb128),
    }
}

/// Parse a signed LEB128 encoded integer.
fn parse_signed_leb(mut input: &[u8]) -> ParseResult<(&[u8], i64)> {
    match leb128::read::signed(&mut input) {
        Ok(val) => Ok((input, val)),
        Err(leb128::read::Error::IoError(ref e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
            Err(Error::UnexpectedEof)
        }
        Err(_) => Err(Error::BadSignedLeb128),
    }
}

/// Parse an abbreviation's code.
fn parse_abbreviation_code(input: &[u8]) -> ParseResult<(&[u8], u64)> {
    let (rest, code) = try!(parse_unsigned_leb(input));
    if code == 0 {
        Err(Error::AbbreviationCodeZero)
    } else {
        Ok((rest, code))
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
fn parse_abbreviation_tag(input: &[u8]) -> ParseResult<(&[u8], AbbreviationTag)> {
    let (rest, val) = try!(parse_unsigned_leb(input));

    if AbbreviationTag::ArrayType as u64 == val {
        Ok((rest, AbbreviationTag::ArrayType))
    } else if AbbreviationTag::ClassType as u64 == val {
        Ok((rest, AbbreviationTag::ClassType))
    } else if AbbreviationTag::EntryPoint as u64 == val {
        Ok((rest, AbbreviationTag::EntryPoint))
    } else if AbbreviationTag::EnumerationType as u64 == val {
        Ok((rest, AbbreviationTag::EnumerationType))
    } else if AbbreviationTag::FormalParameter as u64 == val {
        Ok((rest, AbbreviationTag::FormalParameter))
    } else if AbbreviationTag::ImportedDeclaration as u64 == val {
        Ok((rest, AbbreviationTag::ImportedDeclaration))
    } else if AbbreviationTag::Label as u64 == val {
        Ok((rest, AbbreviationTag::Label))
    } else if AbbreviationTag::LexicalBlock as u64 == val {
        Ok((rest, AbbreviationTag::LexicalBlock))
    } else if AbbreviationTag::Member as u64 == val {
        Ok((rest, AbbreviationTag::Member))
    } else if AbbreviationTag::PointerType as u64 == val {
        Ok((rest, AbbreviationTag::PointerType))
    } else if AbbreviationTag::ReferenceType as u64 == val {
        Ok((rest, AbbreviationTag::ReferenceType))
    } else if AbbreviationTag::CompileUnit as u64 == val {
        Ok((rest, AbbreviationTag::CompileUnit))
    } else if AbbreviationTag::StringType as u64 == val {
        Ok((rest, AbbreviationTag::StringType))
    } else if AbbreviationTag::StructureType as u64 == val {
        Ok((rest, AbbreviationTag::StructureType))
    } else if AbbreviationTag::SubroutineType as u64 == val {
        Ok((rest, AbbreviationTag::SubroutineType))
    } else if AbbreviationTag::Typedef as u64 == val {
        Ok((rest, AbbreviationTag::Typedef))
    } else if AbbreviationTag::UnionType as u64 == val {
        Ok((rest, AbbreviationTag::UnionType))
    } else if AbbreviationTag::UnspecifiedParameters as u64 == val {
        Ok((rest, AbbreviationTag::UnspecifiedParameters))
    } else if AbbreviationTag::Variant as u64 == val {
        Ok((rest, AbbreviationTag::Variant))
    } else if AbbreviationTag::CommonBlock as u64 == val {
        Ok((rest, AbbreviationTag::CommonBlock))
    } else if AbbreviationTag::CommonInclusion as u64 == val {
        Ok((rest, AbbreviationTag::CommonInclusion))
    } else if AbbreviationTag::Inheritance as u64 == val {
        Ok((rest, AbbreviationTag::Inheritance))
    } else if AbbreviationTag::InlinedSubroutine as u64 == val {
        Ok((rest, AbbreviationTag::InlinedSubroutine))
    } else if AbbreviationTag::Module as u64 == val {
        Ok((rest, AbbreviationTag::Module))
    } else if AbbreviationTag::PtrToMemberType as u64 == val {
        Ok((rest, AbbreviationTag::PtrToMemberType))
    } else if AbbreviationTag::SetType as u64 == val {
        Ok((rest, AbbreviationTag::SetType))
    } else if AbbreviationTag::SubrangeType as u64 == val {
        Ok((rest, AbbreviationTag::SubrangeType))
    } else if AbbreviationTag::WithStmt as u64 == val {
        Ok((rest, AbbreviationTag::WithStmt))
    } else if AbbreviationTag::AccessDeclaration as u64 == val {
        Ok((rest, AbbreviationTag::AccessDeclaration))
    } else if AbbreviationTag::BaseType as u64 == val {
        Ok((rest, AbbreviationTag::BaseType))
    } else if AbbreviationTag::CatchBlock as u64 == val {
        Ok((rest, AbbreviationTag::CatchBlock))
    } else if AbbreviationTag::ConstType as u64 == val {
        Ok((rest, AbbreviationTag::ConstType))
    } else if AbbreviationTag::Constant as u64 == val {
        Ok((rest, AbbreviationTag::Constant))
    } else if AbbreviationTag::Enumerator as u64 == val {
        Ok((rest, AbbreviationTag::Enumerator))
    } else if AbbreviationTag::FileType as u64 == val {
        Ok((rest, AbbreviationTag::FileType))
    } else if AbbreviationTag::Friend as u64 == val {
        Ok((rest, AbbreviationTag::Friend))
    } else if AbbreviationTag::Namelist as u64 == val {
        Ok((rest, AbbreviationTag::Namelist))
    } else if AbbreviationTag::NamelistItem as u64 == val {
        Ok((rest, AbbreviationTag::NamelistItem))
    } else if AbbreviationTag::PackedType as u64 == val {
        Ok((rest, AbbreviationTag::PackedType))
    } else if AbbreviationTag::Subprogram as u64 == val {
        Ok((rest, AbbreviationTag::Subprogram))
    } else if AbbreviationTag::TemplateTypeParameter as u64 == val {
        Ok((rest, AbbreviationTag::TemplateTypeParameter))
    } else if AbbreviationTag::TemplateValueParameter as u64 == val {
        Ok((rest, AbbreviationTag::TemplateValueParameter))
    } else if AbbreviationTag::ThrownType as u64 == val {
        Ok((rest, AbbreviationTag::ThrownType))
    } else if AbbreviationTag::TryBlock as u64 == val {
        Ok((rest, AbbreviationTag::TryBlock))
    } else if AbbreviationTag::VariantPart as u64 == val {
        Ok((rest, AbbreviationTag::VariantPart))
    } else if AbbreviationTag::Variable as u64 == val {
        Ok((rest, AbbreviationTag::Variable))
    } else if AbbreviationTag::VolatileType as u64 == val {
        Ok((rest, AbbreviationTag::VolatileType))
    } else if AbbreviationTag::RestrictType as u64 == val {
        Ok((rest, AbbreviationTag::RestrictType))
    } else if AbbreviationTag::InterfaceType as u64 == val {
        Ok((rest, AbbreviationTag::InterfaceType))
    } else if AbbreviationTag::Namespace as u64 == val {
        Ok((rest, AbbreviationTag::Namespace))
    } else if AbbreviationTag::ImportedModule as u64 == val {
        Ok((rest, AbbreviationTag::ImportedModule))
    } else if AbbreviationTag::UnspecifiedType as u64 == val {
        Ok((rest, AbbreviationTag::UnspecifiedType))
    } else if AbbreviationTag::PartialUnit as u64 == val {
        Ok((rest, AbbreviationTag::PartialUnit))
    } else if AbbreviationTag::ImportedUnit as u64 == val {
        Ok((rest, AbbreviationTag::ImportedUnit))
    } else if AbbreviationTag::Condition as u64 == val {
        Ok((rest, AbbreviationTag::Condition))
    } else if AbbreviationTag::SharedType as u64 == val {
        Ok((rest, AbbreviationTag::SharedType))
    } else if AbbreviationTag::TypeUnit as u64 == val {
        Ok((rest, AbbreviationTag::TypeUnit))
    } else if AbbreviationTag::RvalueReferenceType as u64 == val {
        Ok((rest, AbbreviationTag::RvalueReferenceType))
    } else if AbbreviationTag::TemplateAlias as u64 == val {
        Ok((rest, AbbreviationTag::TemplateAlias))
    } else if AbbreviationTag::LoUser as u64 == val {
        Ok((rest, AbbreviationTag::LoUser))
    } else if AbbreviationTag::HiUser as u64 == val {
        Ok((rest, AbbreviationTag::HiUser))
    } else {
        Err(Error::UnknownTag)
    }
}

/// Whether an abbreviation's type has children or not, aka
/// `DW_CHILDREN_{yes,no}` in the standard.
///
/// DWARF standard 4, section 7.5.4, page 154
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbbreviationHasChildren {
    /// The type does not have children.
    No = 0x0,

    /// The type has children.
    Yes = 0x1,
}

/// Parse an abbreviation's "does the type have children?" byte.
fn parse_abbreviation_has_children(input: &[u8]) -> ParseResult<(&[u8], AbbreviationHasChildren)> {
    let (rest, val) = try!(parse_u8(input));

    if AbbreviationHasChildren::Yes as u8 == val {
        Ok((rest, AbbreviationHasChildren::Yes))
    } else if AbbreviationHasChildren::No as u8 == val {
        Ok((rest, AbbreviationHasChildren::No))
    } else {
        Err(Error::BadHasChildren)
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
fn parse_attribute_name(input: &[u8]) -> ParseResult<(&[u8], AttributeName)> {
    let (rest, val) = try!(parse_unsigned_leb(input));
    if AttributeName::Sibling as u64 == val {
        Ok((rest, AttributeName::Sibling))
    } else if AttributeName::Location as u64 == val {
        Ok((rest, AttributeName::Location))
    } else if AttributeName::Name as u64 == val {
        Ok((rest, AttributeName::Name))
    } else if AttributeName::Ordering as u64 == val {
        Ok((rest, AttributeName::Ordering))
    } else if AttributeName::ByteSize as u64 == val {
        Ok((rest, AttributeName::ByteSize))
    } else if AttributeName::BitOffset as u64 == val {
        Ok((rest, AttributeName::BitOffset))
    } else if AttributeName::BitSize as u64 == val {
        Ok((rest, AttributeName::BitSize))
    } else if AttributeName::StmtList as u64 == val {
        Ok((rest, AttributeName::StmtList))
    } else if AttributeName::LowPc as u64 == val {
        Ok((rest, AttributeName::LowPc))
    } else if AttributeName::HighPc as u64 == val {
        Ok((rest, AttributeName::HighPc))
    } else if AttributeName::Language as u64 == val {
        Ok((rest, AttributeName::Language))
    } else if AttributeName::Discr as u64 == val {
        Ok((rest, AttributeName::Discr))
    } else if AttributeName::DiscrValue as u64 == val {
        Ok((rest, AttributeName::DiscrValue))
    } else if AttributeName::Visibility as u64 == val {
        Ok((rest, AttributeName::Visibility))
    } else if AttributeName::Import as u64 == val {
        Ok((rest, AttributeName::Import))
    } else if AttributeName::StringLength as u64 == val {
        Ok((rest, AttributeName::StringLength))
    } else if AttributeName::CommonReference as u64 == val {
        Ok((rest, AttributeName::CommonReference))
    } else if AttributeName::CompDir as u64 == val {
        Ok((rest, AttributeName::CompDir))
    } else if AttributeName::ConstValue as u64 == val {
        Ok((rest, AttributeName::ConstValue))
    } else if AttributeName::ContainingType as u64 == val {
        Ok((rest, AttributeName::ContainingType))
    } else if AttributeName::DefaultValue as u64 == val {
        Ok((rest, AttributeName::DefaultValue))
    } else if AttributeName::Inline as u64 == val {
        Ok((rest, AttributeName::Inline))
    } else if AttributeName::IsOptional as u64 == val {
        Ok((rest, AttributeName::IsOptional))
    } else if AttributeName::LowerBound as u64 == val {
        Ok((rest, AttributeName::LowerBound))
    } else if AttributeName::Producer as u64 == val {
        Ok((rest, AttributeName::Producer))
    } else if AttributeName::Prototyped as u64 == val {
        Ok((rest, AttributeName::Prototyped))
    } else if AttributeName::ReturnAddr as u64 == val {
        Ok((rest, AttributeName::ReturnAddr))
    } else if AttributeName::StartScope as u64 == val {
        Ok((rest, AttributeName::StartScope))
    } else if AttributeName::BitStride as u64 == val {
        Ok((rest, AttributeName::BitStride))
    } else if AttributeName::UpperBound as u64 == val {
        Ok((rest, AttributeName::UpperBound))
    } else if AttributeName::AbstractOrigin as u64 == val {
        Ok((rest, AttributeName::AbstractOrigin))
    } else if AttributeName::Accessibility as u64 == val {
        Ok((rest, AttributeName::Accessibility))
    } else if AttributeName::AddressClass as u64 == val {
        Ok((rest, AttributeName::AddressClass))
    } else if AttributeName::Artificial as u64 == val {
        Ok((rest, AttributeName::Artificial))
    } else if AttributeName::BaseTypes as u64 == val {
        Ok((rest, AttributeName::BaseTypes))
    } else if AttributeName::CallingConvention as u64 == val {
        Ok((rest, AttributeName::CallingConvention))
    } else if AttributeName::Count as u64 == val {
        Ok((rest, AttributeName::Count))
    } else if AttributeName::DataMemberLocation as u64 == val {
        Ok((rest, AttributeName::DataMemberLocation))
    } else if AttributeName::DeclColumn as u64 == val {
        Ok((rest, AttributeName::DeclColumn))
    } else if AttributeName::DeclFile as u64 == val {
        Ok((rest, AttributeName::DeclFile))
    } else if AttributeName::DeclLine as u64 == val {
        Ok((rest, AttributeName::DeclLine))
    } else if AttributeName::Declaration as u64 == val {
        Ok((rest, AttributeName::Declaration))
    } else if AttributeName::DiscrList as u64 == val {
        Ok((rest, AttributeName::DiscrList))
    } else if AttributeName::Encoding as u64 == val {
        Ok((rest, AttributeName::Encoding))
    } else if AttributeName::External as u64 == val {
        Ok((rest, AttributeName::External))
    } else if AttributeName::FrameBase as u64 == val {
        Ok((rest, AttributeName::FrameBase))
    } else if AttributeName::Friend as u64 == val {
        Ok((rest, AttributeName::Friend))
    } else if AttributeName::IdentifierCase as u64 == val {
        Ok((rest, AttributeName::IdentifierCase))
    } else if AttributeName::MacroInfo as u64 == val {
        Ok((rest, AttributeName::MacroInfo))
    } else if AttributeName::NamelistItem as u64 == val {
        Ok((rest, AttributeName::NamelistItem))
    } else if AttributeName::Priority as u64 == val {
        Ok((rest, AttributeName::Priority))
    } else if AttributeName::Segment as u64 == val {
        Ok((rest, AttributeName::Segment))
    } else if AttributeName::Specification as u64 == val {
        Ok((rest, AttributeName::Specification))
    } else if AttributeName::StaticLink as u64 == val {
        Ok((rest, AttributeName::StaticLink))
    } else if AttributeName::Type as u64 == val {
        Ok((rest, AttributeName::Type))
    } else if AttributeName::UseLocation as u64 == val {
        Ok((rest, AttributeName::UseLocation))
    } else if AttributeName::VariableParameter as u64 == val {
        Ok((rest, AttributeName::VariableParameter))
    } else if AttributeName::Virtuality as u64 == val {
        Ok((rest, AttributeName::Virtuality))
    } else if AttributeName::VtableElemLocation as u64 == val {
        Ok((rest, AttributeName::VtableElemLocation))
    } else if AttributeName::Allocated as u64 == val {
        Ok((rest, AttributeName::Allocated))
    } else if AttributeName::Associated as u64 == val {
        Ok((rest, AttributeName::Associated))
    } else if AttributeName::DataLocation as u64 == val {
        Ok((rest, AttributeName::DataLocation))
    } else if AttributeName::ByteStride as u64 == val {
        Ok((rest, AttributeName::ByteStride))
    } else if AttributeName::EntryPc as u64 == val {
        Ok((rest, AttributeName::EntryPc))
    } else if AttributeName::UseUtf8 as u64 == val {
        Ok((rest, AttributeName::UseUtf8))
    } else if AttributeName::Extension as u64 == val {
        Ok((rest, AttributeName::Extension))
    } else if AttributeName::Ranges as u64 == val {
        Ok((rest, AttributeName::Ranges))
    } else if AttributeName::Trampoline as u64 == val {
        Ok((rest, AttributeName::Trampoline))
    } else if AttributeName::CallColumn as u64 == val {
        Ok((rest, AttributeName::CallColumn))
    } else if AttributeName::CallFile as u64 == val {
        Ok((rest, AttributeName::CallFile))
    } else if AttributeName::CallLine as u64 == val {
        Ok((rest, AttributeName::CallLine))
    } else if AttributeName::Description as u64 == val {
        Ok((rest, AttributeName::Description))
    } else if AttributeName::BinaryScale as u64 == val {
        Ok((rest, AttributeName::BinaryScale))
    } else if AttributeName::DecimalScale as u64 == val {
        Ok((rest, AttributeName::DecimalScale))
    } else if AttributeName::Small as u64 == val {
        Ok((rest, AttributeName::Small))
    } else if AttributeName::DecimalSign as u64 == val {
        Ok((rest, AttributeName::DecimalSign))
    } else if AttributeName::DigitCount as u64 == val {
        Ok((rest, AttributeName::DigitCount))
    } else if AttributeName::PictureString as u64 == val {
        Ok((rest, AttributeName::PictureString))
    } else if AttributeName::Mutable as u64 == val {
        Ok((rest, AttributeName::Mutable))
    } else if AttributeName::ThreadsScaled as u64 == val {
        Ok((rest, AttributeName::ThreadsScaled))
    } else if AttributeName::Explicit as u64 == val {
        Ok((rest, AttributeName::Explicit))
    } else if AttributeName::ObjectPointer as u64 == val {
        Ok((rest, AttributeName::ObjectPointer))
    } else if AttributeName::Endianity as u64 == val {
        Ok((rest, AttributeName::Endianity))
    } else if AttributeName::Elemental as u64 == val {
        Ok((rest, AttributeName::Elemental))
    } else if AttributeName::Pure as u64 == val {
        Ok((rest, AttributeName::Pure))
    } else if AttributeName::Recursive as u64 == val {
        Ok((rest, AttributeName::Recursive))
    } else if AttributeName::Signature as u64 == val {
        Ok((rest, AttributeName::Signature))
    } else if AttributeName::MainSubprogram as u64 == val {
        Ok((rest, AttributeName::MainSubprogram))
    } else if AttributeName::DataBitOffset as u64 == val {
        Ok((rest, AttributeName::DataBitOffset))
    } else if AttributeName::ConstExpr as u64 == val {
        Ok((rest, AttributeName::ConstExpr))
    } else if AttributeName::EnumClass as u64 == val {
        Ok((rest, AttributeName::EnumClass))
    } else if AttributeName::LinkageName as u64 == val {
        Ok((rest, AttributeName::LinkageName))
    } else if AttributeName::LoUser as u64 == val {
        Ok((rest, AttributeName::LoUser))
    } else if AttributeName::HiUser as u64 == val {
        Ok((rest, AttributeName::HiUser))
    } else {
        Err(Error::UnknownName)
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
fn parse_attribute_form(input: &[u8]) -> ParseResult<(&[u8], AttributeForm)> {
    let (rest, val) = try!(parse_unsigned_leb(input));
    if AttributeForm::Addr as u64 == val {
        Ok((rest, AttributeForm::Addr))
    } else if AttributeForm::Block2 as u64 == val {
        Ok((rest, AttributeForm::Block2))
    } else if AttributeForm::Block4 as u64 == val {
        Ok((rest, AttributeForm::Block4))
    } else if AttributeForm::Data2 as u64 == val {
        Ok((rest, AttributeForm::Data2))
    } else if AttributeForm::Data4 as u64 == val {
        Ok((rest, AttributeForm::Data4))
    } else if AttributeForm::Data8 as u64 == val {
        Ok((rest, AttributeForm::Data8))
    } else if AttributeForm::String as u64 == val {
        Ok((rest, AttributeForm::String))
    } else if AttributeForm::Block as u64 == val {
        Ok((rest, AttributeForm::Block))
    } else if AttributeForm::Block1 as u64 == val {
        Ok((rest, AttributeForm::Block1))
    } else if AttributeForm::Data1 as u64 == val {
        Ok((rest, AttributeForm::Data1))
    } else if AttributeForm::Flag as u64 == val {
        Ok((rest, AttributeForm::Flag))
    } else if AttributeForm::Sdata as u64 == val {
        Ok((rest, AttributeForm::Sdata))
    } else if AttributeForm::Strp as u64 == val {
        Ok((rest, AttributeForm::Strp))
    } else if AttributeForm::Udata as u64 == val {
        Ok((rest, AttributeForm::Udata))
    } else if AttributeForm::RefAddr as u64 == val {
        Ok((rest, AttributeForm::RefAddr))
    } else if AttributeForm::Ref1 as u64 == val {
        Ok((rest, AttributeForm::Ref1))
    } else if AttributeForm::Ref2 as u64 == val {
        Ok((rest, AttributeForm::Ref2))
    } else if AttributeForm::Ref4 as u64 == val {
        Ok((rest, AttributeForm::Ref4))
    } else if AttributeForm::Ref8 as u64 == val {
        Ok((rest, AttributeForm::Ref8))
    } else if AttributeForm::RefUdata as u64 == val {
        Ok((rest, AttributeForm::RefUdata))
    } else if AttributeForm::Indirect as u64 == val {
        Ok((rest, AttributeForm::Indirect))
    } else if AttributeForm::SecOffset as u64 == val {
        Ok((rest, AttributeForm::SecOffset))
    } else if AttributeForm::Exprloc as u64 == val {
        Ok((rest, AttributeForm::Exprloc))
    } else if AttributeForm::FlagPresent as u64 == val {
        Ok((rest, AttributeForm::FlagPresent))
    } else if AttributeForm::RefSig8 as u64 == val {
        Ok((rest, AttributeForm::RefSig8))
    } else {
        Err(Error::UnknownForm)
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
    pub fn size<'me, 'input, 'unit, Endian>(&'me self,
                                            header: &'unit CompilationUnit<'input, Endian>)
                                            -> Option<usize>
        where Endian: Endianity
    {
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
fn parse_attribute_specification(input: &[u8]) -> ParseResult<(&[u8], AttributeSpecification)> {
    let (rest, name) = try!(parse_attribute_name(input));
    let (rest, form) = try!(parse_attribute_form(rest));
    let spec = AttributeSpecification::new(name, form);
    Ok((rest, spec))
}

/// Parse the null attribute specification.
fn parse_null_attribute_specification(input: &[u8]) -> ParseResult<(&[u8], ())> {
    let (rest, name) = try!(parse_unsigned_leb(input));
    if name != 0 {
        return Err(Error::ExpectedZero);
    }

    let (rest, form) = try!(parse_unsigned_leb(rest));
    if form != 0 {
        return Err(Error::ExpectedZero);
    }

    Ok((rest, ()))
}

/// Parse a series of attribute specifications, terminated by a null attribute
/// specification.
fn parse_attribute_specifications(mut input: &[u8])
                                  -> ParseResult<(&[u8], Vec<AttributeSpecification>)> {
    let mut attrs = Vec::new();

    loop {
        let result = parse_null_attribute_specification(input).map(|(rest, _)| (rest, None));
        let result = result.or_else(|_| parse_attribute_specification(input).map(|(rest, a)| (rest, Some(a))));
        let (rest, attr) = try!(result);
        input = rest;

        match attr {
            None => break,
            Some(attr) => attrs.push(attr),
        };
    }

    Ok((input, attrs))
}

/// An abbreviation describes the shape of a `DebuggingInformationEntry`'s type:
/// its code, tag type, whether it has children, and its set of attributes.
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
fn parse_abbreviation(input: &[u8]) -> ParseResult<(&[u8], Abbreviation)> {
    let (rest, code) = try!(parse_abbreviation_code(input));
    let (rest, tag) = try!(parse_abbreviation_tag(rest));
    let (rest, has_children) = try!(parse_abbreviation_has_children(rest));
    let (rest, attributes) = try!(parse_attribute_specifications(rest));
    let abbrev = Abbreviation::new(code, tag, has_children, attributes);
    Ok((rest, abbrev))
}

/// Parse a null abbreviation.
fn parse_null_abbreviation(input: &[u8]) -> ParseResult<(&[u8], ())> {
    let (rest, name) = try!(parse_unsigned_leb(input));
    if name == 0 {
        Ok((rest, ()))
    } else {
        Err(Error::ExpectedZero)
    }

}

/// A set of type abbreviations.
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
    fn get(&self, code: u64) -> Option<&Abbreviation> {
        self.abbrevs.get(&code)
    }
}

/// Parse a series of abbreviations, terminated by a null abbreviation.
fn parse_abbreviations(mut input: &[u8]) -> ParseResult<(&[u8], Abbreviations)> {
    let mut abbrevs = Abbreviations::empty();

    loop {
        let result = parse_null_abbreviation(input).map(|(rest, _)| (rest, None));
        let result = result.or_else(|_| parse_abbreviation(input).map(|(rest, a)| (rest, Some(a))));
        let (rest, abbrev) = try!(result);
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

/// Whether the format of a compilation unit is 32- or 64-bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// 64-bit DWARF
    Dwarf64,
    /// 32-bit DWARF
    Dwarf32,
}

/// The input to parsing various compilation unit header information.
#[derive(Debug, Clone, Copy)]
struct FormatInput<'input, Endian>(EndianBuf<'input, Endian>, Format) where Endian: Endianity;

impl<'input, Endian> FormatInput<'input, Endian>
    where Endian: Endianity
{
    fn merge(&self, rest: EndianBuf<'input, Endian>) -> FormatInput<'input, Endian> {
        FormatInput(rest, self.1)
    }
}

impl<'input, Endian> Into<EndianBuf<'input, Endian>> for FormatInput<'input, Endian>
    where Endian: Endianity
{
    fn into(self) -> EndianBuf<'input, Endian> {
        self.0
    }
}

impl<'input, Endian> Into<&'input [u8]> for FormatInput<'input, Endian>
    where Endian: Endianity
{
    fn into(self) -> &'input [u8] {
        self.0.into()
    }
}

impl<'input, Endian> Deref for FormatInput<'input, Endian>
    where Endian: Endianity
{
    type Target = EndianBuf<'input, Endian>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

const MAX_DWARF_32_UNIT_LENGTH: u64 = 0xfffffff0;

const DWARF_64_INITIAL_UNIT_LENGTH: u64 = 0xffffffff;

/// Parse the compilation unit header's length.
fn parse_unit_length<'input, Endian>(input: EndianBuf<'input, Endian>)
                                     -> ParseResult<(EndianBuf<'input, Endian>, (u64, Format))>
    where Endian: Endianity
{
    let (rest, val) = try!(parse_u32_as_u64(input));
    if val < MAX_DWARF_32_UNIT_LENGTH {
        Ok((rest, (val, Format::Dwarf32)))
    } else if val == DWARF_64_INITIAL_UNIT_LENGTH {
        let (rest, val) = try!(parse_u64(rest));
        Ok((rest, (val, Format::Dwarf64)))
    } else {
        Err(Error::UnknownReservedLength)
    }
}

#[test]
fn test_parse_unit_length_32_ok() {
    let buf = [0x12, 0x34, 0x56, 0x78];

    match parse_unit_length(EndianBuf::<LittleEndian>::new(&buf)) {
        Ok((rest, (length, format))) => {
            assert_eq!(rest.len(), 0);
            assert_eq!(format, Format::Dwarf32);
            assert_eq!(0x78563412, length);
        }
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    }
}

#[test]
#[cfg_attr(rustfmt, rustfmt_skip)]
fn test_parse_unit_length_64_ok() {
    let buf = [
        // Dwarf_64_INITIAL_UNIT_LENGTH
        0xff, 0xff, 0xff, 0xff,
        // Actual length
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xff
    ];

    match parse_unit_length(EndianBuf::<LittleEndian>::new(&buf)) {
        Ok((rest, (length, format))) => {
            assert_eq!(rest.len(), 0);
            assert_eq!(format, Format::Dwarf64);
            assert_eq!(0xffdebc9a78563412, length);
        }
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    }
}

#[test]
fn test_parse_unit_length_unknown_reserved_value() {
    let buf = [0xfe, 0xff, 0xff, 0xff];

    match parse_unit_length(EndianBuf::<LittleEndian>::new(&buf)) {
        Err(Error::UnknownReservedLength) => assert!(true),
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    };
}

#[test]
fn test_parse_unit_length_incomplete() {
    let buf = [0xff, 0xff, 0xff]; // Need at least 4 bytes.

    match parse_unit_length(EndianBuf::<LittleEndian>::new(&buf)) {
        Err(Error::UnexpectedEof) => assert!(true),
        otherwise => panic!("Unexpected result: {:?}", otherwise),
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

    match parse_unit_length(EndianBuf::<LittleEndian>::new(&buf)) {
        Err(Error::UnexpectedEof) => assert!(true),
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    };
}

/// Parse the DWARF version from the compilation unit header.
fn parse_version<'input, Endian>(input: EndianBuf<'input, Endian>)
                                 -> ParseResult<(EndianBuf<'input, Endian>, u16)>
    where Endian: Endianity
{
    let (rest, val) = try!(parse_u16(input));

    // DWARF 1 was very different, and is obsolete, so isn't supported by this
    // reader.
    if 2 <= val && val <= 4 {
        Ok((rest, val))
    } else {
        Err(Error::UnknownVersion)
    }
}

#[test]
fn test_compilation_unit_version_ok() {
    // Version 4 and two extra bytes
    let buf = [0x04, 0x00, 0xff, 0xff];

    match parse_version(EndianBuf::<LittleEndian>::new(&buf)) {
        Ok((rest, val)) => {
            assert_eq!(val, 4);
            assert_eq!(rest, EndianBuf::new(&[0xff, 0xff]));
        }
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    };
}

#[test]
fn test_compilation_unit_version_unknown_version() {
    let buf = [0xab, 0xcd];

    match parse_version(EndianBuf::<LittleEndian>::new(&buf)) {
        Err(Error::UnknownVersion) => assert!(true),
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    };

    let buf = [0x1, 0x0];

    match parse_version(EndianBuf::<LittleEndian>::new(&buf)) {
        Err(Error::UnknownVersion) => assert!(true),
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    };
}

#[test]
fn test_compilation_unit_version_incomplete() {
    let buf = [0x04];

    match parse_version(EndianBuf::<LittleEndian>::new(&buf)) {
        Err(Error::UnexpectedEof) => assert!(true),
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    };
}

/// Parse the `debug_abbrev_offset` in the compilation unit header.
fn parse_debug_abbrev_offset<'input, Endian>
    (input: FormatInput<'input, Endian>)
     -> ParseResult<(FormatInput<'input, Endian>, DebugAbbrevOffset)>
    where Endian: Endianity
{
    let offset = match input.1 {
        Format::Dwarf32 => parse_u32_as_u64(input.0),
        Format::Dwarf64 => parse_u64(input.0),
    };
    offset.map(|(rest, offset)| (input.merge(rest), DebugAbbrevOffset(offset)))
}

#[test]
fn test_parse_debug_abbrev_offset_32() {
    let buf = [0x01, 0x02, 0x03, 0x04];

    match parse_debug_abbrev_offset(FormatInput(EndianBuf::<LittleEndian>::new(&buf),
                                                Format::Dwarf32)) {
        Ok((_, val)) => assert_eq!(val, DebugAbbrevOffset(0x04030201)),
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    };
}

#[test]
fn test_parse_debug_abbrev_offset_32_incomplete() {
    let buf = [0x01, 0x02];

    match parse_debug_abbrev_offset(FormatInput(EndianBuf::<LittleEndian>::new(&buf),
                                                Format::Dwarf32)) {
        Err(Error::UnexpectedEof) => assert!(true),
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    };
}

#[test]
fn test_parse_debug_abbrev_offset_64() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    match parse_debug_abbrev_offset(FormatInput(EndianBuf::<LittleEndian>::new(&buf),
                                                Format::Dwarf64)) {
        Ok((_, val)) => assert_eq!(val, DebugAbbrevOffset(0x0807060504030201)),
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    };
}

#[test]
fn test_parse_debug_abbrev_offset_64_incomplete() {
    let buf = [0x01, 0x02];

    match parse_debug_abbrev_offset(FormatInput(EndianBuf::<LittleEndian>::new(&buf),
                                                Format::Dwarf64)) {
        Err(Error::UnexpectedEof) => assert!(true),
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    };
}

/// Parse the size of addresses (in bytes) on the target architecture.
fn parse_address_size(input: &[u8]) -> ParseResult<(&[u8], u8)> {
    parse_u8(input)
}

#[test]
fn test_parse_address_size_ok() {
    let buf = [0x04];

    match parse_address_size(&buf) {
        Ok((_, val)) => assert_eq!(val, 4),
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    };
}

/// The header of a compilation unit's debugging information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompilationUnit<'input, Endian>
    where Endian: Endianity
{
    unit_length: u64,
    version: u16,
    debug_abbrev_offset: DebugAbbrevOffset,
    address_size: u8,
    format: Format,
    entries_buf: EndianBuf<'input, Endian>,
}

/// Static methods.
impl<'input, Endian> CompilationUnit<'input, Endian>
    where Endian: Endianity
{
    /// Construct a new `CompilationUnit`.
    pub fn new(unit_length: u64,
               version: u16,
               debug_abbrev_offset: DebugAbbrevOffset,
               address_size: u8,
               format: Format,
               entries_buf: &'input [u8])
               -> CompilationUnit<'input, Endian> {
        CompilationUnit {
            unit_length: unit_length,
            version: version,
            debug_abbrev_offset: debug_abbrev_offset,
            address_size: address_size,
            format: format,
            entries_buf: EndianBuf(entries_buf, PhantomData),
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
impl<'input, Endian> CompilationUnit<'input, Endian>
    where Endian: Endianity
{
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
    /// debugging information entries' abbreviations.
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

    fn is_valid_offset(&self, offset: UnitOffset) -> bool {
        let size_of_header = Self::size_of_header(self.format);
        if !offset.0 as usize >= size_of_header {
            return false;
        }

        let relative_to_entries_buf = offset.0 as usize - size_of_header;
        relative_to_entries_buf < self.entries_buf.len()
    }

    /// Get the underlying bytes for the supplied range.
    pub fn range(&self, idx: Range<UnitOffset>) -> &'input [u8] {
        assert!(self.is_valid_offset(idx.start));
        assert!(self.is_valid_offset(idx.end));
        assert!(idx.start <= idx.end);
        let size_of_header = Self::size_of_header(self.format);
        let start = idx.start.0 as usize - size_of_header;
        let end = idx.end.0 as usize - size_of_header;
        &self.entries_buf.0[start..end]
    }

    /// Get the underlying bytes for the supplied range.
    pub fn range_from(&self, idx: RangeFrom<UnitOffset>) -> &'input [u8] {
        assert!(self.is_valid_offset(idx.start));
        let start = idx.start.0 as usize - Self::size_of_header(self.format);
        &self.entries_buf.0[start..]
    }

    /// Get the underlying bytes for the supplied range.
    pub fn range_to(&self, idx: RangeTo<UnitOffset>) -> &'input [u8] {
        assert!(self.is_valid_offset(idx.end));
        let end = idx.end.0 as usize - Self::size_of_header(self.format);
        &self.entries_buf.0[..end]
    }

    /// Navigate this compilation unit's `DebuggingInformationEntry`s.
    pub fn entries<'me, 'abbrev>(&'me self,
                                 abbreviations: &'abbrev Abbreviations)
                                 -> EntriesCursor<'input, 'abbrev, 'me, Endian> {
        EntriesCursor {
            unit: self,
            input: self.entries_buf.into(),
            abbreviations: abbreviations,
            cached_current: RefCell::new(None),
        }
    }
}

/// Parse a compilation unit header.
fn parse_compilation_unit_header<'input, Endian>
    (input: EndianBuf<'input, Endian>)
     -> ParseResult<(EndianBuf<'input, Endian>, CompilationUnit<'input, Endian>)>
    where Endian: Endianity
{
    let (rest, (unit_length, format)) = try!(parse_unit_length(input));
    let (rest, version) = try!(parse_version(rest));
    let (rest, offset) = try!(parse_debug_abbrev_offset(FormatInput(rest, format)));
    let (rest, address_size) = try!(parse_address_size(rest.into()));

    let size_of_unit_length = CompilationUnit::<Endian>::size_of_unit_length(format);
    let size_of_header = CompilationUnit::<Endian>::size_of_header(format);

    if unit_length as usize + size_of_unit_length < size_of_header {
        return Err(Error::UnitHeaderLengthTooShort);
    }

    let end = unit_length as usize + size_of_unit_length - size_of_header;
    if end > rest.len() {
        return Err(Error::UnexpectedEof);
    }

    let entries_buf = &rest[..end];
    Ok((EndianBuf::new(rest),
        CompilationUnit::new(unit_length,
                             version,
                             offset,
                             address_size,
                             format,
                             entries_buf)))
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

    match parse_compilation_unit_header(EndianBuf::<LittleEndian>::new(&buf)) {
        Ok((_, header)) => {
            assert_eq!(header,
                       CompilationUnit::new(7,
                                            4,
                                            DebugAbbrevOffset(0x08070605),
                                            4,
                                            Format::Dwarf32,
                                            &[]))
        }
        otherwise => panic!("Unexpected result: {:?}", otherwise),
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

    match parse_compilation_unit_header(EndianBuf::<LittleEndian>::new(&buf)) {
        Ok((_, header)) => {
            let expected = CompilationUnit::new(11,
                                                4,
                                                DebugAbbrevOffset(0x0102030405060708),
                                                8,
                                                Format::Dwarf64,
                                                &[]);
            assert_eq!(header, expected)
        }
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    }
}

/// A Debugging Information Entry (DIE).
///
/// DIEs have a set of attributes and optionally have children DIEs as well.
#[derive(Clone, Debug)]
pub struct DebuggingInformationEntry<'input, 'abbrev, 'unit, Endian>
    where 'input: 'unit,
          Endian: Endianity + 'unit
{
    attrs_slice: &'input [u8],
    after_attrs: Cell<Option<&'input [u8]>>,
    code: u64,
    abbrev: &'abbrev Abbreviation,
    unit: &'unit CompilationUnit<'input, Endian>,
}

impl<'input, 'abbrev, 'unit, Endian> DebuggingInformationEntry<'input, 'abbrev, 'unit, Endian>
    where Endian: Endianity
{
    /// Get this entry's code.
    pub fn code(&self) -> u64 {
        self.code
    }

    /// Iterate over this entry's set of attributes.
    ///
    /// ```
    /// use gimli::{DebugAbbrev, DebugInfo, LittleEndian};
    ///
    /// // Read the `.debug_abbrev` section and parse it into `Abbreviations`.
    ///
    /// # let abbrev_buf = [
    /// #     // Code
    /// #     0x01,
    /// #     // DW_TAG_subprogram
    /// #     0x2e,
    /// #     // DW_CHILDREN_no
    /// #     0x00,
    /// #     // Begin attributes
    /// #       // Attribute name = DW_AT_name
    /// #       0x03,
    /// #       // Attribute form = DW_FORM_string
    /// #       0x08,
    /// #     // End attributes
    /// #     0x00,
    /// #     0x00,
    /// #     // Null terminator
    /// #     0x00
    /// # ];
    /// # let read_debug_abbrev_section_somehow = || &abbrev_buf;
    /// let debug_abbrev = DebugAbbrev::<LittleEndian>::new(read_debug_abbrev_section_somehow());
    /// let abbrevs = debug_abbrev.abbreviations().unwrap();
    ///
    /// // Read the `.debug_info` section.
    ///
    /// # let info_buf = [
    /// #     // Comilation unit header
    /// #
    /// #     // 32-bit unit length = 12
    /// #     0x0c, 0x00, 0x00, 0x00,
    /// #     // Version 4
    /// #     0x04, 0x00,
    /// #     // debug_abbrev_offset
    /// #     0x05, 0x06, 0x07, 0x08,
    /// #     // Address size
    /// #     0x04,
    /// #
    /// #     // DIEs
    /// #
    /// #     // Abbreviation code
    /// #     0x01,
    /// #     // Attribute of form DW_FORM_string = "foo\0"
    /// #     0x66, 0x6f, 0x6f, 0x00,
    /// # ];
    /// # let read_debug_info_section_somehow = || &info_buf;
    /// let debug_info = DebugInfo::<LittleEndian>::new(read_debug_info_section_somehow());
    ///
    /// // Get the data about the first compilation unit out of the `.debug_info`.
    ///
    /// let unit = debug_info.compilation_units().next()
    ///     .expect("Should have at least one compilation unit")
    ///     .expect("and it should parse ok");
    ///
    /// // Get the first entry from that compilation unit.
    ///
    /// let mut cursor = unit.entries(&abbrevs);
    /// let entry = cursor.current()
    ///     .expect("Should have at least one entry")
    ///     .expect("and it should parse ok");
    ///
    /// // Finally, print the first entry's attributes.
    ///
    /// for attr_result in entry.attrs() {
    ///     let attr = attr_result.unwrap();
    ///
    ///     println!("Attribute name = {:?}", attr.name());
    ///     println!("Attribute value = {:?}", attr.value());
    /// }
    /// ```
    pub fn attrs<'me>(&'me self) -> AttrsIter<'input, 'abbrev, 'me, 'unit, Endian> {
        AttrsIter {
            input: self.attrs_slice,
            attributes: &self.abbrev.attributes[..],
            entry: self,
        }
    }
}

/// The value of an attribute in a `DebuggingInformationEntry`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttributeValue<'input> {
    /// A slice that is CompilationUnitHeader::address_size bytes long.
    Addr(&'input [u8]),

    /// A slice of an arbitrary number of bytes.
    Block(&'input [u8]),

    /// A one, two, four, or eight byte constant data value. How to interpret
    /// the bytes depends on context.
    ///
    /// From section 7 of the standard: "Depending on context, it may be a
    /// signed integer, an unsigned integer, a floating-point constant, or
    /// anything else."
    Data(&'input [u8]),

    /// A signed integer constant.
    Sdata(i64),

    /// An unsigned integer constant.
    Udata(u64),

    /// "The information bytes contain a DWARF expression (see Section 2.5) or
    /// location description (see Section 2.6)."
    Exprloc(&'input [u8]),

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
    String(&'input [u8]),
}

/// An attribute in a `DebuggingInformationEntry`, consisting of a name and
/// associated value.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Attribute<'input> {
    name: AttributeName,
    value: AttributeValue<'input>,
}

impl<'input> Attribute<'input> {
    /// Get this attribute's name.
    pub fn name(&self) -> AttributeName {
        self.name
    }

    /// Get this attribute's value.
    pub fn value(&self) -> AttributeValue<'input> {
        self.value
    }
}

/// The input to parsing an attribute.
#[derive(Clone, Copy, Debug)]
pub struct AttributeInput<'input, 'unit, Endian>(EndianBuf<'input, Endian>,
                                                 &'unit CompilationUnit<'input, Endian>,
                                                 AttributeSpecification)
    where 'input: 'unit,
          Endian: Endianity + 'unit;

impl<'input, 'unit, Endian> AttributeInput<'input, 'unit, Endian>
    where Endian: Endianity
{
    fn merge<T>(&self, rest: T) -> AttributeInput<'input, 'unit, Endian>
        where T: Into<&'input [u8]>
    {
        let buf = rest.into();
        AttributeInput(EndianBuf::new(buf), self.1, self.2)
    }

    fn range_from(&self, range: RangeFrom<usize>) -> AttributeInput<'input, 'unit, Endian> {
        AttributeInput(self.0.range_from(range), self.1, self.2)
    }
}

impl<'input, 'unit, Endian> Deref for AttributeInput<'input, 'unit, Endian>
    where Endian: Endianity
{
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        (self.0).0
    }
}

impl<'input, 'unit, Endian> Into<&'input [u8]> for AttributeInput<'input, 'unit, Endian>
    where Endian: Endianity
{
    fn into(self) -> &'input [u8] {
        self.0.into()
    }
}

impl<'input, 'unit, Endian> Into<EndianBuf<'input, Endian>> for AttributeInput<'input,
                                                                               'unit,
                                                                               Endian>
    where Endian: Endianity
{
    fn into(self) -> EndianBuf<'input, Endian> {
        self.0
    }
}

/// Take a slice of size `bytes` from the input.
fn take(bytes: usize, input: &[u8]) -> ParseResult<(&[u8], &[u8])> {
    if input.len() < bytes {
        Err(Error::UnexpectedEof)
    } else {
        Ok((&input[bytes..], &input[0..bytes]))
    }
}

fn length_u8_value(input: &[u8]) -> ParseResult<(&[u8], &[u8])> {
    let (rest, len) = try!(parse_u8(input));
    take(len as usize, rest)
}

fn length_u16_value<'input, Endian>(input: EndianBuf<'input, Endian>)
                                    -> ParseResult<(EndianBuf<'input, Endian>, &'input [u8])>
    where Endian: Endianity
{
    let (rest, len) = try!(parse_u16(input));
    take(len as usize, rest.into()).map(|(rest, result)| (EndianBuf::new(rest), result))
}

fn length_u32_value<'input, Endian>(input: EndianBuf<'input, Endian>)
                                    -> ParseResult<(EndianBuf<'input, Endian>, &'input [u8])>
    where Endian: Endianity
{
    let (rest, len) = try!(parse_u32(input));
    take(len as usize, rest.into()).map(|(rest, result)| (EndianBuf::new(rest), result))
}

fn length_leb_value(input: &[u8]) -> ParseResult<(&[u8], &[u8])> {
    let (rest, len) = try!(parse_unsigned_leb(input));
    take(len as usize, rest)
}

fn parse_attribute<'input, 'unit, Endian>
    (mut input: AttributeInput<'input, 'unit, Endian>)
     -> ParseResult<(AttributeInput<'input, 'unit, Endian>, Attribute<'input>)>
    where Endian: Endianity
{
    let mut form = input.2.form;
    loop {
        match form {
            AttributeForm::Indirect => {
                let (rest, dynamic_form) = try!(parse_attribute_form(input.into()));
                form = dynamic_form;
                input = input.merge(rest);
                continue;
            }
            AttributeForm::Addr => {
                return take(input.1.address_size() as usize, input.into()).map(|(rest, addr)| {
                    let attr = Attribute {
                        name: input.2.name,
                        value: AttributeValue::Addr(addr),
                    };
                    (input.merge(rest), attr)
                });
            }
            AttributeForm::Block1 => {
                return length_u8_value(input.into()).map(|(rest, block)| {
                    let attr = Attribute {
                        name: input.2.name,
                        value: AttributeValue::Block(block),
                    };
                    (input.merge(rest), attr)
                });
            }
            AttributeForm::Block2 => {
                return length_u16_value(input.into()).map(|(rest, block)| {
                    let attr = Attribute {
                        name: input.2.name,
                        value: AttributeValue::Block(block),
                    };
                    (input.merge(rest), attr)
                });
            }
            AttributeForm::Block4 => {
                return length_u32_value(input.into()).map(|(rest, block)| {
                    let attr = Attribute {
                        name: input.2.name,
                        value: AttributeValue::Block(block),
                    };
                    (input.merge(rest), attr)
                });
            }
            AttributeForm::Block => {
                return length_leb_value(input.into()).map(|(rest, block)| {
                    let attr = Attribute {
                        name: input.2.name,
                        value: AttributeValue::Block(block),
                    };
                    (input.merge(rest), attr)
                });
            }
            AttributeForm::Data1 => {
                return take(1, input.into()).map(|(rest, data)| {
                    let attr = Attribute {
                        name: input.2.name,
                        value: AttributeValue::Data(data),
                    };
                    (input.merge(rest), attr)
                });
            }
            AttributeForm::Data2 => {
                return take(2, input.into()).map(|(rest, data)| {
                    let attr = Attribute {
                        name: input.2.name,
                        value: AttributeValue::Data(data),
                    };
                    (input.merge(rest), attr)
                });
            }
            AttributeForm::Data4 => {
                return take(4, input.into()).map(|(rest, data)| {
                    let attr = Attribute {
                        name: input.2.name,
                        value: AttributeValue::Data(data),
                    };
                    (input.merge(rest), attr)
                });
            }
            AttributeForm::Data8 => {
                return take(8, input.into()).map(|(rest, data)| {
                    let attr = Attribute {
                        name: input.2.name,
                        value: AttributeValue::Data(data),
                    };
                    (input.merge(rest), attr)
                });
            }
            AttributeForm::Udata => {
                return parse_unsigned_leb(input.into()).map(|(rest, data)| {
                    let attr = Attribute {
                        name: input.2.name,
                        value: AttributeValue::Udata(data),
                    };
                    (input.merge(rest), attr)
                });
            }
            AttributeForm::Sdata => {
                return parse_signed_leb(input.into()).map(|(rest, data)| {
                    let attr = Attribute {
                        name: input.2.name,
                        value: AttributeValue::Sdata(data),
                    };
                    (input.merge(rest), attr)
                });
            }
            AttributeForm::Exprloc => {
                return length_leb_value(input.into()).map(|(rest, block)| {
                    let attr = Attribute {
                        name: input.2.name,
                        value: AttributeValue::Exprloc(block),
                    };
                    (input.merge(rest), attr)
                })
            }
            AttributeForm::Flag => {
                return parse_u8(input.into()).map(|(rest, present)| {
                    let attr = Attribute {
                        name: input.2.name,
                        value: AttributeValue::Flag(present != 0),
                    };
                    (input.merge(rest), attr)
                })
            }
            AttributeForm::FlagPresent => {
                // FlagPresent is this weird compile time always true thing that
                // isn't actually present in the serialized DIEs, only in Ok(
                return Ok((input,
                           Attribute {
                    name: input.2.name,
                    value: AttributeValue::Flag(true),
                }));
            }
            AttributeForm::SecOffset => {
                return match input.1.format() {
                    Format::Dwarf32 => {
                        parse_u32(input.into()).map(|(rest, offset)| {
                            let attr = Attribute {
                                name: input.2.name,
                                value: AttributeValue::SecOffset(offset as u64),
                            };
                            (input.merge(rest), attr)
                        })
                    }
                    Format::Dwarf64 => {
                        parse_u64(input.into()).map(|(rest, offset)| {
                            let attr = Attribute {
                                name: input.2.name,
                                value: AttributeValue::SecOffset(offset),
                            };
                            (input.merge(rest), attr)
                        })
                    }
                };
            }
            AttributeForm::Ref1 => {
                return parse_u8(input.into()).map(|(rest, reference)| {
                    let attr = Attribute {
                        name: input.2.name,
                        value: AttributeValue::UnitRef(UnitOffset(reference as u64)),
                    };
                    (input.merge(rest), attr)
                });
            }
            AttributeForm::Ref2 => {
                return parse_u16(input.into()).map(|(rest, reference)| {
                    let attr = Attribute {
                        name: input.2.name,
                        value: AttributeValue::UnitRef(UnitOffset(reference as u64)),
                    };
                    (input.merge(rest), attr)
                });
            }
            AttributeForm::Ref4 => {
                return parse_u32(input.into()).map(|(rest, reference)| {
                    let attr = Attribute {
                        name: input.2.name,
                        value: AttributeValue::UnitRef(UnitOffset(reference as u64)),
                    };
                    (input.merge(rest), attr)
                });
            }
            AttributeForm::Ref8 => {
                return parse_u64(input.into()).map(|(rest, reference)| {
                    let attr = Attribute {
                        name: input.2.name,
                        value: AttributeValue::UnitRef(UnitOffset(reference)),
                    };
                    (input.merge(rest), attr)
                });
            }
            AttributeForm::RefUdata => {
                return parse_unsigned_leb(input.into()).map(|(rest, reference)| {
                    let attr = Attribute {
                        name: input.2.name,
                        value: AttributeValue::UnitRef(UnitOffset(reference)),
                    };
                    (input.merge(rest), attr)
                });
            }
            AttributeForm::RefAddr => {
                return match input.1.format() {
                    Format::Dwarf32 => {
                        parse_u32(input.into()).map(|(rest, offset)| {
                            let offset = DebugInfoOffset(offset as u64);
                            let attr = Attribute {
                                name: input.2.name,
                                value: AttributeValue::DebugInfoRef(offset),
                            };
                            (input.merge(rest), attr)
                        })
                    }
                    Format::Dwarf64 => {
                        parse_u64(input.into()).map(|(rest, offset)| {
                            let offset = DebugInfoOffset(offset);
                            let attr = Attribute {
                                name: input.2.name,
                                value: AttributeValue::DebugInfoRef(offset),
                            };
                            (input.merge(rest), attr)
                        })
                    }
                };
            }
            AttributeForm::RefSig8 => {
                return parse_u64(input.into()).map(|(rest, offset)| {
                    let offset = DebugTypesOffset(offset);
                    let attr = Attribute {
                        name: input.2.name,
                        value: AttributeValue::DebugTypesRef(offset),
                    };
                    (input.merge(rest), attr)
                });
            }
            AttributeForm::String => {
                let null_idx = input.iter().position(|ch| *ch == 0);

                if let Some(idx) = null_idx {
                    let buf: &[u8] = input.into();
                    return Ok((input.range_from(idx + 1..),
                               Attribute {
                        name: input.2.name,
                        value: AttributeValue::String(&buf[0..idx + 1]),
                    }));
                } else {
                    return Err(Error::UnexpectedEof);
                }
            }
            AttributeForm::Strp => {
                return match input.1.format() {
                    Format::Dwarf32 => {
                        parse_u32(input.into()).map(|(rest, offset)| {
                            let offset = DebugStrOffset(offset as u64);
                            let attr = Attribute {
                                name: input.2.name,
                                value: AttributeValue::DebugStrRef(offset),
                            };
                            (input.merge(rest), attr)
                        })
                    }
                    Format::Dwarf64 => {
                        parse_u64(input.into()).map(|(rest, offset)| {
                            let offset = DebugStrOffset(offset);
                            let attr = Attribute {
                                name: input.2.name,
                                value: AttributeValue::DebugStrRef(offset),
                            };
                            (input.merge(rest), attr)
                        })
                    }
                };
            }
        };
    }
}

#[test]
fn test_parse_attribute_addr() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    let unit = CompilationUnit::<LittleEndian>::new(7,
                                                    4,
                                                    DebugAbbrevOffset(0x08070605),
                                                    4,
                                                    Format::Dwarf32,
                                                    &[]);

    let spec = AttributeSpecification {
        name: AttributeName::LowPc,
        form: AttributeForm::Addr,
    };

    let input = AttributeInput(EndianBuf::new(&buf), &unit, spec);

    match parse_attribute(input) {
        Ok((rest, attr)) => {
            assert_eq!(attr,
                       Attribute {
                           name: AttributeName::LowPc,
                           value: AttributeValue::Addr(&buf[..4]),
                       });
            assert_eq!(rest.0, EndianBuf::new(&buf[4..]));
        }
        otherwise => {
            println!("Unexpected parse result = {:#?}", otherwise);
            assert!(false);
        }
    };
}

#[test]
fn test_parse_attribute_block1() {
    // Length of data (3), three bytes of data, two bytes of left over input.
    let buf = [0x03, 0x09, 0x09, 0x09, 0x00, 0x00];

    let unit = CompilationUnit::<LittleEndian>::new(7,
                                                    4,
                                                    DebugAbbrevOffset(0x08070605),
                                                    4,
                                                    Format::Dwarf32,
                                                    &[]);

    let spec = AttributeSpecification {
        name: AttributeName::Name,
        form: AttributeForm::Block1,
    };

    let input = AttributeInput(EndianBuf::new(&buf), &unit, spec);

    match parse_attribute(input) {
        Ok((rest, attr)) => {
            assert_eq!(attr,
                       Attribute {
                           name: AttributeName::Name,
                           value: AttributeValue::Block(&buf[1..4]),
                       });
            assert_eq!(rest.0, EndianBuf::new(&buf[4..]));
        }
        otherwise => {
            println!("Unexpected parse result = {:#?}", otherwise);
            assert!(false);
        }
    };
}

#[test]
fn test_parse_attribute_block2() {
    // Two byte length of data (2), two bytes of data, two bytes of left over input.
    let buf = [0x02, 0x00, 0x09, 0x09, 0x00, 0x00];

    let unit = CompilationUnit::<LittleEndian>::new(7,
                                                    4,
                                                    DebugAbbrevOffset(0x08070605),
                                                    4,
                                                    Format::Dwarf32,
                                                    &[]);

    let spec = AttributeSpecification {
        name: AttributeName::Name,
        form: AttributeForm::Block2,
    };

    let input = AttributeInput(EndianBuf::new(&buf), &unit, spec);

    match parse_attribute(input) {
        Ok((rest, attr)) => {
            assert_eq!(attr,
                       Attribute {
                           name: AttributeName::Name,
                           value: AttributeValue::Block(&buf[2..4]),
                       });
            assert_eq!(rest.0, EndianBuf::new(&buf[4..]));
        }
        otherwise => {
            println!("Unexpected parse result = {:#?}", otherwise);
            assert!(false);
        }
    };
}

#[test]
fn test_parse_attribute_block4() {
    // Four byte length of data (2), two bytes of data, no left over input.
    let buf = [0x02, 0x00, 0x00, 0x00, 0x99, 0x99];

    let unit = CompilationUnit::<LittleEndian>::new(7,
                                                    4,
                                                    DebugAbbrevOffset(0x08070605),
                                                    4,
                                                    Format::Dwarf32,
                                                    &[]);

    let spec = AttributeSpecification {
        name: AttributeName::Name,
        form: AttributeForm::Block4,
    };

    let input = AttributeInput(EndianBuf::new(&buf), &unit, spec);

    match parse_attribute(input) {
        Ok((rest, attr)) => {
            assert_eq!(attr,
                       Attribute {
                           name: AttributeName::Name,
                           value: AttributeValue::Block(&buf[4..]),
                       });
            assert_eq!(rest.0, EndianBuf::new(&buf[..0]));
        }
        otherwise => {
            println!("Unexpected parse result = {:#?}", otherwise);
            assert!(false);
        }
    };
}

#[test]
fn test_parse_attribute_block() {
    // LEB length of data (2, one byte), two bytes of data, no left over input.
    let buf = [0x02, 0x99, 0x99];

    let unit = CompilationUnit::<LittleEndian>::new(7,
                                                    4,
                                                    DebugAbbrevOffset(0x08070605),
                                                    4,
                                                    Format::Dwarf32,
                                                    &[]);

    let spec = AttributeSpecification {
        name: AttributeName::Name,
        form: AttributeForm::Block,
    };

    let input = AttributeInput(EndianBuf::new(&buf), &unit, spec);

    match parse_attribute(input) {
        Ok((rest, attr)) => {
            assert_eq!(attr,
                       Attribute {
                           name: AttributeName::Name,
                           value: AttributeValue::Block(&buf[1..]),
                       });
            assert_eq!(rest.0, EndianBuf::new(&buf[..0]));
        }
        otherwise => {
            println!("Unexpected parse result = {:#?}", otherwise);
            assert!(false);
        }
    };
}

#[test]
fn test_parse_attribute_data1() {
    let buf = [0x03];

    let unit = CompilationUnit::<LittleEndian>::new(7,
                                                    4,
                                                    DebugAbbrevOffset(0x08070605),
                                                    4,
                                                    Format::Dwarf32,
                                                    &[]);

    let spec = AttributeSpecification {
        name: AttributeName::Name,
        form: AttributeForm::Data1,
    };

    let input = AttributeInput(EndianBuf::new(&buf), &unit, spec);

    match parse_attribute(input) {
        Ok((_, attr)) => {
            assert_eq!(attr,
                       Attribute {
                           name: AttributeName::Name,
                           value: AttributeValue::Data(&buf[..]),
                       });
        }
        otherwise => {
            println!("Unexpected parse result = {:#?}", otherwise);
            assert!(false);
        }
    };
}

#[test]
fn test_parse_attribute_data2() {
    let buf = [0x02, 0x01, 0x0];

    let unit = CompilationUnit::<LittleEndian>::new(7,
                                                    4,
                                                    DebugAbbrevOffset(0x08070605),
                                                    4,
                                                    Format::Dwarf32,
                                                    &[]);

    let spec = AttributeSpecification {
        name: AttributeName::Name,
        form: AttributeForm::Data2,
    };

    let input = AttributeInput(EndianBuf::new(&buf), &unit, spec);

    match parse_attribute(input) {
        Ok((rest, attr)) => {
            assert_eq!(attr,
                       Attribute {
                           name: AttributeName::Name,
                           value: AttributeValue::Data(&buf[..2]),
                       });
            assert_eq!(rest.0, EndianBuf::new(&buf[2..]));
        }
        otherwise => {
            println!("Unexpected parse result = {:#?}", otherwise);
            assert!(false);
        }
    };
}

#[test]
fn test_parse_attribute_data4() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x99, 0x99];

    let unit = CompilationUnit::<LittleEndian>::new(7,
                                                    4,
                                                    DebugAbbrevOffset(0x08070605),
                                                    4,
                                                    Format::Dwarf32,
                                                    &[]);

    let spec = AttributeSpecification {
        name: AttributeName::Name,
        form: AttributeForm::Data4,
    };

    let input = AttributeInput(EndianBuf::new(&buf), &unit, spec);

    match parse_attribute(input) {
        Ok((rest, attr)) => {
            assert_eq!(attr,
                       Attribute {
                           name: AttributeName::Name,
                           value: AttributeValue::Data(&buf[..4]),
                       });
            assert_eq!(rest.0, EndianBuf::new(&buf[4..]));
        }
        otherwise => {
            println!("Unexpected parse result = {:#?}", otherwise);
            assert!(false);
        }
    };
}

#[test]
fn test_parse_attribute_data8() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x99, 0x99];

    let unit = CompilationUnit::<LittleEndian>::new(7,
                                                    8,
                                                    DebugAbbrevOffset(0x08070605),
                                                    8,
                                                    Format::Dwarf32,
                                                    &[]);

    let spec = AttributeSpecification {
        name: AttributeName::Name,
        form: AttributeForm::Data8,
    };

    let input = AttributeInput(EndianBuf::new(&buf), &unit, spec);

    match parse_attribute(input) {
        Ok((rest, attr)) => {
            assert_eq!(attr,
                       Attribute {
                           name: AttributeName::Name,
                           value: AttributeValue::Data(&buf[..8]),
                       });
            assert_eq!(rest.0, EndianBuf::new(&buf[8..]));
        }
        otherwise => {
            println!("Unexpected parse result = {:#?}", otherwise);
            assert!(false);
        }
    };
}

#[test]
fn test_parse_attribute_udata() {
    let mut buf = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    let bytes_written = {
        let mut writable = &mut buf[..];
        leb128::write::unsigned(&mut writable, 4097).expect("should write ok")
    };

    let unit = CompilationUnit::<LittleEndian>::new(7,
                                                    8,
                                                    DebugAbbrevOffset(0x08070605),
                                                    8,
                                                    Format::Dwarf32,
                                                    &[]);

    let spec = AttributeSpecification {
        name: AttributeName::Name,
        form: AttributeForm::Udata,
    };

    let input = AttributeInput(EndianBuf::new(&buf), &unit, spec);

    match parse_attribute(input) {
        Ok((rest, attr)) => {
            assert_eq!(attr,
                       Attribute {
                           name: AttributeName::Name,
                           value: AttributeValue::Udata(4097),
                       });
            assert_eq!(rest.0, EndianBuf::new(&buf[bytes_written..]));
        }
        otherwise => {
            println!("Unexpected parse result = {:#?}", otherwise);
            assert!(false);
        }
    };
}

#[test]
fn test_parse_attribute_sdata() {
    let mut buf = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    let bytes_written = {
        let mut writable = &mut buf[..];
        leb128::write::signed(&mut writable, -4097).expect("should write ok")
    };

    let unit = CompilationUnit::<LittleEndian>::new(7,
                                                    8,
                                                    DebugAbbrevOffset(0x08070605),
                                                    8,
                                                    Format::Dwarf32,
                                                    &[]);

    let spec = AttributeSpecification {
        name: AttributeName::Name,
        form: AttributeForm::Sdata,
    };

    let input = AttributeInput(EndianBuf::new(&buf), &unit, spec);

    match parse_attribute(input) {
        Ok((rest, attr)) => {
            assert_eq!(attr,
                       Attribute {
                           name: AttributeName::Name,
                           value: AttributeValue::Sdata(-4097),
                       });
            assert_eq!(rest.0, EndianBuf::new(&buf[bytes_written..]));
        }
        otherwise => {
            println!("Unexpected parse result = {:#?}", otherwise);
            assert!(false);
        }
    };
}

#[test]
fn test_parse_attribute_exprloc() {
    // LEB length of data (2, one byte), two bytes of data, one byte left over input.
    let buf = [0x02, 0x99, 0x99, 0x11];

    let unit = CompilationUnit::<LittleEndian>::new(7,
                                                    4,
                                                    DebugAbbrevOffset(0x08070605),
                                                    4,
                                                    Format::Dwarf32,
                                                    &[]);

    let spec = AttributeSpecification {
        name: AttributeName::Name,
        form: AttributeForm::Exprloc,
    };

    let input = AttributeInput(EndianBuf::new(&buf), &unit, spec);

    match parse_attribute(input) {
        Ok((rest, attr)) => {
            assert_eq!(attr,
                       Attribute {
                           name: AttributeName::Name,
                           value: AttributeValue::Exprloc(&buf[1..3]),
                       });
            assert_eq!(rest.0, EndianBuf::new(&buf[3..]));
        }
        otherwise => {
            println!("Unexpected parse result = {:#?}", otherwise);
            assert!(false);
        }
    };
}

#[test]
fn test_parse_attribute_flag_true() {
    let buf = [0x42];

    let unit = CompilationUnit::<LittleEndian>::new(7,
                                                    4,
                                                    DebugAbbrevOffset(0x08070605),
                                                    4,
                                                    Format::Dwarf32,
                                                    &[]);

    let spec = AttributeSpecification {
        name: AttributeName::Name,
        form: AttributeForm::Flag,
    };

    let input = AttributeInput(EndianBuf::new(&buf), &unit, spec);

    match parse_attribute(input) {
        Ok((_, attr)) => {
            assert_eq!(attr,
                       Attribute {
                           name: AttributeName::Name,
                           value: AttributeValue::Flag(true),
                       });
        }
        otherwise => {
            println!("Unexpected parse result = {:#?}", otherwise);
            assert!(false);
        }
    };
}

#[test]
fn test_parse_attribute_flag_false() {
    let buf = [0x00];

    let unit = CompilationUnit::<LittleEndian>::new(7,
                                                    4,
                                                    DebugAbbrevOffset(0x08070605),
                                                    4,
                                                    Format::Dwarf32,
                                                    &[]);

    let spec = AttributeSpecification {
        name: AttributeName::Name,
        form: AttributeForm::Flag,
    };

    let input = AttributeInput(EndianBuf::new(&buf), &unit, spec);

    match parse_attribute(input) {
        Ok((_, attr)) => {
            assert_eq!(attr,
                       Attribute {
                           name: AttributeName::Name,
                           value: AttributeValue::Flag(false),
                       });
        }
        otherwise => {
            println!("Unexpected parse result = {:#?}", otherwise);
            assert!(false);
        }
    };
}

#[test]
fn test_parse_attribute_flag_present() {
    let buf = [0x01, 0x02, 0x03, 0x04];

    let unit = CompilationUnit::<LittleEndian>::new(7,
                                                    4,
                                                    DebugAbbrevOffset(0x08070605),
                                                    4,
                                                    Format::Dwarf32,
                                                    &[]);

    let spec = AttributeSpecification {
        name: AttributeName::Name,
        form: AttributeForm::FlagPresent,
    };

    let input = AttributeInput(EndianBuf::new(&buf), &unit, spec);

    match parse_attribute(input) {
        Ok((rest, attr)) => {
            assert_eq!(attr,
                       Attribute {
                           name: AttributeName::Name,
                           value: AttributeValue::Flag(true),
                       });
            // DW_FORM_flag_present does not consume any bytes of the input
            // stream.
            assert_eq!(rest.0, EndianBuf::new(&buf[..]));
        }
        otherwise => {
            println!("Unexpected parse result = {:#?}", otherwise);
            assert!(false);
        }
    };
}

#[test]
fn test_parse_attribute_sec_offset_32() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10];

    let unit = CompilationUnit::<LittleEndian>::new(7,
                                                    4,
                                                    DebugAbbrevOffset(0x08070605),
                                                    4,
                                                    Format::Dwarf32,
                                                    &[]);

    let spec = AttributeSpecification {
        name: AttributeName::Name,
        form: AttributeForm::SecOffset,
    };

    let input = AttributeInput(EndianBuf::new(&buf), &unit, spec);

    match parse_attribute(input) {
        Ok((rest, attr)) => {
            assert_eq!(attr,
                       Attribute {
                           name: AttributeName::Name,
                           value: AttributeValue::SecOffset(0x04030201),
                       });
            assert_eq!(rest.0, EndianBuf::new(&buf[4..]));
        }
        otherwise => {
            println!("Unexpected parse result = {:#?}", otherwise);
            assert!(false);
        }
    };
}

#[test]
fn test_parse_attribute_sec_offset_64() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10];

    let unit = CompilationUnit::<LittleEndian>::new(7,
                                                    4,
                                                    DebugAbbrevOffset(0x08070605),
                                                    4,
                                                    Format::Dwarf64,
                                                    &[]);

    let spec = AttributeSpecification {
        name: AttributeName::Name,
        form: AttributeForm::SecOffset,
    };

    let input = AttributeInput(EndianBuf::new(&buf), &unit, spec);

    match parse_attribute(input) {
        Ok((rest, attr)) => {
            assert_eq!(attr,
                       Attribute {
                           name: AttributeName::Name,
                           value: AttributeValue::SecOffset(0x0807060504030201),
                       });
            assert_eq!(rest.0, EndianBuf::new(&buf[8..]));
        }
        otherwise => {
            println!("Unexpected parse result = {:#?}", otherwise);
            assert!(false);
        }
    };
}

#[test]
fn test_parse_attribute_ref1() {
    let buf = [0x03];

    let unit = CompilationUnit::<LittleEndian>::new(7,
                                                    4,
                                                    DebugAbbrevOffset(0x08070605),
                                                    4,
                                                    Format::Dwarf32,
                                                    &[]);

    let spec = AttributeSpecification {
        name: AttributeName::Name,
        form: AttributeForm::Ref1,
    };

    let input = AttributeInput(EndianBuf::new(&buf), &unit, spec);

    match parse_attribute(input) {
        Ok((_, attr)) => {
            assert_eq!(attr,
                       Attribute {
                           name: AttributeName::Name,
                           value: AttributeValue::UnitRef(UnitOffset(3)),
                       });
        }
        otherwise => {
            println!("Unexpected parse result = {:#?}", otherwise);
            assert!(false);
        }
    };
}

#[test]
fn test_parse_attribute_ref2() {
    let buf = [0x02, 0x01, 0x0];

    let unit = CompilationUnit::<LittleEndian>::new(7,
                                                    4,
                                                    DebugAbbrevOffset(0x08070605),
                                                    4,
                                                    Format::Dwarf32,
                                                    &[]);

    let spec = AttributeSpecification {
        name: AttributeName::Name,
        form: AttributeForm::Ref2,
    };

    let input = AttributeInput(EndianBuf::new(&buf), &unit, spec);

    match parse_attribute(input) {
        Ok((rest, attr)) => {
            assert_eq!(attr,
                       Attribute {
                           name: AttributeName::Name,
                           value: AttributeValue::UnitRef(UnitOffset(258)),
                       });
            assert_eq!(rest.0, EndianBuf::new(&buf[2..]));
        }
        otherwise => {
            println!("Unexpected parse result = {:#?}", otherwise);
            assert!(false);
        }
    };
}

#[test]
fn test_parse_attribute_ref4() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x99, 0x99];

    let unit = CompilationUnit::<LittleEndian>::new(7,
                                                    4,
                                                    DebugAbbrevOffset(0x08070605),
                                                    4,
                                                    Format::Dwarf32,
                                                    &[]);

    let spec = AttributeSpecification {
        name: AttributeName::Name,
        form: AttributeForm::Ref4,
    };

    let input = AttributeInput(EndianBuf::new(&buf), &unit, spec);

    match parse_attribute(input) {
        Ok((rest, attr)) => {
            assert_eq!(attr,
                       Attribute {
                           name: AttributeName::Name,
                           value: AttributeValue::UnitRef(UnitOffset(67305985)),
                       });
            assert_eq!(rest.0, EndianBuf::new(&buf[4..]));
        }
        otherwise => {
            println!("Unexpected parse result = {:#?}", otherwise);
            assert!(false);
        }
    };
}

#[test]
fn test_parse_attribute_ref8() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x99, 0x99];

    let unit = CompilationUnit::<LittleEndian>::new(7,
                                                    8,
                                                    DebugAbbrevOffset(0x08070605),
                                                    8,
                                                    Format::Dwarf32,
                                                    &[]);

    let spec = AttributeSpecification {
        name: AttributeName::Name,
        form: AttributeForm::Ref8,
    };

    let input = AttributeInput(EndianBuf::new(&buf), &unit, spec);

    match parse_attribute(input) {
        Ok((rest, attr)) => {
            assert_eq!(attr,
                       Attribute {
                           name: AttributeName::Name,
                           value: AttributeValue::UnitRef(UnitOffset(578437695752307201)),
                       });
            assert_eq!(rest.0, EndianBuf::new(&buf[8..]));
        }
        otherwise => {
            println!("Unexpected parse result = {:#?}", otherwise);
            assert!(false);
        }
    };
}

#[test]
fn test_parse_attribute_refudata() {
    let mut buf = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    let bytes_written = {
        let mut writable = &mut buf[..];
        leb128::write::unsigned(&mut writable, 4097).expect("should write ok")
    };

    let unit = CompilationUnit::<LittleEndian>::new(7,
                                                    8,
                                                    DebugAbbrevOffset(0x08070605),
                                                    8,
                                                    Format::Dwarf32,
                                                    &[]);

    let spec = AttributeSpecification {
        name: AttributeName::Name,
        form: AttributeForm::RefUdata,
    };

    let input = AttributeInput(EndianBuf::new(&buf), &unit, spec);

    match parse_attribute(input) {
        Ok((rest, attr)) => {
            assert_eq!(attr,
                       Attribute {
                           name: AttributeName::Name,
                           value: AttributeValue::UnitRef(UnitOffset(4097)),
                       });
            assert_eq!(rest.0, EndianBuf::new(&buf[bytes_written..]));
        }
        otherwise => {
            println!("Unexpected parse result = {:#?}", otherwise);
            assert!(false);
        }
    };
}

#[test]
fn test_parse_attribute_refaddr_32() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x99, 0x99];

    let unit = CompilationUnit::<LittleEndian>::new(7,
                                                    8,
                                                    DebugAbbrevOffset(0x08070605),
                                                    8,
                                                    Format::Dwarf32,
                                                    &[]);

    let spec = AttributeSpecification {
        name: AttributeName::Name,
        form: AttributeForm::RefAddr,
    };

    let input = AttributeInput(EndianBuf::new(&buf), &unit, spec);

    match parse_attribute(input) {
        Ok((rest, attr)) => {
            assert_eq!(attr,
                       Attribute {
                           name: AttributeName::Name,
                           value: AttributeValue::DebugInfoRef(DebugInfoOffset(67305985)),
                       });
            assert_eq!(rest.0, EndianBuf::new(&buf[4..]));
        }
        otherwise => {
            println!("Unexpected parse result = {:#?}", otherwise);
            assert!(false);
        }
    };
}

#[test]
fn test_parse_attribute_refaddr_64() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x99, 0x99];

    let unit = CompilationUnit::<LittleEndian>::new(7,
                                                    8,
                                                    DebugAbbrevOffset(0x08070605),
                                                    8,
                                                    Format::Dwarf64,
                                                    &[]);

    let spec = AttributeSpecification {
        name: AttributeName::Name,
        form: AttributeForm::RefAddr,
    };

    let input = AttributeInput(EndianBuf::new(&buf), &unit, spec);

    match parse_attribute(input) {
        Ok((rest, attr)) => {
            assert_eq!(attr,
                       Attribute {
                           name: AttributeName::Name,
                           value: AttributeValue::DebugInfoRef(DebugInfoOffset(578437695752307201)),
                       });
            assert_eq!(rest.0, EndianBuf::new(&buf[8..]));
        }
        otherwise => {
            println!("Unexpected parse result = {:#?}", otherwise);
            assert!(false);
        }
    };
}

#[test]
fn test_parse_attribute_refsig8() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x99, 0x99];

    let unit = CompilationUnit::<LittleEndian>::new(7,
                                                    8,
                                                    DebugAbbrevOffset(0x08070605),
                                                    8,
                                                    Format::Dwarf64,
                                                    &[]);

    let spec = AttributeSpecification {
        name: AttributeName::Name,
        form: AttributeForm::RefSig8,
    };

    let input = AttributeInput(EndianBuf::new(&buf), &unit, spec);

    match parse_attribute(input) {
        Ok((rest, attr)) => {
            assert_eq!(attr,
                       Attribute {
                           name: AttributeName::Name,
                           value:
                               AttributeValue::DebugTypesRef(DebugTypesOffset(578437695752307201)),
                       });
            assert_eq!(rest.0, EndianBuf::new(&buf[8..]));
        }
        otherwise => {
            println!("Unexpected parse result = {:#?}", otherwise);
            assert!(false);
        }
    };
}

#[test]
fn test_parse_attribute_string() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x0, 0x99, 0x99];

    let unit = CompilationUnit::<LittleEndian>::new(7,
                                                    8,
                                                    DebugAbbrevOffset(0x08070605),
                                                    8,
                                                    Format::Dwarf64,
                                                    &[]);

    let spec = AttributeSpecification {
        name: AttributeName::Name,
        form: AttributeForm::String,
    };

    let input = AttributeInput(EndianBuf::new(&buf), &unit, spec);

    match parse_attribute(input) {
        Ok((rest, attr)) => {
            assert_eq!(attr,
                       Attribute {
                           name: AttributeName::Name,
                           value: AttributeValue::String(&buf[..6]),
                       });
            assert_eq!(rest.0, EndianBuf::new(&buf[6..]));
        }
        otherwise => {
            println!("Unexpected parse result = {:#?}", otherwise);
            assert!(false);
        }
    };
}

#[test]
fn test_parse_attribute_strp_32() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x99, 0x99];

    let unit = CompilationUnit::<LittleEndian>::new(7,
                                                    8,
                                                    DebugAbbrevOffset(0x08070605),
                                                    8,
                                                    Format::Dwarf32,
                                                    &[]);

    let spec = AttributeSpecification {
        name: AttributeName::Name,
        form: AttributeForm::Strp,
    };

    let input = AttributeInput(EndianBuf::new(&buf), &unit, spec);

    match parse_attribute(input) {
        Ok((rest, attr)) => {
            assert_eq!(attr,
                       Attribute {
                           name: AttributeName::Name,
                           value: AttributeValue::DebugStrRef(DebugStrOffset(67305985)),
                       });
            assert_eq!(rest.0, EndianBuf::new(&buf[4..]));
        }
        otherwise => {
            println!("Unexpected parse result = {:#?}", otherwise);
            assert!(false);
        }
    };
}

#[test]
fn test_parse_attribute_strp_64() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x99, 0x99];

    let unit = CompilationUnit::<LittleEndian>::new(7,
                                                    8,
                                                    DebugAbbrevOffset(0x08070605),
                                                    8,
                                                    Format::Dwarf64,
                                                    &[]);

    let spec = AttributeSpecification {
        name: AttributeName::Name,
        form: AttributeForm::Strp,
    };

    let input = AttributeInput(EndianBuf::new(&buf), &unit, spec);

    match parse_attribute(input) {
        Ok((rest, attr)) => {
            assert_eq!(attr,
                       Attribute {
                           name: AttributeName::Name,
                           value: AttributeValue::DebugStrRef(DebugStrOffset(578437695752307201)),
                       });
            assert_eq!(rest.0, EndianBuf::new(&buf[8..]));
        }
        otherwise => {
            println!("Unexpected parse result = {:#?}", otherwise);
            assert!(false);
        }
    };
}

#[test]
fn test_parse_attribute_indirect() {
    let mut buf = [0; 100];

    let bytes_written = {
        let mut writable = &mut buf[..];
        leb128::write::unsigned(&mut writable, AttributeForm::Udata as u64)
            .expect("should write udata") +
        leb128::write::unsigned(&mut writable, 9999999).expect("should write value")
    };

    let unit = CompilationUnit::<LittleEndian>::new(7,
                                                    8,
                                                    DebugAbbrevOffset(0x08070605),
                                                    8,
                                                    Format::Dwarf64,
                                                    &[]);

    let spec = AttributeSpecification {
        name: AttributeName::Name,
        form: AttributeForm::Indirect,
    };

    let input = AttributeInput(EndianBuf::new(&buf), &unit, spec);

    match parse_attribute(input) {
        Ok((rest, attr)) => {
            assert_eq!(attr,
                       Attribute {
                           name: AttributeName::Name,
                           value: AttributeValue::Udata(9999999),
                       });
            assert_eq!(rest.0, EndianBuf::new(&buf[bytes_written..]));
        }
        otherwise => {
            println!("Unexpected parse result = {:#?}", otherwise);
            assert!(false);
        }
    };
}

/// An iterator over a particular entry's attributes.
///
/// See [the documentation for
/// `DebuggingInformationEntry::attrs()`](./struct.DebuggingInformationEntry.html#method.attrs)
/// for details.
#[derive(Clone, Copy, Debug)]
pub struct AttrsIter<'input, 'abbrev, 'entry, 'unit, Endian>
    where 'input: 'entry + 'unit,
          'abbrev: 'entry,
          'unit: 'entry,
          Endian: Endianity + 'entry + 'unit
{
    input: &'input [u8],
    attributes: &'abbrev [AttributeSpecification],
    entry: &'entry DebuggingInformationEntry<'input, 'abbrev, 'unit, Endian>,
}

impl<'input, 'abbrev, 'entry, 'unit, Endian> Iterator for AttrsIter<'input,
                                                                    'abbrev,
                                                                    'entry,
                                                                    'unit,
                                                                    Endian>
    where Endian: Endianity
{
    type Item = ParseResult<Attribute<'input>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.attributes.len() == 0 {
            // Now that we have parsed all of the attributes, we know where
            // either (1) this entry's children start, if the abbreviation says
            // this entry has children; or (2) where this entry's siblings
            // begin.
            if let Some(end) = self.entry.after_attrs.get() {
                debug_assert!(end == self.input);
            } else {
                self.entry.after_attrs.set(Some(self.input));
            }

            return None;
        }

        let attr = self.attributes[0];
        self.attributes = &self.attributes[1..];
        match parse_attribute(AttributeInput(EndianBuf::new(self.input), self.entry.unit, attr)) {
            Ok((rest, attr)) => {
                self.input = rest.0.into();
                Some(Ok(attr))
            }
            Err(e) => {
                self.attributes = &[];
                Some(Err(e))
            }
        }
    }
}

#[test]
fn test_attrs_iter() {
    let unit = CompilationUnit::<LittleEndian>::new(7,
                                                    4,
                                                    DebugAbbrevOffset(0x08070605),
                                                    4,
                                                    Format::Dwarf32,
                                                    &[]);

    let abbrev = Abbreviation {
        code: 42,
        tag: AbbreviationTag::Subprogram,
        has_children: AbbreviationHasChildren::Yes,
        attributes: vec![
            AttributeSpecification {
                name: AttributeName::Name,
                form: AttributeForm::String,
            },
            AttributeSpecification {
                name: AttributeName::LowPc,
                form: AttributeForm::Addr,
            },
            AttributeSpecification {
                name: AttributeName::HighPc,
                form: AttributeForm::Addr,
            },
        ],
    };

    // "foo", 42, 1337, 4 dangling bytes of 0xaa where children would be
    let buf = [0x66, 0x6f, 0x6f, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x39, 0x05, 0x00, 0x00, 0xaa, 0xaa,
               0xaa, 0xaa];

    let entry = DebuggingInformationEntry {
        attrs_slice: &buf,
        after_attrs: Cell::new(None),
        code: 1,
        abbrev: &abbrev,
        unit: &unit,
    };

    let mut attrs = AttrsIter {
        input: &buf[..],
        attributes: &abbrev.attributes[..],
        entry: &entry,
    };

    match attrs.next() {
        Some(Ok(attr)) => {
            assert_eq!(attr,
                       Attribute {
                           name: AttributeName::Name,
                           value: AttributeValue::String(b"foo\0"),
                       });
        }
        otherwise => {
            println!("Unexpected parse result = {:#?}", otherwise);
            assert!(false);
        }
    }

    assert!(entry.after_attrs.get().is_none());

    match attrs.next() {
        Some(Ok(attr)) => {
            assert_eq!(attr,
                       Attribute {
                           name: AttributeName::LowPc,
                           value: AttributeValue::Addr(&[0x2a, 0x00, 0x00, 0x00]),
                       });
        }
        otherwise => {
            println!("Unexpected parse result = {:#?}", otherwise);
            assert!(false);
        }
    }

    assert!(entry.after_attrs.get().is_none());

    match attrs.next() {
        Some(Ok(attr)) => {
            assert_eq!(attr,
                       Attribute {
                           name: AttributeName::HighPc,
                           value: AttributeValue::Addr(&[0x39, 0x05, 0x00, 0x00]),
                       });
        }
        otherwise => {
            println!("Unexpected parse result = {:#?}", otherwise);
            assert!(false);
        }
    }

    assert!(entry.after_attrs.get().is_none());

    assert!(attrs.next().is_none());
    assert!(entry.after_attrs.get().is_some());
    assert_eq!(entry.after_attrs.get().expect("should have entry.after_attrs"),
               &buf[buf.len() - 4..])
}

/// A cursor into the Debugging Information Entries tree for a compilation unit.
///
/// The `EntriesCursor` can traverse the DIE tree in either DFS order, or skip
/// to the next sibling of the entry the cursor is currently pointing to.
#[derive(Clone, Debug)]
pub struct EntriesCursor<'input, 'abbrev, 'unit, Endian>
    where 'input: 'unit,
          Endian: Endianity + 'unit
{
    input: &'input [u8],
    unit: &'unit CompilationUnit<'input, Endian>,
    abbreviations: &'abbrev Abbreviations,
    cached_current: RefCell<Option<ParseResult<DebuggingInformationEntry<'input,
                                                                         'abbrev,
                                                                         'unit,
                                                                         Endian>>>>,
}

impl<'input, 'abbrev, 'unit, Endian> EntriesCursor<'input, 'abbrev, 'unit, Endian>
    where Endian: Endianity
{
    /// Get the entry that the cursor is currently pointing to.
    pub fn current<'me>
        (&'me mut self)
         -> Option<ParseResult<DebuggingInformationEntry<'input, 'abbrev, 'unit, Endian>>> {

        // First, check for a cached result.
        {
            let cached = self.cached_current.borrow();
            if let Some(ref cached) = *cached {
                debug_assert!(cached.is_ok());
                return Some(cached.clone());
            }
        }

        if self.input.len() == 0 {
            return None;
        }

        match parse_unsigned_leb(self.input) {
            Err(e) => Some(Err(e)),

            // Null abbreviation is the lack of an entry.
            Ok((_, 0)) => None,

            Ok((rest, code)) => {
                if let Some(abbrev) = self.abbreviations.get(code) {
                    let result = Some(Ok(DebuggingInformationEntry {
                        attrs_slice: rest,
                        after_attrs: Cell::new(None),
                        code: code,
                        abbrev: abbrev,
                        unit: self.unit,
                    }));

                    let mut cached = self.cached_current.borrow_mut();
                    debug_assert!(cached.is_none());
                    mem::replace(&mut *cached, result.clone());

                    result
                } else {
                    Some(Err(Error::UnknownAbbreviation))
                }
            }
        }
    }

    /// Move the cursor to the next DIE in the tree in DFS order.
    ///
    /// Upon successful movement of the cursor, return the delta traversal
    /// depth:
    ///
    ///   * If we moved down into the previous current entry's children, we get
    ///     `Some(1)`.
    ///
    ///   * If we moved to the previous current entry's sibling, we get
    ///     `Some(0)`.
    ///
    ///   * If the previous entry does not have any siblings and we move up to
    ///     its parent's next sibling, then we get `Some(-1)`. Note that if the
    ///     parent doesn't have a next sibling, then it could go up to the
    ///     parent's parent's next sibling and return `Some(-2)`, etc.
    ///
    /// If there is no next entry, then `None` is returned.
    ///
    /// Here is an example that finds the first entry in a compilation unit that
    /// does not have any children.
    ///
    /// ```
    /// # use gimli::{DebugAbbrev, DebugInfo, LittleEndian};
    /// # let abbrev_buf = [
    /// #     // Code
    /// #     0x01,
    /// #     // DW_TAG_subprogram
    /// #     0x2e,
    /// #     // DW_CHILDREN_yes
    /// #     0x01,
    /// #     // Begin attributes
    /// #       // Attribute name = DW_AT_name
    /// #       0x03,
    /// #       // Attribute form = DW_FORM_string
    /// #       0x08,
    /// #     // End attributes
    /// #     0x00,
    /// #     0x00,
    /// #     // Null terminator
    /// #     0x00
    /// # ];
    /// # let debug_abbrev = DebugAbbrev::<LittleEndian>::new(&abbrev_buf);
    /// # let get_abbrevs_for_compilation_unit = |_| debug_abbrev.abbreviations().unwrap();
    /// #
    /// # let info_buf = [
    /// #     // Comilation unit header
    /// #
    /// #     // 32-bit unit length = 25
    /// #     0x19, 0x00, 0x00, 0x00,
    /// #     // Version 4
    /// #     0x04, 0x00,
    /// #     // debug_abbrev_offset
    /// #     0x05, 0x06, 0x07, 0x08,
    /// #     // Address size
    /// #     0x04,
    /// #
    /// #     // DIEs
    /// #
    /// #     // Abbreviation code
    /// #     0x01,
    /// #     // Attribute of form DW_FORM_string = "foo\0"
    /// #     0x66, 0x6f, 0x6f, 0x00,
    /// #
    /// #       // Children
    /// #
    /// #       // Abbreviation code
    /// #       0x01,
    /// #       // Attribute of form DW_FORM_string = "foo\0"
    /// #       0x66, 0x6f, 0x6f, 0x00,
    /// #
    /// #         // Children
    /// #
    /// #         // Abbreviation code
    /// #         0x01,
    /// #         // Attribute of form DW_FORM_string = "foo\0"
    /// #         0x66, 0x6f, 0x6f, 0x00,
    /// #
    /// #           // Children
    /// #
    /// #           // End of children
    /// #           0x00,
    /// #
    /// #         // End of children
    /// #         0x00,
    /// #
    /// #       // End of children
    /// #       0x00,
    /// # ];
    /// # let debug_info = DebugInfo::<LittleEndian>::new(&info_buf);
    /// #
    /// # let get_some_compilation_unit = || debug_info.compilation_units().next().unwrap().unwrap();
    ///
    /// let unit = get_some_compilation_unit();
    /// let abbrevs = get_abbrevs_for_compilation_unit(&unit);
    ///
    /// let mut first_entry_with_no_children = None;
    /// let mut cursor = unit.entries(&abbrevs);
    ///
    /// // Keep looping while the cursor is moving deeper into the DIE tree.
    /// while let Some(delta_depth) = cursor.next_dfs() {
    ///     // 0 means we moved to a sibling, a negative number means we went back
    ///     // up to a parent's sibling. In either case, bail out of the loop because
    ///     //  we aren't going deeper into the tree anymore.
    ///     if delta_depth <= 0 {
    ///         break;
    ///     }
    ///
    ///     let current = cursor.current()
    ///         .expect("Should be at an entry")
    ///         .expect("And we should parse the entry ok");
    ///     first_entry_with_no_children = Some(current);
    /// }
    ///
    /// println!("The first entry with no children is {:?}",
    ///          first_entry_with_no_children.unwrap());
    /// ```
    pub fn next_dfs(&mut self) -> Option<isize> {
        match self.current() {
            Some(Ok(current)) => {
                self.input = if let Some(after_attrs) = current.after_attrs.get() {
                    after_attrs
                } else {
                    for _ in current.attrs() {
                    }
                    current.after_attrs
                        .get()
                        .expect("should have after_attrs after iterating attrs")
                };

                let mut delta_depth = if current.abbrev.has_children() {
                    1
                } else {
                    0
                };

                // Keep eating null entries that mark the end of an entry's
                // children.
                while self.input.len() > 0 && self.input[0] == 0 {
                    delta_depth -= 1;
                    self.input = &self.input[1..];
                }

                let mut cached_current = self.cached_current.borrow_mut();
                mem::replace(&mut *cached_current, None);

                if self.input.len() > 0 {
                    Some(delta_depth)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Move the cursor to the next sibling DIE of the current one.
    ///
    /// Returns `Some` when the cursor the cursor has been moved to the next
    /// sibling, `None` when there is no next sibling.
    ///
    /// After returning `None`, the cursor is exhausted.
    ///
    /// Here is an example that iterates over all of the direct children of the
    /// root entry:
    ///
    /// ```
    /// # use gimli::{DebugAbbrev, DebugInfo, LittleEndian};
    /// # let abbrev_buf = [
    /// #     // Code
    /// #     0x01,
    /// #     // DW_TAG_subprogram
    /// #     0x2e,
    /// #     // DW_CHILDREN_yes
    /// #     0x01,
    /// #     // Begin attributes
    /// #       // Attribute name = DW_AT_name
    /// #       0x03,
    /// #       // Attribute form = DW_FORM_string
    /// #       0x08,
    /// #     // End attributes
    /// #     0x00,
    /// #     0x00,
    /// #     // Null terminator
    /// #     0x00
    /// # ];
    /// # let debug_abbrev = DebugAbbrev::<LittleEndian>::new(&abbrev_buf);
    /// # let get_abbrevs_for_compilation_unit = |_| debug_abbrev.abbreviations().unwrap();
    /// #
    /// # let info_buf = [
    /// #     // Comilation unit header
    /// #
    /// #     // 32-bit unit length = 25
    /// #     0x19, 0x00, 0x00, 0x00,
    /// #     // Version 4
    /// #     0x04, 0x00,
    /// #     // debug_abbrev_offset
    /// #     0x05, 0x06, 0x07, 0x08,
    /// #     // Address size
    /// #     0x04,
    /// #
    /// #     // DIEs
    /// #
    /// #     // Abbreviation code
    /// #     0x01,
    /// #     // Attribute of form DW_FORM_string = "foo\0"
    /// #     0x66, 0x6f, 0x6f, 0x00,
    /// #
    /// #       // Children
    /// #
    /// #       // Abbreviation code
    /// #       0x01,
    /// #       // Attribute of form DW_FORM_string = "foo\0"
    /// #       0x66, 0x6f, 0x6f, 0x00,
    /// #
    /// #         // Children
    /// #
    /// #         // Abbreviation code
    /// #         0x01,
    /// #         // Attribute of form DW_FORM_string = "foo\0"
    /// #         0x66, 0x6f, 0x6f, 0x00,
    /// #
    /// #           // Children
    /// #
    /// #           // End of children
    /// #           0x00,
    /// #
    /// #         // End of children
    /// #         0x00,
    /// #
    /// #       // End of children
    /// #       0x00,
    /// # ];
    /// # let debug_info = DebugInfo::<LittleEndian>::new(&info_buf);
    /// #
    /// # let get_some_compilation_unit = || debug_info.compilation_units().next().unwrap().unwrap();
    ///
    /// let unit = get_some_compilation_unit();
    /// let abbrevs = get_abbrevs_for_compilation_unit(&unit);
    ///
    /// let mut cursor = unit.entries(&abbrevs);
    ///
    /// // Move the cursor to the root's first child.
    /// assert_eq!(cursor.next_dfs().unwrap(), 1);
    ///
    /// // Iterate the root's children.
    /// loop {
    ///     let current = cursor.current()
    ///         .expect("Should be at an entry")
    ///         .expect("And we should parse the entry ok");
    ///
    ///     println!("{:?} is a child of the root", current);
    ///
    ///     if cursor.next_sibling().is_none() {
    ///         break;
    ///     }
    /// }
    /// ```
    pub fn next_sibling(&mut self) -> Option<()> {
        match self.current() {
            Some(Ok(current)) => {
                let sibling_ptr = current.attrs()
                    .take_while(|res| res.is_ok())
                    .find(|res| res.unwrap().name() == AttributeName::Sibling);

                if let Some(sibling_ptr) = sibling_ptr {
                    if let AttributeValue::UnitRef(offset) = sibling_ptr.unwrap().value() {
                        if self.unit.is_valid_offset(offset) {
                            // Fast path: this entry has a DW_AT_sibling
                            // attribute pointing to its sibling.
                            self.input = &self.unit.range_from(offset..);
                            if self.input.len() > 0 && self.input[0] != 0 {
                                return Some(());
                            } else {
                                self.input = &[];
                                return None;
                            }
                        }
                    }
                }

                // Slow path: either the entry doesn't have a sibling pointer,
                // or the pointer is bogus. Do a DFS until we get to the next
                // sibling.

                let mut depth = 0;
                while let Some(delta_depth) = self.next_dfs() {
                    depth += delta_depth;

                    if depth == 0 && self.input[0] != 0 {
                        // We found the next sibling.
                        return Some(());
                    }

                    if depth < 0 {
                        // We moved up to the original entry's parent's (or
                        // parent's parent's, etc ...) siblings.
                        self.input = &[];
                        return None;
                    }
                }

                // No sibling found.
                self.input = &[];
                None
            }
            _ => {
                self.input = &[];
                None
            }
        }
    }
}

#[cfg(test)]
fn assert_entry_with_name<'input, 'abbrev, 'unit, Endian>(entry: DebuggingInformationEntry<'input,
                                                                                           'abbrev,
                                                                                           'unit,
                                                                                           Endian>,
                                                          name: &'static str)
    where Endian: Endianity
{
    let attr = entry.attrs()
        .find(|attr| attr.is_ok() && attr.unwrap().name() == AttributeName::Name)
        .expect("Should have found the name attribute")
        .expect("and it should parse ok");

    let mut with_null: Vec<u8> = name.as_bytes().into();
    with_null.push(0);

    assert_eq!(attr.value, AttributeValue::String(&with_null));
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
    // Comilation unit header

    // 32-bit unit length = 67
    0x43, 0x00, 0x00, 0x00,
    // Version 4
    0x04, 0x00,
    // debug_abbrev_offset
    0x05, 0x06, 0x07, 0x08,
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
    let abbrevs_buf = &ENTRIES_CURSOR_TESTS_ABBREV_BUF;
    let debug_abbrev = DebugAbbrev::<LittleEndian>::new(abbrevs_buf);

    let abbrevs = debug_abbrev.abbreviations()
        .expect("Should parse abbreviations");

    let info_buf = &ENTRIES_CURSOR_TESTS_DEBUG_INFO_BUF;
    let debug_info = DebugInfo::<LittleEndian>::new(info_buf);

    let unit = debug_info.compilation_units().next()
        .expect("should have a unit result")
        .expect("and it should be ok");

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
    let abbrevs_buf = &ENTRIES_CURSOR_TESTS_ABBREV_BUF;
    let debug_abbrev = DebugAbbrev::<LittleEndian>::new(abbrevs_buf);

    let abbrevs = debug_abbrev.abbreviations()
        .expect("Should parse abbreviations");

    let info_buf = &ENTRIES_CURSOR_TESTS_DEBUG_INFO_BUF;
    let debug_info = DebugInfo::<LittleEndian>::new(info_buf);

    let unit = debug_info.compilation_units().next()
        .expect("should have a unit result")
        .expect("and it should be ok");

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

    let abbrevs = debug_abbrev.abbreviations()
        .expect("Should parse abbreviations");

    let info_buf = [
        // Comilation unit header

        // 32-bit unit length = 56
        0x38, 0x00, 0x00, 0x00,
        // Version 4
        0x04, 0x00,
        // debug_abbrev_offset
        0x05, 0x06, 0x07, 0x08,
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

/// Parse a type unit header's unique type signature. Callers should handle
/// unique-ness checking.
fn parse_type_signature<'input, Endian>(input: EndianBuf<'input, Endian>)
                                        -> ParseResult<(EndianBuf<'input, Endian>, u64)>
    where Endian: Endianity
{
    parse_u64(input)
}

#[test]
fn test_parse_type_signature_ok() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    match parse_type_signature(EndianBuf::<LittleEndian>::new(&buf)) {
        Ok((_, val)) => assert_eq!(val, 0x0807060504030201),
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    }
}

#[test]
fn test_parse_type_signature_incomplete() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];

    match parse_type_signature(EndianBuf::<LittleEndian>::new(&buf)) {
        Err(Error::UnexpectedEof) => assert!(true),
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    }
}

/// Parse a type unit header's type offset.
fn parse_type_offset<'input, Endian>
    (input: FormatInput<'input, Endian>)
     -> ParseResult<(FormatInput<'input, Endian>, DebugTypesOffset)>
    where Endian: Endianity
{
    let result = match input.1 {
        Format::Dwarf32 => parse_u32_as_u64(input.into()),
        Format::Dwarf64 => parse_u64(input.into()),
    };

    result.map(|(rest, offset)| (input.merge(rest), DebugTypesOffset(offset)))
}

#[test]
fn test_parse_type_offset_32_ok() {
    let buf = [0x12, 0x34, 0x56, 0x78, 0x00];

    match parse_type_offset(FormatInput(EndianBuf::<LittleEndian>::new(&buf), Format::Dwarf32)) {
        Ok((rest, offset)) => {
            assert_eq!(rest.0.len(), 1);
            assert_eq!(rest.1, Format::Dwarf32);
            assert_eq!(DebugTypesOffset(0x78563412), offset);
        }
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    }
}

#[test]
fn test_parse_type_offset_64_ok() {
    let buf = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xff, 0x00];

    match parse_type_offset(FormatInput(EndianBuf::<LittleEndian>::new(&buf), Format::Dwarf64)) {
        Ok((rest, offset)) => {
            assert_eq!(rest.0.len(), 1);
            assert_eq!(rest.1, Format::Dwarf64);
            assert_eq!(DebugTypesOffset(0xffdebc9a78563412), offset);
        }
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    }
}

#[test]
fn test_parse_type_offset_incomplete() {
    // Need at least 4 bytes.
    let buf = [0xff, 0xff, 0xff];

    match parse_type_offset(FormatInput(EndianBuf::<LittleEndian>::new(&buf), Format::Dwarf32)) {
        Err(Error::UnexpectedEof) => assert!(true),
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    };
}

/// The header of a type unit's debugging information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypeUnit<'input, Endian>
    where Endian: Endianity
{
    header: CompilationUnit<'input, Endian>,
    type_signature: u64,
    type_offset: DebugTypesOffset,
}

impl<'input, Endian> TypeUnit<'input, Endian>
    where Endian: Endianity
{
    /// Construct a new `TypeUnit`.
    pub fn new(header: CompilationUnit<'input, Endian>,
               type_signature: u64,
               type_offset: DebugTypesOffset)
               -> TypeUnit<'input, Endian> {
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
#[allow(dead_code)] // TODO FITZGEN
fn parse_type_unit_header<'input, Endian>
    (input: EndianBuf<'input, Endian>)
     -> ParseResult<(EndianBuf<'input, Endian>, TypeUnit<'input, Endian>)>
    where Endian: Endianity
{
    let (rest, header) = try!(parse_compilation_unit_header(input));
    let (rest, signature) = try!(parse_type_signature(rest));
    let (rest, offset) = try!(parse_type_offset(FormatInput(rest, header.format())));
    Ok((rest.0, TypeUnit::new(header, signature, offset)))
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

    let result = parse_type_unit_header(EndianBuf::<LittleEndian>::new(&buf));
    println!("result = {:#?}", result);

    match result {
        Ok((_, header)) => {
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
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    }
}
