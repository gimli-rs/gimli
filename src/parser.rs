//! Functions for parsing DWARF debugging information.

#![deny(missing_docs)]

use constants;
use leb128;
use abbrev::{DebugAbbrev, DebugAbbrevOffset, Abbreviations, Abbreviation, AttributeSpecification};
use endianity::{Endianity, EndianBuf};
#[cfg(test)]
use endianity::LittleEndian;
use line::DebugLineOffset;
use std::cell::Cell;
use std::error;
use std::ffi;
use std::fmt::{self, Debug};
use std::io;
use std::marker::PhantomData;
use std::ops::{Range, RangeFrom, RangeTo};
use str::DebugStrOffset;

/// An error that occurred when parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// An error parsing an unsigned LEB128 value.
    BadUnsignedLeb128,
    /// An error parsing a signed LEB128 value.
    BadSignedLeb128,
    /// An abbreviation declared that its tag is zero, but zero is reserved for
    /// null records.
    AbbreviationTagZero,
    /// An attribute specification declared that its form is zero, but zero is
    /// reserved for null records.
    AttributeFormZero,
    /// The abbreviation's has-children byte was not one of
    /// `DW_CHILDREN_{yes,no}`.
    BadHasChildren,
    /// The specified length is impossible.
    BadLength,
    /// Found an unknown `DW_FORM_*` type.
    UnknownForm,
    /// Expected a zero, found something else.
    ExpectedZero,
    /// Found an abbreviation code that has already been used.
    DuplicateAbbreviationCode,
    /// Found a duplicate arange.
    DuplicateArange,
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
    /// Found an unknown standard opcode.
    UnknownStandardOpcode(constants::DwLns),
    /// Found an unknown extended opcode.
    UnknownExtendedOpcode(constants::DwLne),
    /// The specified address size is not supported.
    UnsupportedAddressSize(u8),
    /// The specified field size is not supported.
    UnsupportedFieldSize(u8),
    /// The minimum instruction length must not be zero.
    MinimumInstructionLengthZero,
    /// The maximum operations per instruction must not be zero.
    MaximumOperationsPerInstructionZero,
    /// The line range must not be zero.
    LineRangeZero,
    /// The opcode base must not be zero.
    OpcodeBaseZero,
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
            Error::AbbreviationTagZero => {
                "An abbreviation declared that its tag is zero,
                 but zero is reserved for null records"
            }
            Error::AttributeFormZero => {
                "An attribute specification declared that its form is zero,
                 but zero is reserved for null records"
            }
            Error::BadHasChildren => {
                "The abbreviation's has-children byte was not one of
                 `DW_CHILDREN_{yes,no}`"
            }
            Error::BadLength => "The specified length is impossible",
            Error::UnknownForm => "Found an unknown `DW_FORM_*` type",
            Error::ExpectedZero => "Expected a zero, found something else",
            Error::DuplicateAbbreviationCode => {
                "Found an abbreviation code that has already been used"
            }
            Error::DuplicateArange => "Found a duplicate arange",
            Error::UnknownReservedLength => "Found an unknown reserved length value",
            Error::UnknownVersion => "Found an unknown DWARF version",
            Error::UnitHeaderLengthTooShort => {
                "The unit header's claimed length is too short to even hold
                 the header itself"
            }
            Error::UnknownAbbreviation => "Found a record with an unknown abbreviation code",
            Error::UnexpectedEof => "Hit the end of input before it was expected",
            Error::UnknownStandardOpcode(_) => "Found an unknown standard opcode",
            Error::UnknownExtendedOpcode(_) => "Found an unknown extended opcode",
            Error::UnsupportedAddressSize(_) => "The specified address size is not supported",
            Error::UnsupportedFieldSize(_) => "The specified field size is not supported",
            Error::MinimumInstructionLengthZero => {
                "The minimum instruction length must not be zero."
            }
            Error::MaximumOperationsPerInstructionZero => {
                "The maximum operations per instruction must not be zero."
            }
            Error::LineRangeZero => "The line range must not be zero.",
            Error::OpcodeBaseZero => "The opcode base must not be zero.",
        }
    }
}

/// The result of a parse.
pub type ParseResult<T> = Result<T, Error>;

/// Parse a `u8` from the input.
#[doc(hidden)]
#[inline]
pub fn parse_u8(input: &[u8]) -> ParseResult<(&[u8], u8)> {
    if input.len() == 0 {
        Err(Error::UnexpectedEof)
    } else {
        Ok((&input[1..], input[0]))
    }
}

/// Parse a `i8` from the input.
#[doc(hidden)]
#[inline]
pub fn parse_i8(input: &[u8]) -> ParseResult<(&[u8], i8)> {
    if input.len() == 0 {
        Err(Error::UnexpectedEof)
    } else {
        Ok((&input[1..], input[0] as i8))
    }
}

/// Parse a `u16` from the input.
#[doc(hidden)]
#[inline]
pub fn parse_u16<Endian>(input: EndianBuf<Endian>) -> ParseResult<(EndianBuf<Endian>, u16)>
    where Endian: Endianity
{
    if input.len() < 2 {
        Err(Error::UnexpectedEof)
    } else {
        Ok((input.range_from(2..), Endian::read_u16(&input)))
    }
}

/// Parse a `u32` from the input.
#[doc(hidden)]
#[inline]
pub fn parse_u32<Endian>(input: EndianBuf<Endian>) -> ParseResult<(EndianBuf<Endian>, u32)>
    where Endian: Endianity
{
    if input.len() < 4 {
        Err(Error::UnexpectedEof)
    } else {
        Ok((input.range_from(4..), Endian::read_u32(&input)))
    }
}

/// Parse a `u64` from the input.
#[doc(hidden)]
#[inline]
pub fn parse_u64<Endian>(input: EndianBuf<Endian>) -> ParseResult<(EndianBuf<Endian>, u64)>
    where Endian: Endianity
{
    if input.len() < 8 {
        Err(Error::UnexpectedEof)
    } else {
        Ok((input.range_from(8..), Endian::read_u64(&input)))
    }
}

/// Parse a `u32` from the input and return it as a `u64`.
#[doc(hidden)]
#[inline]
pub fn parse_u32_as_u64<Endian>(input: EndianBuf<Endian>) -> ParseResult<(EndianBuf<Endian>, u64)>
    where Endian: Endianity
{
    if input.len() < 4 {
        Err(Error::UnexpectedEof)
    } else {
        Ok((input.range_from(4..), Endian::read_u32(&input) as u64))
    }
}

/// Parse a variable length sequence and return it as a `u64`. Currently only supports lengths of
/// 0, 1, 2, 4, and 8 bytes.
#[doc(hidden)]
#[inline]
#[allow(non_snake_case)]
pub fn parse_uN_as_u64<Endian>(size: u8,
                               input: EndianBuf<Endian>)
                               -> ParseResult<(EndianBuf<Endian>, u64)>
    where Endian: Endianity
{
    match size {
        0 => Ok((input, 0)),
        1 => parse_u8(input.into()).map(|(r, u)| (EndianBuf::new(r), u as u64)),
        2 => parse_u16(input).map(|(r, u)| (r, u as u64)),
        4 => parse_u32(input).map(|(r, u)| (r, u as u64)),
        8 => {
            // NB: DWARF stores 8 byte address in .debug_arange as two separate 32-bit
            // words. Not sure yet if this happens elsewhere, or if it only happens in DWARF32,
            // and not DWARF64.
            let (r, u) = try!(parse_u32_as_u64(input));
            let (r, v) = try!(parse_u32_as_u64(r));
            Ok((r, (u << 32) + v))
        }
        _ => Err(Error::UnsupportedFieldSize(size)),
    }
}

/// Parse a word-sized integer according to the DWARF format, and return it as a `u64`.
#[doc(hidden)]
#[inline]
pub fn parse_word<Endian>(input: EndianBuf<Endian>,
                          format: Format)
                          -> ParseResult<(EndianBuf<Endian>, u64)>
    where Endian: Endianity
{
    match format {
        Format::Dwarf32 => parse_u32_as_u64(input),
        Format::Dwarf64 => parse_u64(input),
    }
}

/// Parse an address-sized integer, and return it as a `u64`.
#[doc(hidden)]
#[inline]
pub fn parse_address<Endian>(input: EndianBuf<Endian>,
                             address_size: u8)
                             -> ParseResult<(EndianBuf<Endian>, u64)>
    where Endian: Endianity
{
    if input.len() < address_size as usize {
        Err(Error::UnexpectedEof)
    } else {
        let address = match address_size {
            8 => Endian::read_u64(&input),
            4 => Endian::read_u32(&input) as u64,
            2 => Endian::read_u16(&input) as u64,
            1 => input[0] as u64,
            otherwise => return Err(Error::UnsupportedAddressSize(otherwise)),
        };
        Ok((input.range_from(address_size as usize..), address))
    }
}

/// Parse a null-terminated slice from the input.
#[doc(hidden)]
#[inline]
pub fn parse_null_terminated_string(input: &[u8]) -> ParseResult<(&[u8], &ffi::CStr)> {
    let null_idx = input.iter().position(|ch| *ch == 0);

    if let Some(idx) = null_idx {
        let cstr = unsafe {
            // It is safe to use the unchecked variant here because we know we
            // grabbed the index of the first null byte in the input and
            // therefore there can't be any interior null bytes in this slice.
            ffi::CStr::from_bytes_with_nul_unchecked(&input[0..idx + 1])
        };
        Ok((&input[idx + 1..], cstr))
    } else {
        Err(Error::UnexpectedEof)
    }
}

/// An offset into the `.debug_types` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugTypesOffset(pub u64);

/// An offset into the `.debug_info` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugInfoOffset(pub u64);

/// An offset into the `.debug_loc` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugLocOffset(pub u64);

/// An offset into the `.debug_macinfo` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugMacinfoOffset(pub u64);

/// An offset into the current compilation or type unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub struct UnitOffset(pub u64);

/// The `DebugInfo` struct represents the DWARF debugging information found in
/// the `.debug_info` section.
#[derive(Debug, Clone, Copy)]
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

    /// Iterate the compilation- and partial-units in this
    /// `.debug_info` section.
    ///
    /// ```
    /// use gimli::{DebugInfo, LittleEndian};
    ///
    /// # let buf = [];
    /// # let read_debug_info_section_somehow = || &buf;
    /// let debug_info = DebugInfo::<LittleEndian>::new(read_debug_info_section_somehow());
    ///
    /// for parse_result in debug_info.units() {
    ///     let unit = parse_result.unwrap();
    ///     println!("unit's length is {}", unit.unit_length());
    /// }
    /// ```
    pub fn units(&self) -> UnitHeadersIter<'input, Endian> {
        UnitHeadersIter { input: self.debug_info_section }
    }

    /// Get the UnitHeader located at offset from this .debug_info section.
    ///
    ///
    pub fn header_from_offset(&self,
                              offset: DebugInfoOffset)
                              -> ParseResult<UnitHeader<'input, Endian>> {
        let offset = offset.0 as usize;
        if self.debug_info_section.len() < offset {
            return Err(Error::UnexpectedEof);
        }

        let input = self.debug_info_section.range_from(offset..);
        match parse_unit_header(input) {
            Ok((_, header)) => Ok(header),
            Err(e) => Err(e),
        }
    }
}

/// An iterator over the compilation- and partial-units of a section.
///
/// See the [documentation on
/// `DebugInfo::units`](./struct.DebugInfo.html#method.units)
/// for more detail.
pub struct UnitHeadersIter<'input, Endian>
    where Endian: Endianity
{
    input: EndianBuf<'input, Endian>,
}

impl<'input, Endian> Iterator for UnitHeadersIter<'input, Endian>
    where Endian: Endianity
{
    type Item = ParseResult<UnitHeader<'input, Endian>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.input.is_empty() {
            None
        } else {
            match parse_unit_header(self.input) {
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
fn test_units() {
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
    let mut units = debug_info.units();

    match units.next() {
        Some(Ok(header)) => {
            let expected = UnitHeader::<LittleEndian>::new(0x000000000000002b,
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
                UnitHeader::new(0x00000027,
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
#[inline]
pub fn parse_unsigned_leb(mut input: &[u8]) -> ParseResult<(&[u8], u64)> {
    match leb128::read::unsigned(&mut input) {
        Ok(val) => Ok((input, val)),
        Err(leb128::read::Error::IoError(ref e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
            Err(Error::UnexpectedEof)
        }
        Err(_) => Err(Error::BadUnsignedLeb128),
    }
}

/// Parse a signed LEB128 encoded integer.
#[inline]
pub fn parse_signed_leb(mut input: &[u8]) -> ParseResult<(&[u8], i64)> {
    match leb128::read::signed(&mut input) {
        Ok(val) => Ok((input, val)),
        Err(leb128::read::Error::IoError(ref e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
            Err(Error::UnexpectedEof)
        }
        Err(_) => Err(Error::BadSignedLeb128),
    }
}

/// Whether the format of a compilation unit is 32- or 64-bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// 64-bit DWARF
    Dwarf64,
    /// 32-bit DWARF
    Dwarf32,
}

const MAX_DWARF_32_UNIT_LENGTH: u64 = 0xfffffff0;

const DWARF_64_INITIAL_UNIT_LENGTH: u64 = 0xffffffff;

/// Parse the compilation unit header's length.
#[doc(hidden)]
pub fn parse_unit_length<Endian>(input: EndianBuf<Endian>)
                                 -> ParseResult<(EndianBuf<Endian>, (u64, Format))>
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
fn parse_version<Endian>(input: EndianBuf<Endian>) -> ParseResult<(EndianBuf<Endian>, u16)>
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
fn test_unit_version_ok() {
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
fn test_unit_version_unknown_version() {
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
fn test_unit_version_incomplete() {
    let buf = [0x04];

    match parse_version(EndianBuf::<LittleEndian>::new(&buf)) {
        Err(Error::UnexpectedEof) => assert!(true),
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    };
}

/// Parse the `debug_abbrev_offset` in the compilation unit header.
fn parse_debug_abbrev_offset<Endian>(input: EndianBuf<Endian>,
                                     format: Format)
                                     -> ParseResult<(EndianBuf<Endian>, DebugAbbrevOffset)>
    where Endian: Endianity
{
    parse_word(input, format).map(|(rest, offset)| (rest, DebugAbbrevOffset(offset)))
}

#[test]
fn test_parse_debug_abbrev_offset_32() {
    let buf = [0x01, 0x02, 0x03, 0x04];

    match parse_debug_abbrev_offset(EndianBuf::<LittleEndian>::new(&buf), Format::Dwarf32) {
        Ok((_, val)) => assert_eq!(val, DebugAbbrevOffset(0x04030201)),
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    };
}

#[test]
fn test_parse_debug_abbrev_offset_32_incomplete() {
    let buf = [0x01, 0x02];

    match parse_debug_abbrev_offset(EndianBuf::<LittleEndian>::new(&buf), Format::Dwarf32) {
        Err(Error::UnexpectedEof) => assert!(true),
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    };
}

#[test]
fn test_parse_debug_abbrev_offset_64() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    match parse_debug_abbrev_offset(EndianBuf::<LittleEndian>::new(&buf), Format::Dwarf64) {
        Ok((_, val)) => assert_eq!(val, DebugAbbrevOffset(0x0807060504030201)),
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    };
}

#[test]
fn test_parse_debug_abbrev_offset_64_incomplete() {
    let buf = [0x01, 0x02];

    match parse_debug_abbrev_offset(EndianBuf::<LittleEndian>::new(&buf), Format::Dwarf64) {
        Err(Error::UnexpectedEof) => assert!(true),
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    };
}


/// Parse the `debug_info_offset` in the arange header.
pub fn parse_debug_info_offset<Endian>(input: EndianBuf<Endian>,
                                       format: Format)
                                       -> ParseResult<(EndianBuf<Endian>, DebugInfoOffset)>
    where Endian: Endianity
{
    parse_word(input, format).map(|(rest, offset)| (rest, DebugInfoOffset(offset)))
}

#[test]
fn test_parse_debug_inro_offset_32() {
    let buf = [0x01, 0x02, 0x03, 0x04];

    match parse_debug_info_offset(EndianBuf::<LittleEndian>::new(&buf), Format::Dwarf32) {
        Ok((_, val)) => assert_eq!(val, DebugInfoOffset(0x04030201)),
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    };
}

#[test]
fn test_parse_debug_info_offset_32_incomplete() {
    let buf = [0x01, 0x02];

    match parse_debug_info_offset(EndianBuf::<LittleEndian>::new(&buf), Format::Dwarf32) {
        Err(Error::UnexpectedEof) => assert!(true),
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    };
}

#[test]
fn test_parse_debug_info_offset_64() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    match parse_debug_info_offset(EndianBuf::<LittleEndian>::new(&buf), Format::Dwarf64) {
        Ok((_, val)) => assert_eq!(val, DebugInfoOffset(0x0807060504030201)),
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    };
}

#[test]
fn test_parse_debug_info_offset_64_incomplete() {
    let buf = [0x01, 0x02];

    match parse_debug_info_offset(EndianBuf::<LittleEndian>::new(&buf), Format::Dwarf64) {
        Err(Error::UnexpectedEof) => assert!(true),
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    };
}

/// Parse the `debug_types_offset` in the pubtypes header.
pub fn parse_debug_types_offset<Endian>(input: EndianBuf<Endian>,
                                        format: Format)
                                        -> ParseResult<(EndianBuf<Endian>, DebugTypesOffset)>
    where Endian: Endianity
{
    parse_word(input, format).map(|(rest, offset)| (rest, DebugTypesOffset(offset)))
}

#[test]
fn test_parse_debug_types_offset_32() {
    let buf = [0x01, 0x02, 0x03, 0x04];

    match parse_debug_types_offset(EndianBuf::<LittleEndian>::new(&buf), Format::Dwarf32) {
        Ok((_, val)) => assert_eq!(val, DebugTypesOffset(0x04030201)),
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    };
}

#[test]
fn test_parse_debug_types_offset_32_incomplete() {
    let buf = [0x01, 0x02];

    match parse_debug_types_offset(EndianBuf::<LittleEndian>::new(&buf), Format::Dwarf32) {
        Err(Error::UnexpectedEof) => assert!(true),
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    };
}

#[test]
fn test_parse_debug_types_offset_64() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    match parse_debug_types_offset(EndianBuf::<LittleEndian>::new(&buf), Format::Dwarf64) {
        Ok((_, val)) => assert_eq!(val, DebugTypesOffset(0x0807060504030201)),
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    };
}

#[test]
fn test_parse_debug_types_offset_64_incomplete() {
    let buf = [0x01, 0x02];

    match parse_debug_types_offset(EndianBuf::<LittleEndian>::new(&buf), Format::Dwarf64) {
        Err(Error::UnexpectedEof) => assert!(true),
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    };
}

/// Parse the size of addresses (in bytes) on the target architecture.
pub fn parse_address_size<Endian>(input: EndianBuf<Endian>) -> ParseResult<(EndianBuf<Endian>, u8)>
    where Endian: Endianity
{
    parse_u8(input.into()).map(|(r, u)| (EndianBuf::new(r), u))
}

#[test]
fn test_parse_address_size_ok() {
    let buf = [0x04];

    match parse_address_size(EndianBuf::<LittleEndian>::new(&buf)) {
        Ok((_, val)) => assert_eq!(val, 4),
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    };
}

/// The header of a compilation unit's debugging information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnitHeader<'input, Endian>
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
impl<'input, Endian> UnitHeader<'input, Endian>
    where Endian: Endianity
{
    /// Construct a new `UnitHeader`.
    pub fn new(unit_length: u64,
               version: u16,
               debug_abbrev_offset: DebugAbbrevOffset,
               address_size: u8,
               format: Format,
               entries_buf: &'input [u8])
               -> UnitHeader<'input, Endian> {
        UnitHeader {
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
impl<'input, Endian> UnitHeader<'input, Endian>
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

    fn header_size(&self) -> usize {
        Self::size_of_header(self.format)
    }

    fn is_valid_offset(&self, offset: UnitOffset) -> bool {
        let size_of_header = self.header_size();
        if (offset.0 as usize) < size_of_header {
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
            cached_current: None,
            delta_depth: 0,
        }
    }

    /// Parse this compilation unit's abbreviations.
    ///
    /// ```
    /// use gimli::DebugAbbrev;
    /// # use gimli::{DebugInfo, LittleEndian};
    /// # let info_buf = [
    /// #     // Comilation unit header
    /// #
    /// #     // 32-bit unit length = 25
    /// #     0x19, 0x00, 0x00, 0x00,
    /// #     // Version 4
    /// #     0x04, 0x00,
    /// #     // debug_abbrev_offset
    /// #     0x00, 0x00, 0x00, 0x00,
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
    /// #
    /// # let get_some_unit = || debug_info.units().next().unwrap().unwrap();
    ///
    /// let unit = get_some_unit();
    ///
    /// # let read_debug_abbrev_section_somehow = || &abbrev_buf;
    /// let debug_abbrev = DebugAbbrev::<LittleEndian>::new(read_debug_abbrev_section_somehow());
    /// let abbrevs_for_unit = unit.abbreviations(debug_abbrev).unwrap();
    /// ```
    pub fn abbreviations(&self, debug_abbrev: DebugAbbrev<Endian>) -> ParseResult<Abbreviations> {
        debug_abbrev.abbreviations(self.debug_abbrev_offset())
    }
}

/// Parse a compilation unit header.
fn parse_unit_header<Endian>(input: EndianBuf<Endian>)
                             -> ParseResult<(EndianBuf<Endian>, UnitHeader<Endian>)>
    where Endian: Endianity
{
    let (rest, (unit_length, format)) = try!(parse_unit_length(input));
    let (rest, version) = try!(parse_version(rest));
    let (rest, offset) = try!(parse_debug_abbrev_offset(rest, format));
    let (rest, address_size) = try!(parse_address_size(rest.into()));

    let size_of_unit_length = UnitHeader::<Endian>::size_of_unit_length(format);
    let size_of_header = UnitHeader::<Endian>::size_of_header(format);

    if unit_length as usize + size_of_unit_length < size_of_header {
        return Err(Error::UnitHeaderLengthTooShort);
    }

    let end = unit_length as usize + size_of_unit_length - size_of_header;
    if end > rest.len() {
        return Err(Error::UnexpectedEof);
    }

    let entries_buf = rest.range_to(..end);
    Ok((rest,
        UnitHeader::new(unit_length,
                        version,
                        offset,
                        address_size,
                        format,
                        entries_buf.into())))
}

#[test]
#[cfg_attr(rustfmt, rustfmt_skip)]
fn test_parse_unit_header_32_ok() {
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

    match parse_unit_header(EndianBuf::<LittleEndian>::new(&buf)) {
        Ok((_, header)) => {
            assert_eq!(header,
                       UnitHeader::new(7,
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
fn test_parse_unit_header_64_ok() {
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

    match parse_unit_header(EndianBuf::<LittleEndian>::new(&buf)) {
        Ok((_, header)) => {
            let expected = UnitHeader::new(11,
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
    offset: usize,
    attrs_slice: &'input [u8],
    after_attrs: Cell<Option<&'input [u8]>>,
    code: u64,
    abbrev: &'abbrev Abbreviation,
    unit: &'unit UnitHeader<'input, Endian>,
}

impl<'input, 'abbrev, 'unit, Endian> DebuggingInformationEntry<'input, 'abbrev, 'unit, Endian>
    where Endian: Endianity
{
    /// Get this entry's code.
    pub fn code(&self) -> u64 {
        self.code
    }

    /// Get this entry's offset.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// Get this entry's `DW_TAG_whatever` tag.
    ///
    /// ```
    /// # use gimli::{DebugAbbrev, DebugInfo, LittleEndian};
    /// # let info_buf = [
    /// #     // Comilation unit header
    /// #
    /// #     // 32-bit unit length = 12
    /// #     0x0c, 0x00, 0x00, 0x00,
    /// #     // Version 4
    /// #     0x04, 0x00,
    /// #     // debug_abbrev_offset
    /// #     0x00, 0x00, 0x00, 0x00,
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
    /// # let debug_info = DebugInfo::<LittleEndian>::new(&info_buf);
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
    /// # let debug_abbrev = DebugAbbrev::<LittleEndian>::new(&abbrev_buf);
    /// # let unit = debug_info.units().next().unwrap().unwrap();
    /// # let abbrevs = unit.abbreviations(debug_abbrev).unwrap();
    /// # let mut cursor = unit.entries(&abbrevs);
    /// # let (_, entry) = cursor.next_dfs().unwrap().unwrap();
    /// # let mut get_some_entry = || entry;
    /// let entry = get_some_entry();
    ///
    /// match entry.tag() {
    ///     gimli::DW_TAG_subprogram =>
    ///         println!("this entry contains debug info about a function"),
    ///     gimli::DW_TAG_inlined_subroutine =>
    ///         println!("this entry contains debug info about a particular instance of inlining"),
    ///     gimli::DW_TAG_variable =>
    ///         println!("this entry contains debug info about a local variable"),
    ///     gimli::DW_TAG_formal_parameter =>
    ///         println!("this entry contains debug info about a function parameter"),
    ///     otherwise =>
    ///         println!("this entry is some other kind of data: {:?}", otherwise),
    /// };
    /// ```
    pub fn tag(&self) -> constants::DwTag {
        self.abbrev.tag()
    }

    /// Return true if this entry's type can have children, false otherwise.
    pub fn has_children(&self) -> bool {
        self.abbrev.has_children()
    }

    /// Iterate over this entry's set of attributes.
    ///
    /// ```
    /// use gimli::{DebugAbbrev, DebugInfo, LittleEndian};
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
    /// #     0x00, 0x00, 0x00, 0x00,
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
    /// let unit = debug_info.units().next()
    ///     .expect("Should have at least one compilation unit")
    ///     .expect("and it should parse ok");
    ///
    /// // Read the `.debug_abbrev` section and parse the
    /// // abbreviations for our compilation unit.
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
    /// let abbrevs = unit.abbreviations(debug_abbrev).unwrap();
    ///
    /// // Get the first entry from that compilation unit.
    ///
    /// let mut cursor = unit.entries(&abbrevs);
    /// let (_, entry) = cursor.next_dfs()
    ///     .expect("Should parse next entry")
    ///     .expect("Should have at least one entry");
    ///
    /// // Finally, print the first entry's attributes.
    ///
    /// let mut attrs = entry.attrs();
    /// while let Some(attr) = attrs.next().unwrap() {
    ///     println!("Attribute name = {:?}", attr.name());
    ///     println!("Attribute value = {:?}", attr.value());
    /// }
    /// ```
    pub fn attrs<'me>(&'me self) -> AttrsIter<'input, 'abbrev, 'me, 'unit, Endian> {
        AttrsIter {
            input: self.attrs_slice,
            attributes: self.abbrev.attributes(),
            entry: self,
        }
    }

    /// Find the first attribute in this entry which has the given name,
    /// and return it. Returns `Ok(None)` if no attribute is found.
    pub fn attr(&self, name: constants::DwAt) -> Option<Attribute<'input, Endian>> {
        let mut attrs = self.attrs();
        while let Ok(Some(attr)) = attrs.next() {
            if attr.name() == name {
                return Some(attr);
            }
        }
        None
    }

    /// Find the first attribute in this entry which has the given name,
    /// and return its raw value. Returns `Ok(None)` if no attribute is found.
    pub fn attr_value_raw(&self, name: constants::DwAt) -> Option<AttributeValue<'input, Endian>> {
        self.attr(name).map(|attr| attr.raw_value())
    }

    /// Find the first attribute in this entry which has the given name,
    /// and return its normalized value.  Returns `Ok(None)` if no
    /// attribute is found.
    pub fn attr_value(&self, name: constants::DwAt) -> Option<AttributeValue<'input, Endian>> {
        self.attr(name).map(|attr| attr.value())
    }
}

/// The value of an attribute in a `DebuggingInformationEntry`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttributeValue<'input, Endian>
    where Endian: Endianity
{
    /// A slice that is UnitHeaderHeader::address_size bytes long.
    Addr(EndianBuf<'input, Endian>),

    /// A slice of an arbitrary number of bytes.
    Block(EndianBuf<'input, Endian>),

    /// A one, two, four, or eight byte constant data value. How to interpret
    /// the bytes depends on context.
    ///
    /// From section 7 of the standard: "Depending on context, it may be a
    /// signed integer, an unsigned integer, a floating-point constant, or
    /// anything else."
    Data(EndianBuf<'input, Endian>),

    /// A signed integer constant.
    Sdata(i64),

    /// An unsigned integer constant.
    Udata(u64),

    /// "The information bytes contain a DWARF expression (see Section 2.5) or
    /// location description (see Section 2.6)."
    Exprloc(EndianBuf<'input, Endian>),

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

    /// An offset into the `.debug_lines` section.
    DebugLineRef(DebugLineOffset),

    /// An offset into the `.debug_types` section.
    DebugTypesRef(DebugTypesOffset),

    /// An offset into the `.debug_str` section.
    DebugStrRef(DebugStrOffset),

    /// A null terminated C string, including the final null byte. Not
    /// guaranteed to be UTF-8 or anything like that.
    String(&'input ffi::CStr),
}

/// An attribute in a `DebuggingInformationEntry`, consisting of a name and
/// associated value.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Attribute<'input, Endian>
    where Endian: Endianity
{
    name: constants::DwAt,
    value: AttributeValue<'input, Endian>,
}

impl<'input, Endian> Attribute<'input, Endian>
    where Endian: Endianity
{
    /// Get this attribute's name.
    pub fn name(&self) -> constants::DwAt {
        self.name
    }

    /// Get this attribute's raw value.
    pub fn raw_value(&self) -> AttributeValue<'input, Endian> {
        self.value
    }

    /// Get this attribute's normalized value.
    ///
    /// Attribute values can potentially be encoded in multiple equivalent forms,
    /// and may have special meaning depending on the attribute name.  This method
    /// converts the attribute value to a normalized form based on the attribute
    /// name.
    pub fn value(&self) -> AttributeValue<'input, Endian> {
        match self.name {
            constants::DW_AT_stmt_list => {
                let offset = DebugLineOffset(match self.value {
                    AttributeValue::Data(data) if data.len() == 4 => {
                        Endian::read_u32(data.into()) as u64
                    }
                    AttributeValue::Data(data) if data.len() == 8 => Endian::read_u64(data.into()),
                    AttributeValue::SecOffset(offset) => offset,
                    otherwise => return otherwise,
                });
                AttributeValue::DebugLineRef(offset)
            }
            _ => self.value,
        }
    }
}

/// Take a slice of size `bytes` from the input.
#[inline]
fn take<Endian>(bytes: usize,
                input: EndianBuf<Endian>)
                -> ParseResult<(EndianBuf<Endian>, EndianBuf<Endian>)>
    where Endian: Endianity
{
    if input.len() < bytes {
        Err(Error::UnexpectedEof)
    } else {
        Ok((input.range_from(bytes..), input.range_to(..bytes)))
    }
}

fn length_u8_value<Endian>(input: EndianBuf<Endian>)
                           -> ParseResult<(EndianBuf<Endian>, EndianBuf<Endian>)>
    where Endian: Endianity
{
    let (rest, len) = try!(parse_u8(input.into()));
    take(len as usize, EndianBuf::new(rest))
}

fn length_u16_value<Endian>(input: EndianBuf<Endian>)
                            -> ParseResult<(EndianBuf<Endian>, EndianBuf<Endian>)>
    where Endian: Endianity
{
    let (rest, len) = try!(parse_u16(input));
    take(len as usize, rest)
}

fn length_u32_value<Endian>(input: EndianBuf<Endian>)
                            -> ParseResult<(EndianBuf<Endian>, EndianBuf<Endian>)>
    where Endian: Endianity
{
    let (rest, len) = try!(parse_u32(input));
    take(len as usize, rest)
}

fn length_leb_value<Endian>(input: EndianBuf<Endian>)
                            -> ParseResult<(EndianBuf<Endian>, EndianBuf<Endian>)>
    where Endian: Endianity
{
    let (rest, len) = try!(parse_unsigned_leb(input.into()));
    take(len as usize, EndianBuf::new(rest))
}

fn parse_attribute<'input, 'unit, Endian>
    (mut input: EndianBuf<'input, Endian>,
     unit: &'unit UnitHeader<'input, Endian>,
     spec: AttributeSpecification)
     -> ParseResult<(EndianBuf<'input, Endian>, Attribute<'input, Endian>)>
    where Endian: Endianity
{
    let mut form = spec.form();
    loop {
        match form {
            constants::DW_FORM_indirect => {
                let (rest, dynamic_form) = try!(parse_unsigned_leb(input.into()));
                form = constants::DwForm(dynamic_form);
                input = EndianBuf::new(rest);
                continue;
            }
            constants::DW_FORM_addr => {
                return take(unit.address_size() as usize, input.into()).map(|(rest, addr)| {
                    let attr = Attribute {
                        name: spec.name(),
                        value: AttributeValue::Addr(addr),
                    };
                    (rest, attr)
                });
            }
            constants::DW_FORM_block1 => {
                return length_u8_value(input.into()).map(|(rest, block)| {
                    let attr = Attribute {
                        name: spec.name(),
                        value: AttributeValue::Block(block),
                    };
                    (rest, attr)
                });
            }
            constants::DW_FORM_block2 => {
                return length_u16_value(input.into()).map(|(rest, block)| {
                    let attr = Attribute {
                        name: spec.name(),
                        value: AttributeValue::Block(block),
                    };
                    (rest, attr)
                });
            }
            constants::DW_FORM_block4 => {
                return length_u32_value(input.into()).map(|(rest, block)| {
                    let attr = Attribute {
                        name: spec.name(),
                        value: AttributeValue::Block(block),
                    };
                    (rest, attr)
                });
            }
            constants::DW_FORM_block => {
                return length_leb_value(input.into()).map(|(rest, block)| {
                    let attr = Attribute {
                        name: spec.name(),
                        value: AttributeValue::Block(block),
                    };
                    (rest, attr)
                });
            }
            constants::DW_FORM_data1 => {
                return take(1, input.into()).map(|(rest, data)| {
                    let attr = Attribute {
                        name: spec.name(),
                        value: AttributeValue::Data(data),
                    };
                    (rest, attr)
                });
            }
            constants::DW_FORM_data2 => {
                return take(2, input.into()).map(|(rest, data)| {
                    let attr = Attribute {
                        name: spec.name(),
                        value: AttributeValue::Data(data),
                    };
                    (rest, attr)
                });
            }
            constants::DW_FORM_data4 => {
                return take(4, input.into()).map(|(rest, data)| {
                    let attr = Attribute {
                        name: spec.name(),
                        value: AttributeValue::Data(data),
                    };
                    (rest, attr)
                });
            }
            constants::DW_FORM_data8 => {
                return take(8, input.into()).map(|(rest, data)| {
                    let attr = Attribute {
                        name: spec.name(),
                        value: AttributeValue::Data(data),
                    };
                    (rest, attr)
                });
            }
            constants::DW_FORM_udata => {
                return parse_unsigned_leb(input.into()).map(|(rest, data)| {
                    let attr = Attribute {
                        name: spec.name(),
                        value: AttributeValue::Udata(data),
                    };
                    (EndianBuf::new(rest), attr)
                });
            }
            constants::DW_FORM_sdata => {
                return parse_signed_leb(input.into()).map(|(rest, data)| {
                    let attr = Attribute {
                        name: spec.name(),
                        value: AttributeValue::Sdata(data),
                    };
                    (EndianBuf::new(rest), attr)
                });
            }
            constants::DW_FORM_exprloc => {
                return length_leb_value(input.into()).map(|(rest, block)| {
                    let attr = Attribute {
                        name: spec.name(),
                        value: AttributeValue::Exprloc(block),
                    };
                    (rest, attr)
                })
            }
            constants::DW_FORM_flag => {
                return parse_u8(input.into()).map(|(rest, present)| {
                    let attr = Attribute {
                        name: spec.name(),
                        value: AttributeValue::Flag(present != 0),
                    };
                    (EndianBuf::new(rest), attr)
                })
            }
            constants::DW_FORM_flag_present => {
                // FlagPresent is this weird compile time always true thing that
                // isn't actually present in the serialized DIEs, only in Ok(
                return Ok((input,
                           Attribute {
                    name: spec.name(),
                    value: AttributeValue::Flag(true),
                }));
            }
            constants::DW_FORM_sec_offset => {
                return parse_word(input.into(), unit.format()).map(|(rest, offset)| {
                    let attr = Attribute {
                        name: spec.name(),
                        value: AttributeValue::SecOffset(offset),
                    };
                    (rest, attr)
                });
            }
            constants::DW_FORM_ref1 => {
                return parse_u8(input.into()).map(|(rest, reference)| {
                    let attr = Attribute {
                        name: spec.name(),
                        value: AttributeValue::UnitRef(UnitOffset(reference as u64)),
                    };
                    (EndianBuf::new(rest), attr)
                });
            }
            constants::DW_FORM_ref2 => {
                return parse_u16(input.into()).map(|(rest, reference)| {
                    let attr = Attribute {
                        name: spec.name(),
                        value: AttributeValue::UnitRef(UnitOffset(reference as u64)),
                    };
                    (rest, attr)
                });
            }
            constants::DW_FORM_ref4 => {
                return parse_u32(input.into()).map(|(rest, reference)| {
                    let attr = Attribute {
                        name: spec.name(),
                        value: AttributeValue::UnitRef(UnitOffset(reference as u64)),
                    };
                    (rest, attr)
                });
            }
            constants::DW_FORM_ref8 => {
                return parse_u64(input.into()).map(|(rest, reference)| {
                    let attr = Attribute {
                        name: spec.name(),
                        value: AttributeValue::UnitRef(UnitOffset(reference)),
                    };
                    (rest, attr)
                });
            }
            constants::DW_FORM_ref_udata => {
                return parse_unsigned_leb(input.into()).map(|(rest, reference)| {
                    let attr = Attribute {
                        name: spec.name(),
                        value: AttributeValue::UnitRef(UnitOffset(reference)),
                    };
                    (EndianBuf::new(rest), attr)
                });
            }
            constants::DW_FORM_ref_addr => {
                return parse_word(input.into(), unit.format()).map(|(rest, offset)| {
                    let offset = DebugInfoOffset(offset);
                    let attr = Attribute {
                        name: spec.name(),
                        value: AttributeValue::DebugInfoRef(offset),
                    };
                    (rest, attr)
                });
            }
            constants::DW_FORM_ref_sig8 => {
                return parse_u64(input.into()).map(|(rest, offset)| {
                    let offset = DebugTypesOffset(offset);
                    let attr = Attribute {
                        name: spec.name(),
                        value: AttributeValue::DebugTypesRef(offset),
                    };
                    (rest, attr)
                });
            }
            constants::DW_FORM_string => {
                return parse_null_terminated_string(input.0).map(|(rest, string)| {
                    let attr = Attribute {
                        name: spec.name(),
                        value: AttributeValue::String(string),
                    };
                    (EndianBuf::new(rest), attr)
                });
            }
            constants::DW_FORM_strp => {
                return parse_word(input.into(), unit.format()).map(|(rest, offset)| {
                    let offset = DebugStrOffset(offset);
                    let attr = Attribute {
                        name: spec.name(),
                        value: AttributeValue::DebugStrRef(offset),
                    };
                    (rest, attr)
                });
            }
            _ => {
                return Err(Error::UnknownForm);
            }
        };
    }
}

#[cfg(test)]
fn test_parse_attribute_unit<Endian>(address_size: u8,
                                     format: Format)
                                     -> UnitHeader<'static, Endian>
    where Endian: Endianity
{
    UnitHeader::<Endian>::new(7,
                              4,
                              DebugAbbrevOffset(0x08070605),
                              address_size,
                              format,
                              &[])
}

#[cfg(test)]
fn test_parse_attribute_unit_default() -> UnitHeader<'static, LittleEndian> {
    test_parse_attribute_unit(4, Format::Dwarf32)
}

#[cfg(test)]
fn test_parse_attribute<Endian>(buf: &[u8],
                                len: usize,
                                unit: &UnitHeader<Endian>,
                                form: constants::DwForm,
                                value: AttributeValue<Endian>)
    where Endian: Endianity
{
    let spec = AttributeSpecification::new(constants::DW_AT_low_pc, form);

    let expect = Attribute {
        name: constants::DW_AT_low_pc,
        value: value,
    };

    match parse_attribute(EndianBuf::new(buf), unit, spec) {
        Ok((rest, attr)) => {
            assert_eq!(attr, expect);
            assert_eq!(rest, EndianBuf::new(&buf[len..]));
        }
        otherwise => {
            println!("Unexpected parse result = {:#?}", otherwise);
            assert!(false);
        }
    };
}

#[test]
fn test_parse_attribute_addr() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let unit = test_parse_attribute_unit::<LittleEndian>(4, Format::Dwarf32);
    let form = constants::DW_FORM_addr;
    let value = AttributeValue::Addr(EndianBuf::new(&buf[..4]));
    test_parse_attribute(&buf, 4, &unit, form, value);
}

#[test]
fn test_parse_attribute_addr8() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let unit = test_parse_attribute_unit::<LittleEndian>(8, Format::Dwarf32);
    let form = constants::DW_FORM_addr;
    let value = AttributeValue::Addr(EndianBuf::new(&buf[..8]));
    test_parse_attribute(&buf, 8, &unit, form, value);
}

#[test]
fn test_parse_attribute_block1() {
    // Length of data (3), three bytes of data, two bytes of left over input.
    let buf = [0x03, 0x09, 0x09, 0x09, 0x00, 0x00];
    let unit = test_parse_attribute_unit_default();
    let form = constants::DW_FORM_block1;
    let value = AttributeValue::Block(EndianBuf::new(&buf[1..4]));
    test_parse_attribute(&buf, 4, &unit, form, value);
}

#[test]
fn test_parse_attribute_block2() {
    // Two byte length of data (2), two bytes of data, two bytes of left over input.
    let buf = [0x02, 0x00, 0x09, 0x09, 0x00, 0x00];
    let unit = test_parse_attribute_unit_default();
    let form = constants::DW_FORM_block2;
    let value = AttributeValue::Block(EndianBuf::new(&buf[2..4]));
    test_parse_attribute(&buf, 4, &unit, form, value);
}

#[test]
fn test_parse_attribute_block4() {
    // Four byte length of data (2), two bytes of data, no left over input.
    let buf = [0x02, 0x00, 0x00, 0x00, 0x99, 0x99];
    let unit = test_parse_attribute_unit_default();
    let form = constants::DW_FORM_block4;
    let value = AttributeValue::Block(EndianBuf::new(&buf[4..]));
    test_parse_attribute(&buf, 6, &unit, form, value);
}

#[test]
fn test_parse_attribute_block() {
    // LEB length of data (2, one byte), two bytes of data, no left over input.
    let buf = [0x02, 0x99, 0x99];
    let unit = test_parse_attribute_unit_default();
    let form = constants::DW_FORM_block;
    let value = AttributeValue::Block(EndianBuf::new(&buf[1..]));
    test_parse_attribute(&buf, 3, &unit, form, value);
}

#[test]
fn test_parse_attribute_data1() {
    let buf = [0x03];
    let unit = test_parse_attribute_unit_default();
    let form = constants::DW_FORM_data1;
    let value = AttributeValue::Data(EndianBuf::new(&buf[..]));
    test_parse_attribute(&buf, 1, &unit, form, value);
}

#[test]
fn test_parse_attribute_data2() {
    let buf = [0x02, 0x01, 0x0];
    let unit = test_parse_attribute_unit_default();
    let form = constants::DW_FORM_data2;
    let value = AttributeValue::Data(EndianBuf::new(&buf[..2]));
    test_parse_attribute(&buf, 2, &unit, form, value);
}

#[test]
fn test_parse_attribute_data4() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x99, 0x99];
    let unit = test_parse_attribute_unit_default();
    let form = constants::DW_FORM_data4;
    let value = AttributeValue::Data(EndianBuf::new(&buf[..4]));
    test_parse_attribute(&buf, 4, &unit, form, value);
}

#[test]
fn test_parse_attribute_data8() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x99, 0x99];
    let unit = test_parse_attribute_unit_default();
    let form = constants::DW_FORM_data8;
    let value = AttributeValue::Data(EndianBuf::new(&buf[..8]));
    test_parse_attribute(&buf, 8, &unit, form, value);
}

#[test]
fn test_parse_attribute_udata() {
    let mut buf = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    let bytes_written = {
        let mut writable = &mut buf[..];
        leb128::write::unsigned(&mut writable, 4097).expect("should write ok")
    };

    let unit = test_parse_attribute_unit_default();
    let form = constants::DW_FORM_udata;
    let value = AttributeValue::Udata(4097);
    test_parse_attribute(&buf, bytes_written, &unit, form, value);
}

#[test]
fn test_parse_attribute_sdata() {
    let mut buf = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    let bytes_written = {
        let mut writable = &mut buf[..];
        leb128::write::signed(&mut writable, -4097).expect("should write ok")
    };

    let unit = test_parse_attribute_unit_default();
    let form = constants::DW_FORM_sdata;
    let value = AttributeValue::Sdata(-4097);
    test_parse_attribute(&buf, bytes_written, &unit, form, value);
}

#[test]
fn test_parse_attribute_exprloc() {
    // LEB length of data (2, one byte), two bytes of data, one byte left over input.
    let buf = [0x02, 0x99, 0x99, 0x11];
    let unit = test_parse_attribute_unit_default();
    let form = constants::DW_FORM_exprloc;
    let value = AttributeValue::Exprloc(EndianBuf::new(&buf[1..3]));
    test_parse_attribute(&buf, 3, &unit, form, value);
}

#[test]
fn test_parse_attribute_flag_true() {
    let buf = [0x42];
    let unit = test_parse_attribute_unit_default();
    let form = constants::DW_FORM_flag;
    let value = AttributeValue::Flag(true);
    test_parse_attribute(&buf, 1, &unit, form, value);
}

#[test]
fn test_parse_attribute_flag_false() {
    let buf = [0x00];
    let unit = test_parse_attribute_unit_default();
    let form = constants::DW_FORM_flag;
    let value = AttributeValue::Flag(false);
    test_parse_attribute(&buf, 1, &unit, form, value);
}

#[test]
fn test_parse_attribute_flag_present() {
    let buf = [0x01, 0x02, 0x03, 0x04];
    let unit = test_parse_attribute_unit_default();
    let form = constants::DW_FORM_flag_present;
    let value = AttributeValue::Flag(true);
    // DW_FORM_flag_present does not consume any bytes of the input stream.
    test_parse_attribute(&buf, 0, &unit, form, value);
}

#[test]
fn test_parse_attribute_sec_offset_32() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10];
    let unit = test_parse_attribute_unit::<LittleEndian>(4, Format::Dwarf32);
    let form = constants::DW_FORM_sec_offset;
    let value = AttributeValue::SecOffset(0x04030201);
    test_parse_attribute(&buf, 4, &unit, form, value);
}

#[test]
fn test_parse_attribute_sec_offset_64() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10];
    let unit = test_parse_attribute_unit::<LittleEndian>(4, Format::Dwarf64);
    let form = constants::DW_FORM_sec_offset;
    let value = AttributeValue::SecOffset(0x0807060504030201);
    test_parse_attribute(&buf, 8, &unit, form, value);
}

#[test]
fn test_parse_attribute_ref1() {
    let buf = [0x03];
    let unit = test_parse_attribute_unit_default();
    let form = constants::DW_FORM_ref1;
    let value = AttributeValue::UnitRef(UnitOffset(3));
    test_parse_attribute(&buf, 1, &unit, form, value);
}

#[test]
fn test_parse_attribute_ref2() {
    let buf = [0x02, 0x01, 0x0];
    let unit = test_parse_attribute_unit_default();
    let form = constants::DW_FORM_ref2;
    let value = AttributeValue::UnitRef(UnitOffset(258));
    test_parse_attribute(&buf, 2, &unit, form, value);
}

#[test]
fn test_parse_attribute_ref4() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x99, 0x99];
    let unit = test_parse_attribute_unit_default();
    let form = constants::DW_FORM_ref4;
    let value = AttributeValue::UnitRef(UnitOffset(67305985));
    test_parse_attribute(&buf, 4, &unit, form, value);
}

#[test]
fn test_parse_attribute_ref8() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x99, 0x99];
    let unit = test_parse_attribute_unit_default();
    let form = constants::DW_FORM_ref8;
    let value = AttributeValue::UnitRef(UnitOffset(578437695752307201));
    test_parse_attribute(&buf, 8, &unit, form, value);
}

#[test]
fn test_parse_attribute_refudata() {
    let mut buf = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    let bytes_written = {
        let mut writable = &mut buf[..];
        leb128::write::unsigned(&mut writable, 4097).expect("should write ok")
    };

    let unit = test_parse_attribute_unit_default();
    let form = constants::DW_FORM_ref_udata;
    let value = AttributeValue::UnitRef(UnitOffset(4097));
    test_parse_attribute(&buf, bytes_written, &unit, form, value);
}

#[test]
fn test_parse_attribute_refaddr_32() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x99, 0x99];
    let unit = test_parse_attribute_unit::<LittleEndian>(4, Format::Dwarf32);
    let form = constants::DW_FORM_ref_addr;
    let value = AttributeValue::DebugInfoRef(DebugInfoOffset(67305985));
    test_parse_attribute(&buf, 4, &unit, form, value);
}

#[test]
fn test_parse_attribute_refaddr_64() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x99, 0x99];
    let unit = test_parse_attribute_unit::<LittleEndian>(4, Format::Dwarf64);
    let form = constants::DW_FORM_ref_addr;
    let value = AttributeValue::DebugInfoRef(DebugInfoOffset(578437695752307201));
    test_parse_attribute(&buf, 8, &unit, form, value);
}

#[test]
fn test_parse_attribute_refsig8() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x99, 0x99];
    let unit = test_parse_attribute_unit_default();
    let form = constants::DW_FORM_ref_sig8;
    let value = AttributeValue::DebugTypesRef(DebugTypesOffset(578437695752307201));
    test_parse_attribute(&buf, 8, &unit, form, value);
}

#[test]
fn test_parse_attribute_string() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x0, 0x99, 0x99];
    let unit = test_parse_attribute_unit_default();
    let form = constants::DW_FORM_string;
    let value = AttributeValue::String(ffi::CStr::from_bytes_with_nul(&buf[..6]).unwrap());
    test_parse_attribute(&buf, 6, &unit, form, value);
}

#[test]
fn test_parse_attribute_strp_32() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x99, 0x99];
    let unit = test_parse_attribute_unit::<LittleEndian>(4, Format::Dwarf32);
    let form = constants::DW_FORM_strp;
    let value = AttributeValue::DebugStrRef(DebugStrOffset(67305985));
    test_parse_attribute(&buf, 4, &unit, form, value);
}

#[test]
fn test_parse_attribute_strp_64() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x99, 0x99];
    let unit = test_parse_attribute_unit::<LittleEndian>(4, Format::Dwarf64);
    let form = constants::DW_FORM_strp;
    let value = AttributeValue::DebugStrRef(DebugStrOffset(578437695752307201));
    test_parse_attribute(&buf, 8, &unit, form, value);
}

#[test]
fn test_parse_attribute_indirect() {
    let mut buf = [0; 100];

    let bytes_written = {
        let mut writable = &mut buf[..];
        leb128::write::unsigned(&mut writable, constants::DW_FORM_udata.0)
            .expect("should write udata") +
        leb128::write::unsigned(&mut writable, 9999999).expect("should write value")
    };

    let unit = test_parse_attribute_unit_default();
    let form = constants::DW_FORM_indirect;
    let value = AttributeValue::Udata(9999999);
    test_parse_attribute(&buf, bytes_written, &unit, form, value);
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

impl<'input, 'abbrev, 'entry, 'unit, Endian> AttrsIter<'input, 'abbrev, 'entry, 'unit, Endian>
    where Endian: Endianity
{
    /// Advance the iterator and return the next attribute.
    ///
    /// Returns `None` when iteration is finished. If an error
    /// occurs while parsing the next attribute, then this error
    /// is returned on all subsequent calls.
    pub fn next(&mut self) -> ParseResult<Option<Attribute<'input, Endian>>> {
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

            return Ok(None);
        }

        let attr = self.attributes[0];
        let (rest, attr) = try!(parse_attribute(EndianBuf::new(self.input), self.entry.unit, attr));
        self.attributes = &self.attributes[1..];
        self.input = rest.into();
        Ok(Some(attr))
    }
}

#[test]
fn test_attrs_iter() {
    let unit = UnitHeader::<LittleEndian>::new(7,
                                               4,
                                               DebugAbbrevOffset(0x08070605),
                                               4,
                                               Format::Dwarf32,
                                               &[]);

    let abbrev = Abbreviation::new(42,
                                   constants::DW_TAG_subprogram,
                                   constants::DW_CHILDREN_yes,
                                   vec![
            AttributeSpecification::new(constants::DW_AT_name, constants::DW_FORM_string),
            AttributeSpecification::new(constants::DW_AT_low_pc, constants::DW_FORM_addr),
            AttributeSpecification::new(constants::DW_AT_high_pc, constants::DW_FORM_addr),
        ]);

    // "foo", 42, 1337, 4 dangling bytes of 0xaa where children would be
    let buf = [0x66, 0x6f, 0x6f, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x39, 0x05, 0x00, 0x00, 0xaa, 0xaa,
               0xaa, 0xaa];

    let entry = DebuggingInformationEntry {
        offset: 0,
        attrs_slice: &buf,
        after_attrs: Cell::new(None),
        code: 1,
        abbrev: &abbrev,
        unit: &unit,
    };

    let mut attrs = AttrsIter {
        input: &buf[..],
        attributes: abbrev.attributes(),
        entry: &entry,
    };

    match attrs.next() {
        Ok(Some(attr)) => {
            assert_eq!(attr,
                       Attribute {
                           name: constants::DW_AT_name,
                           value: AttributeValue::String(ffi::CStr::from_bytes_with_nul(b"foo\0")
                               .unwrap()),
                       });
        }
        otherwise => {
            println!("Unexpected parse result = {:#?}", otherwise);
            assert!(false);
        }
    }

    assert!(entry.after_attrs.get().is_none());

    match attrs.next() {
        Ok(Some(attr)) => {
            assert_eq!(attr,
                       Attribute {
                           name: constants::DW_AT_low_pc,
                           value: AttributeValue::Addr(EndianBuf::new(&[0x2a, 0x00, 0x00, 0x00])),
                       });
        }
        otherwise => {
            println!("Unexpected parse result = {:#?}", otherwise);
            assert!(false);
        }
    }

    assert!(entry.after_attrs.get().is_none());

    match attrs.next() {
        Ok(Some(attr)) => {
            assert_eq!(attr,
                       Attribute {
                           name: constants::DW_AT_high_pc,
                           value: AttributeValue::Addr(EndianBuf::new(&[0x39, 0x05, 0x00, 0x00])),
                       });
        }
        otherwise => {
            println!("Unexpected parse result = {:#?}", otherwise);
            assert!(false);
        }
    }

    assert!(entry.after_attrs.get().is_none());

    assert!(attrs.next().expect("should parse next").is_none());
    assert!(entry.after_attrs.get().is_some());
    assert_eq!(entry.after_attrs.get().expect("should have entry.after_attrs"),
               &buf[buf.len() - 4..])
}

#[test]
fn test_attrs_iter_incomplete() {
    let unit = UnitHeader::<LittleEndian>::new(7,
                                               4,
                                               DebugAbbrevOffset(0x08070605),
                                               4,
                                               Format::Dwarf32,
                                               &[]);

    let abbrev = Abbreviation::new(42,
                                   constants::DW_TAG_subprogram,
                                   constants::DW_CHILDREN_yes,
                                   vec![
            AttributeSpecification::new(constants::DW_AT_name, constants::DW_FORM_string),
            AttributeSpecification::new(constants::DW_AT_low_pc, constants::DW_FORM_addr),
            AttributeSpecification::new(constants::DW_AT_high_pc, constants::DW_FORM_addr),
        ]);

    // "foo"
    let buf = [0x66, 0x6f, 0x6f, 0x00];

    let entry = DebuggingInformationEntry {
        offset: 0,
        attrs_slice: &buf,
        after_attrs: Cell::new(None),
        code: 1,
        abbrev: &abbrev,
        unit: &unit,
    };

    let mut attrs = AttrsIter {
        input: &buf[..],
        attributes: abbrev.attributes(),
        entry: &entry,
    };

    match attrs.next() {
        Ok(Some(attr)) => {
            assert_eq!(attr,
                       Attribute {
                           name: constants::DW_AT_name,
                           value: AttributeValue::String(ffi::CStr::from_bytes_with_nul(b"foo\0")
                               .unwrap()),
                       });
        }
        otherwise => {
            println!("Unexpected parse result = {:#?}", otherwise);
            assert!(false);
        }
    }

    assert!(entry.after_attrs.get().is_none());

    // Return error for incomplete attribute.
    assert!(attrs.next().is_err());
    assert!(entry.after_attrs.get().is_none());

    // Return error for all subsequent calls.
    assert!(attrs.next().is_err());
    assert!(attrs.next().is_err());
    assert!(attrs.next().is_err());
    assert!(attrs.next().is_err());
    assert!(entry.after_attrs.get().is_none());
}

/// A cursor into the Debugging Information Entries tree for a compilation unit.
///
/// The `EntriesCursor` can traverse the DIE tree in DFS order using `next_dfs()`,
/// or skip to the next sibling of the entry the cursor is currently pointing to
/// using `next_sibling()`.
///
/// It is also possible to traverse the DIE tree at a lower abstraction level
/// using `next_entry()`. This method does not skip over null entries, or provide
/// any indication of the current tree depth. In this case, you must use `current()`
/// to obtain the current entry, and `current().has_children()` to determine if
/// the entry following the current entry will be a sibling or child. `current()`
/// will return `None` if the current entry is a null entry, which signifies the
/// end of the current tree depth.
#[derive(Clone, Debug)]
pub struct EntriesCursor<'input, 'abbrev, 'unit, Endian>
    where 'input: 'unit,
          Endian: Endianity + 'unit
{
    input: &'input [u8],
    unit: &'unit UnitHeader<'input, Endian>,
    abbreviations: &'abbrev Abbreviations,
    cached_current: Option<DebuggingInformationEntry<'input, 'abbrev, 'unit, Endian>>,
    delta_depth: isize,
}

impl<'input, 'abbrev, 'unit, Endian> EntriesCursor<'input, 'abbrev, 'unit, Endian>
    where Endian: Endianity
{
    /// Get a reference to the entry that the cursor is currently pointing to.
    ///
    /// If the cursor is not pointing at an entry, or if the current entry is a
    /// null entry, then `None` is returned.
    pub fn current<'me>
        (&'me self)
         -> Option<&'me DebuggingInformationEntry<'input, 'abbrev, 'unit, Endian>> {
        self.cached_current.as_ref()
    }

    /// Return the input buffer after the current entry.
    fn after_entry(&self) -> ParseResult<&'input [u8]> {
        if let Some(ref current) = self.cached_current {
            if let Some(after_attrs) = current.after_attrs.get() {
                Ok(after_attrs)
            } else {
                let mut attrs = current.attrs();
                while let Some(_) = try!(attrs.next()) {
                }
                Ok(current.after_attrs
                    .get()
                    .expect("should have after_attrs after iterating attrs"))
            }
        } else {
            Ok(self.input)
        }
    }

    /// Return the offset in bytes of the given array from the start of the compilation unit
    fn get_offset(&self, input: &[u8]) -> usize {
        let ptr = input.as_ptr() as *const u8 as usize;
        let start_ptr = self.unit.entries_buf.as_ptr() as *const u8 as usize;
        ptr - start_ptr + self.unit.header_size()
    }

    /// Move the cursor to the next DIE in the tree.
    ///
    /// Returns `Some` if there is a next entry, even if this entry is null.
    /// If there is no next entry, then `None` is returned.
    pub fn next_entry(&mut self) -> ParseResult<Option<()>> {
        let input = try!(self.after_entry());
        if input.len() == 0 {
            self.input = input;
            self.cached_current = None;
            self.delta_depth = 0;
            return Ok(None);
        }

        let offset = self.get_offset(input);
        match try!(parse_unsigned_leb(input)) {
            (rest, 0) => {
                self.input = rest;
                self.cached_current = None;
                self.delta_depth = -1;
                Ok(Some(()))
            }
            (rest, code) => {
                if let Some(abbrev) = self.abbreviations.get(code) {
                    self.cached_current = Some(DebuggingInformationEntry {
                        offset: offset,
                        attrs_slice: rest,
                        after_attrs: Cell::new(None),
                        code: code,
                        abbrev: abbrev,
                        unit: self.unit,
                    });
                    self.delta_depth = abbrev.has_children() as isize;

                    Ok(Some(()))
                } else {
                    Err(Error::UnknownAbbreviation)
                }
            }
        }
    }

    /// Move the cursor to the next DIE in the tree in DFS order.
    ///
    /// Upon successful movement of the cursor, return the delta traversal
    /// depth and the entry:
    ///
    ///   * If we moved down into the previous current entry's children, we get
    ///     `Some((1, entry))`.
    ///
    ///   * If we moved to the previous current entry's sibling, we get
    ///     `Some((0, entry))`.
    ///
    ///   * If the previous entry does not have any siblings and we move up to
    ///     its parent's next sibling, then we get `Some((-1, entry))`. Note that
    ///     if the parent doesn't have a next sibling, then it could go up to the
    ///     parent's parent's next sibling and return `Some((-2, entry))`, etc.
    ///
    /// If there is no next entry, then `None` is returned.
    ///
    /// Here is an example that finds the first entry in a compilation unit that
    /// does not have any children.
    ///
    /// ```
    /// # use gimli::{DebugAbbrev, DebugInfo, LittleEndian};
    /// # let info_buf = [
    /// #     // Comilation unit header
    /// #
    /// #     // 32-bit unit length = 25
    /// #     0x19, 0x00, 0x00, 0x00,
    /// #     // Version 4
    /// #     0x04, 0x00,
    /// #     // debug_abbrev_offset
    /// #     0x00, 0x00, 0x00, 0x00,
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
    /// #
    /// # let get_some_unit = || debug_info.units().next().unwrap().unwrap();
    ///
    /// let unit = get_some_unit();
    /// # let get_abbrevs_for_unit = |_| unit.abbreviations(debug_abbrev).unwrap();
    /// let abbrevs = get_abbrevs_for_unit(&unit);
    ///
    /// let mut first_entry_with_no_children = None;
    /// let mut cursor = unit.entries(&abbrevs);
    ///
    /// // Move the cursor to the root.
    /// assert!(cursor.next_dfs().unwrap().is_some());
    ///
    /// // Keep looping while the cursor is moving deeper into the DIE tree.
    /// while let Some((delta_depth, current)) = cursor.next_dfs().expect("Should parse next dfs") {
    ///     // 0 means we moved to a sibling, a negative number means we went back
    ///     // up to a parent's sibling. In either case, bail out of the loop because
    ///     //  we aren't going deeper into the tree anymore.
    ///     if delta_depth <= 0 {
    ///         break;
    ///     }
    ///
    ///     first_entry_with_no_children = Some(current.clone());
    /// }
    ///
    /// println!("The first entry with no children is {:?}",
    ///          first_entry_with_no_children.unwrap());
    /// ```
    pub fn next_dfs<'me>(&'me mut self)
        -> ParseResult<Option<(isize,
                               &'me DebuggingInformationEntry<'input, 'abbrev, 'unit, Endian>)>> {
        let mut delta_depth = self.delta_depth;
        loop {
            // Keep eating null entries that mark the end of an entry's children.
            // This is a micro optimization; next_entry() can handle reading null
            // entries, but this while loop is slightly more efficient.
            // Note that this doesn't handle unusual LEB128 encodings of zero
            // such as [0x80, 0x00]; they are still handled by next_entry().
            let mut input = try!(self.after_entry());
            while input.len() > 0 && input[0] == 0 {
                delta_depth -= 1;
                input = &input[1..];
            }
            self.input = input;
            self.cached_current = None;

            // The next entry should be the one we want.
            if try!(self.next_entry()).is_some() {
                if let Some(ref entry) = self.cached_current {
                    return Ok(Some((delta_depth, entry)));
                }

                // next_entry() read a null entry.  These are normally handled above,
                // so this must have been an unusual LEB 128 encoding of zero.
                delta_depth += self.delta_depth;
            } else {
                return Ok(None);
            }
        }
    }

    /// Move the cursor to the next sibling DIE of the current one.
    ///
    /// Returns `Ok(Some(entry))` when the cursor has been moved to
    /// the next sibling, `Ok(None)` when there is no next sibling.
    ///
    /// The depth of the cursor is never changed if this method returns `Ok`.
    /// Once `Ok(None)` is returned, this method will continue to return
    /// `Ok(None)` until either `next_entry` or `next_dfs` is called.
    ///
    /// Here is an example that iterates over all of the direct children of the
    /// root entry:
    ///
    /// ```
    /// # use gimli::{DebugAbbrev, DebugInfo, LittleEndian};
    /// # let info_buf = [
    /// #     // Comilation unit header
    /// #
    /// #     // 32-bit unit length = 25
    /// #     0x19, 0x00, 0x00, 0x00,
    /// #     // Version 4
    /// #     0x04, 0x00,
    /// #     // debug_abbrev_offset
    /// #     0x00, 0x00, 0x00, 0x00,
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
    /// # let get_some_unit = || debug_info.units().next().unwrap().unwrap();
    ///
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
    /// #
    /// let unit = get_some_unit();
    /// # let get_abbrevs_for_unit = |_| unit.abbreviations(debug_abbrev).unwrap();
    /// let abbrevs = get_abbrevs_for_unit(&unit);
    ///
    /// let mut cursor = unit.entries(&abbrevs);
    ///
    /// // Move the cursor to the root.
    /// assert!(cursor.next_dfs().unwrap().is_some());
    ///
    /// // Move the cursor to the root's first child.
    /// assert!(cursor.next_dfs().unwrap().is_some());
    ///
    /// // Iterate the root's children.
    /// loop {
    ///     {
    ///         let current = cursor.current().expect("Should be at an entry");
    ///         println!("{:?} is a child of the root", current);
    ///     }
    ///
    ///     if cursor.next_sibling().expect("Should parse next sibling").is_none() {
    ///         break;
    ///     }
    /// }
    /// ```
    pub fn next_sibling<'me>
        (&'me mut self)
         -> ParseResult<Option<(&'me DebuggingInformationEntry<'input, 'abbrev, 'unit, Endian>)>> {
        if self.cached_current.is_some() {
            let sibling_ptr = self.current().unwrap().attr_value(constants::DW_AT_sibling);
            if let Some(AttributeValue::UnitRef(offset)) = sibling_ptr {
                if self.unit.is_valid_offset(offset) {
                    // Fast path: this entry has a DW_AT_sibling
                    // attribute pointing to its sibling.
                    self.input = self.unit.range_from(offset..);
                    self.cached_current = None;
                    try!(self.next_entry());
                    return Ok(self.current());
                }
            }

            // Slow path: either the entry doesn't have a sibling pointer,
            // or the pointer is bogus. Do a DFS until we get to the next
            // sibling.

            let mut depth = self.delta_depth;
            while depth > 0 {
                if try!(self.next_entry()).is_none() {
                    return Ok(None);
                }
                depth += self.delta_depth;
            }

            // The next entry will be the sibling, so parse it
            try!(self.next_entry());
            Ok(self.current())
        } else {
            Ok(None)
        }
    }
}

/// Parse a type unit header's unique type signature. Callers should handle
/// unique-ness checking.
fn parse_type_signature<Endian>(input: EndianBuf<Endian>) -> ParseResult<(EndianBuf<Endian>, u64)>
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
fn parse_type_offset<Endian>(input: EndianBuf<Endian>,
                             format: Format)
                             -> ParseResult<(EndianBuf<Endian>, DebugTypesOffset)>
    where Endian: Endianity
{
    parse_word(input, format).map(|(rest, offset)| (rest, DebugTypesOffset(offset)))
}

#[test]
fn test_parse_type_offset_32_ok() {
    let buf = [0x12, 0x34, 0x56, 0x78, 0x00];

    match parse_type_offset(EndianBuf::<LittleEndian>::new(&buf), Format::Dwarf32) {
        Ok((rest, offset)) => {
            assert_eq!(rest.len(), 1);
            assert_eq!(DebugTypesOffset(0x78563412), offset);
        }
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    }
}

#[test]
fn test_parse_type_offset_64_ok() {
    let buf = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xff, 0x00];

    match parse_type_offset(EndianBuf::<LittleEndian>::new(&buf), Format::Dwarf64) {
        Ok((rest, offset)) => {
            assert_eq!(rest.len(), 1);
            assert_eq!(DebugTypesOffset(0xffdebc9a78563412), offset);
        }
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    }
}

#[test]
fn test_parse_type_offset_incomplete() {
    // Need at least 4 bytes.
    let buf = [0xff, 0xff, 0xff];

    match parse_type_offset(EndianBuf::<LittleEndian>::new(&buf), Format::Dwarf32) {
        Err(Error::UnexpectedEof) => assert!(true),
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    };
}

/// The `DebugTypes` struct represents the DWARF type information
/// found in the `.debug_types` section.
#[derive(Debug, Clone, Copy)]
pub struct DebugTypes<'input, Endian>
    where Endian: Endianity
{
    debug_types_section: EndianBuf<'input, Endian>,
}

impl<'input, Endian> DebugTypes<'input, Endian>
    where Endian: Endianity
{
    /// Construct a new `DebugTypes` instance from the data in the `.debug_types`
    /// section.
    ///
    /// It is the caller's responsibility to read the `.debug_types` section and
    /// present it as a `&[u8]` slice. That means using some ELF loader on
    /// Linux, a Mach-O loader on OSX, etc.
    ///
    /// ```
    /// use gimli::{DebugTypes, LittleEndian};
    ///
    /// # let buf = [0x00, 0x01, 0x02, 0x03];
    /// # let read_debug_types_section_somehow = || &buf;
    /// let debug_types = DebugTypes::<LittleEndian>::new(read_debug_types_section_somehow());
    /// ```
    pub fn new(debug_types_section: &'input [u8]) -> DebugTypes<'input, Endian> {
        DebugTypes { debug_types_section: EndianBuf(debug_types_section, PhantomData) }
    }

    /// Iterate the type-units in this `.debug_types` section.
    ///
    /// ```
    /// use gimli::{DebugTypes, LittleEndian};
    ///
    /// # let buf = [];
    /// # let read_debug_types_section_somehow = || &buf;
    /// let debug_types = DebugTypes::<LittleEndian>::new(read_debug_types_section_somehow());
    ///
    /// for parse_result in debug_types.units() {
    ///     let unit = parse_result.unwrap();
    ///     println!("unit's length is {}", unit.unit_length());
    /// }
    /// ```
    pub fn units(&self) -> TypeUnitHeadersIter<'input, Endian> {
        TypeUnitHeadersIter { input: self.debug_types_section }
    }
}

/// An iterator over the type-units of this `.debug_types` section.
///
/// See the [documentation on
/// `DebugTypes::units`](./struct.DebugTypes.html#method.units) for
/// more detail.
pub struct TypeUnitHeadersIter<'input, Endian>
    where Endian: Endianity
{
    input: EndianBuf<'input, Endian>,
}

impl<'input, Endian> Iterator for TypeUnitHeadersIter<'input, Endian>
    where Endian: Endianity
{
    type Item = ParseResult<TypeUnitHeader<'input, Endian>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.input.is_empty() {
            None
        } else {
            match parse_type_unit_header(self.input) {
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

/// The header of a type unit's debugging information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypeUnitHeader<'input, Endian>
    where Endian: Endianity
{
    header: UnitHeader<'input, Endian>,
    type_signature: u64,
    type_offset: DebugTypesOffset,
}

impl<'input, Endian> TypeUnitHeader<'input, Endian>
    where Endian: Endianity
{
    /// Construct a new `TypeUnitHeader`.
    fn new(mut header: UnitHeader<'input, Endian>,
           type_signature: u64,
           type_offset: DebugTypesOffset)
           -> TypeUnitHeader<'input, Endian> {
        // First, fix up the header's entries_buf. Currently it points
        // right after end of the header, but since this is a type
        // unit header, there are two more fields before entries
        // begin to account for.
        let additional = Self::additional_header_size(header.format);
        header.entries_buf = header.entries_buf.range_from(additional..);

        TypeUnitHeader {
            header: header,
            type_signature: type_signature,
            type_offset: type_offset,
        }
    }

    /// Get the length of the debugging info for this type-unit.
    pub fn unit_length(&self) -> u64 {
        self.header.unit_length
    }

    fn additional_header_size(format: Format) -> usize {
        // There are two additional fields in a type-unit compared to
        // compilation- and partial-units. The type_signature is
        // always 64 bits regardless of format, the type_offset is 32
        // or 64 bits depending on the format.
        let type_signature_size = 8;
        let type_offset_size = match format {
            Format::Dwarf32 => 4,
            Format::Dwarf64 => 8,
        };
        type_signature_size + type_offset_size
    }

    /// Get the length of the debugging info for this type-unit,
    /// uncluding the byte length of the encoded length itself.
    pub fn length_including_self(&self) -> u64 {
        self.header.length_including_self() +
        Self::additional_header_size(self.header.format) as u64
    }

    /// Get the DWARF version of the debugging info for this type-unit.
    pub fn version(&self) -> u16 {
        self.header.version
    }

    /// The offset into the `.debug_abbrev` section for this type-unit's
    /// debugging information entries.
    pub fn debug_abbrev_offset(&self) -> DebugAbbrevOffset {
        self.header.debug_abbrev_offset
    }

    /// The size of addresses (in bytes) in this type-unit.
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

    /// Navigate this type unit's `DebuggingInformationEntry`s.
    pub fn entries<'me, 'abbrev>(&'me self,
                                 abbreviations: &'abbrev Abbreviations)
                                 -> EntriesCursor<'input, 'abbrev, 'me, Endian> {
        EntriesCursor {
            unit: &self.header,
            input: self.header.entries_buf.into(),
            abbreviations: abbreviations,
            cached_current: None,
            delta_depth: 0,
        }
    }

    /// Parse this type unit's abbreviations.
    ///
    /// ```
    /// use gimli::DebugAbbrev;
    /// # use gimli::{DebugTypes, LittleEndian};
    /// # let types_buf = [
    /// #     // Type unit header
    /// #
    /// #     // 32-bit unit length = 37
    /// #     0x25, 0x00, 0x00, 0x00,
    /// #     // Version 4
    /// #     0x04, 0x00,
    /// #     // debug_abbrev_offset
    /// #     0x00, 0x00, 0x00, 0x00,
    /// #     // Address size
    /// #     0x04,
    /// #     // Type signature
    /// #     0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    /// #     // Type offset
    /// #     0x01, 0x02, 0x03, 0x04,
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
    /// # let debug_types = DebugTypes::<LittleEndian>::new(&types_buf);
    /// #
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
    /// #
    /// # let get_some_type_unit = || debug_types.units().next().unwrap().unwrap();
    ///
    /// let unit = get_some_type_unit();
    ///
    /// # let read_debug_abbrev_section_somehow = || &abbrev_buf;
    /// let debug_abbrev = DebugAbbrev::<LittleEndian>::new(read_debug_abbrev_section_somehow());
    /// let abbrevs_for_unit = unit.abbreviations(debug_abbrev).unwrap();
    /// ```
    pub fn abbreviations(&self, debug_abbrev: DebugAbbrev<Endian>) -> ParseResult<Abbreviations> {
        debug_abbrev.abbreviations(self.debug_abbrev_offset())
    }
}

/// Parse a type unit header.
fn parse_type_unit_header<Endian>(input: EndianBuf<Endian>)
                                  -> ParseResult<(EndianBuf<Endian>, TypeUnitHeader<Endian>)>
    where Endian: Endianity
{
    let (rest, header) = try!(parse_unit_header(input));
    let (rest, signature) = try!(parse_type_signature(rest));
    let (rest, offset) = try!(parse_type_offset(rest, header.format()));
    Ok((rest, TypeUnitHeader::new(header, signature, offset)))
}

#[test]
#[cfg_attr(rustfmt, rustfmt_skip)]
fn test_parse_type_unit_header_64_ok() {
    let buf = [
        // Enable 64-bit unit length mode.
        0xff, 0xff, 0xff, 0xff,
        // The actual unit length (27).
        0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
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

    match result {
        Ok((_, header)) => {
            assert_eq!(header,
                       TypeUnitHeader::new(UnitHeader::new(27,
                                                           4,
                                                           DebugAbbrevOffset(0x0807060504030201),
                                                           8,
                                                           Format::Dwarf64,
                                                           &buf[buf.len() - 16..]),
                                           0xdeadbeefdeadbeef,
                                           DebugTypesOffset(0x7856341278563412)))
        },
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    }
}
