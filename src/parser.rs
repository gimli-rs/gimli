//! Functions for parsing DWARF debugging information.

use std::error;
use std::ffi;
use std::fmt::{self, Debug};
use std::io;
use std::result;

use constants;
use endianity::{Endianity, EndianBuf};
use leb128;

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
    /// Found an invalid UTF-8 string.
    BadUtf8,
    /// Expected to find the CIE ID, but found something else.
    NotCieId,
    /// Expected to find a pointer to a CIE, but found the CIE ID instead.
    NotCiePointer,
    /// Invalid branch target for a DW_OP_bra or DW_OP_skip.
    BadBranchTarget(usize),
    /// DW_OP_push_object_address used but no address passed in.
    InvalidPushObjectAddress,
    /// Not enough items on the stack when evaluating an expression.
    NotEnoughStackItems,
    /// Too many iterations to compute the expression.
    TooManyIterations,
    /// An unrecognized operation was found while parsing a DWARF
    /// expression.
    InvalidExpression(constants::DwOp),
    /// The expression had a piece followed by an expression
    /// terminator without a piece.
    InvalidPiece,
    /// An expression-terminating operation was followed by something
    /// other than the end of the expression or a piece operation.
    InvalidExpressionTerminator(usize),
    /// Division or modulus by zero when evaluating an expression.
    DivisionByZero,
    /// An unknown DW_CFA_* instruction.
    UnknownCallFrameInstruction(constants::DwCfa),
    /// The end of an address range was before the beginning.
    InvalidAddressRange,
    /// The end offset of a loc list entry was before the beginning.
    InvalidLocationAddressRange,
    /// Encountered a call frame instruction in a context in which it is not
    /// valid.
    CfiInstructionInInvalidContext,
    /// When evaluating call frame instructions, found a `DW_CFA_restore_state`
    /// stack pop instruction, but the stack was empty, and had nothing to pop.
    PopWithEmptyStack,
    /// Do not have unwind info for the given address.
    NoUnwindInfoForAddress,
    /// An offset value was larger than the maximum supported value.
    UnsupportedOffset,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> ::std::result::Result<(), fmt::Error> {
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
            Error::BadUtf8 => "Found an invalid UTF-8 string.",
            Error::NotCieId => "Expected to find the CIE ID, but found something else.",
            Error::NotCiePointer => "Expected to find a CIE pointer, but found the CIE ID instead.",
            Error::BadBranchTarget(_) => "Invalid branch target in DWARF expression",
            Error::InvalidPushObjectAddress => {
                "DW_OP_push_object_address used but no object address given"
            }
            Error::NotEnoughStackItems => "Not enough items on stack when evaluating expression",
            Error::TooManyIterations => "Too many iterations to evaluate DWARF expression",
            Error::InvalidExpression(_) => "Invalid opcode in DWARF expression",
            Error::InvalidPiece => {
                "DWARF expression has piece followed by non-piece expression at end"
            }
            Error::InvalidExpressionTerminator(_) => "Expected DW_OP_piece or DW_OP_bit_piece",
            Error::DivisionByZero => "Division or modulus by zero when evaluating expression",
            Error::UnknownCallFrameInstruction(_) => "An unknown DW_CFA_* instructiion",
            Error::InvalidAddressRange => {
                "The end of an address range must not be before the beginning."
            }
            Error::InvalidLocationAddressRange => {
                "The end offset of a location list entry must not be before the beginning."
            }
            Error::CfiInstructionInInvalidContext => {
                "Encountered a call frame instruction in a context in which it is not valid."
            }
            Error::PopWithEmptyStack => {
                "When evaluating call frame instructions, found a `DW_CFA_restore_state` stack pop \
                 instruction, but the stack was empty, and had nothing to pop."
            }
            Error::NoUnwindInfoForAddress => "Do not have unwind info for the given address.",
            Error::UnsupportedOffset => {
                "An offset value was larger than the maximum supported value."
            }
        }
    }
}

/// The result of a parse.
pub type Result<T> = result::Result<T, Error>;

/// Parse a `u8` from the input.
#[doc(hidden)]
#[inline]
pub fn parse_u8(input: &[u8]) -> Result<(&[u8], u8)> {
    if input.len() == 0 {
        Err(Error::UnexpectedEof)
    } else {
        Ok((&input[1..], input[0]))
    }
}

/// Parse a `i8` from the input.
#[doc(hidden)]
#[inline]
pub fn parse_i8(input: &[u8]) -> Result<(&[u8], i8)> {
    if input.len() == 0 {
        Err(Error::UnexpectedEof)
    } else {
        Ok((&input[1..], input[0] as i8))
    }
}

/// Parse a `u16` from the input.
#[doc(hidden)]
#[inline]
pub fn parse_u16<Endian>(input: EndianBuf<Endian>) -> Result<(EndianBuf<Endian>, u16)>
    where Endian: Endianity
{
    if input.len() < 2 {
        Err(Error::UnexpectedEof)
    } else {
        Ok((input.range_from(2..), Endian::read_u16(&input)))
    }
}

/// Parse a `i16` from the input.
#[doc(hidden)]
#[inline]
pub fn parse_i16<Endian>(input: EndianBuf<Endian>) -> Result<(EndianBuf<Endian>, i16)>
    where Endian: Endianity
{
    if input.len() < 2 {
        Err(Error::UnexpectedEof)
    } else {
        Ok((input.range_from(2..), Endian::read_i16(&input)))
    }
}

/// Parse a `u32` from the input.
#[doc(hidden)]
#[inline]
pub fn parse_u32<Endian>(input: EndianBuf<Endian>) -> Result<(EndianBuf<Endian>, u32)>
    where Endian: Endianity
{
    if input.len() < 4 {
        Err(Error::UnexpectedEof)
    } else {
        Ok((input.range_from(4..), Endian::read_u32(&input)))
    }
}

/// Parse a `i32` from the input.
#[doc(hidden)]
#[inline]
pub fn parse_i32<Endian>(input: EndianBuf<Endian>) -> Result<(EndianBuf<Endian>, i32)>
    where Endian: Endianity
{
    if input.len() < 4 {
        Err(Error::UnexpectedEof)
    } else {
        Ok((input.range_from(4..), Endian::read_i32(&input)))
    }
}

/// Parse a `u64` from the input.
#[doc(hidden)]
#[inline]
pub fn parse_u64<Endian>(input: EndianBuf<Endian>) -> Result<(EndianBuf<Endian>, u64)>
    where Endian: Endianity
{
    if input.len() < 8 {
        Err(Error::UnexpectedEof)
    } else {
        Ok((input.range_from(8..), Endian::read_u64(&input)))
    }
}

/// Parse a `i64` from the input.
#[doc(hidden)]
#[inline]
pub fn parse_i64<Endian>(input: EndianBuf<Endian>) -> Result<(EndianBuf<Endian>, i64)>
    where Endian: Endianity
{
    if input.len() < 8 {
        Err(Error::UnexpectedEof)
    } else {
        Ok((input.range_from(8..), Endian::read_i64(&input)))
    }
}

/// Like `parse_u8` but takes and returns an `EndianBuf` for convenience.
#[doc(hidden)]
#[inline]
pub fn parse_u8e<Endian>(bytes: EndianBuf<Endian>) -> Result<(EndianBuf<Endian>, u8)>
    where Endian: Endianity
{
    let (bytes, value) = try!(parse_u8(bytes.into()));
    Ok((EndianBuf::new(bytes), value))
}

/// Like `parse_i8` but takes and returns an `EndianBuf` for convenience.
#[doc(hidden)]
#[inline]
pub fn parse_i8e<Endian>(bytes: EndianBuf<Endian>) -> Result<(EndianBuf<Endian>, i8)>
    where Endian: Endianity
{
    let (bytes, value) = try!(parse_i8(bytes.into()));
    Ok((EndianBuf::new(bytes), value))
}

/// Like `parse_unsigned_leb` but takes and returns an `EndianBuf` for convenience.
#[doc(hidden)]
#[inline]
pub fn parse_unsigned_lebe<Endian>(bytes: EndianBuf<Endian>)
                                   -> Result<(EndianBuf<Endian>, u64)>
    where Endian: Endianity
{
    let (bytes, value) = try!(parse_unsigned_leb(bytes.into()));
    Ok((EndianBuf::new(bytes), value))
}

/// Like `parse_signed_leb` but takes and returns an `EndianBuf` for convenience.
#[doc(hidden)]
#[inline]
pub fn parse_signed_lebe<Endian>(bytes: EndianBuf<Endian>)
                                 -> Result<(EndianBuf<Endian>, i64)>
    where Endian: Endianity
{
    let (bytes, value) = try!(parse_signed_leb(bytes.into()));
    Ok((EndianBuf::new(bytes), value))
}

/// Parse a `u32` from the input and return it as a `u64`.
#[doc(hidden)]
#[inline]
pub fn parse_u32_as_u64<Endian>(input: EndianBuf<Endian>) -> Result<(EndianBuf<Endian>, u64)>
    where Endian: Endianity
{
    if input.len() < 4 {
        Err(Error::UnexpectedEof)
    } else {
        Ok((input.range_from(4..), Endian::read_u32(&input) as u64))
    }
}

/// Convert a `u64` to a `usize` and return it.
#[doc(hidden)]
#[inline]
pub fn u64_to_offset(offset64: u64) -> Result<usize> {
    let offset = offset64 as usize;
    if offset as u64 == offset64 {
        Ok(offset)
    } else {
        Err(Error::UnsupportedOffset)
    }
}

/// Parse a `u64` from the input, and return it as a `usize`.
#[doc(hidden)]
#[inline]
pub fn parse_u64_as_offset<Endian>(input: EndianBuf<Endian>) -> Result<(EndianBuf<Endian>, usize)>
    where Endian: Endianity
{
    let (rest, offset) = try!(parse_u64(input));
    let offset = try!(u64_to_offset(offset));
    Ok((rest, offset))
}

/// Parse an unsigned LEB128 encoded integer from the input, and return it as a `usize`.
#[doc(hidden)]
#[inline]
pub fn parse_uleb_as_offset<Endian>(input: EndianBuf<Endian>) -> Result<(EndianBuf<Endian>, usize)>
    where Endian: Endianity
{
    let (rest, offset) = try!(parse_unsigned_lebe(input));
    let offset = try!(u64_to_offset(offset));
    Ok((rest, offset))
}

/// Parse a word-sized integer according to the DWARF format, and return it as a `u64`.
#[doc(hidden)]
#[inline]
pub fn parse_word<Endian>(input: EndianBuf<Endian>,
                          format: Format)
                          -> Result<(EndianBuf<Endian>, u64)>
    where Endian: Endianity
{
    match format {
        Format::Dwarf32 => parse_u32_as_u64(input),
        Format::Dwarf64 => parse_u64(input),
    }
}

/// Parse a word-sized integer according to the DWARF format, and return it as a `usize`.
#[doc(hidden)]
#[inline]
pub fn parse_offset<Endian>(input: EndianBuf<Endian>,
                            format: Format)
                            -> Result<(EndianBuf<Endian>, usize)>
    where Endian: Endianity
{
    let (rest, offset) = try!(parse_word(input, format));
    let offset = try!(u64_to_offset(offset));
    Ok((rest, offset))
}

/// Parse an address-sized integer, and return it as a `u64`.
#[doc(hidden)]
#[inline]
pub fn parse_address<Endian>(input: EndianBuf<Endian>,
                             address_size: u8)
                             -> Result<(EndianBuf<Endian>, u64)>
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

/// Parse an address-sized integer, and return it as a `usize`.
#[doc(hidden)]
#[inline]
pub fn parse_address_as_offset<Endian>(input: EndianBuf<Endian>,
                                       address_size: u8)
                                       -> Result<(EndianBuf<Endian>, usize)>
    where Endian: Endianity
{
    let (rest, offset) = try!(parse_address(input, address_size));
    let offset = try!(u64_to_offset(offset));
    Ok((rest, offset))
}

/// Parse a null-terminated slice from the input.
#[doc(hidden)]
#[inline]
pub fn parse_null_terminated_string(input: &[u8]) -> Result<(&[u8], &ffi::CStr)> {
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

/// An offset into the `.debug_macinfo` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugMacinfoOffset(pub usize);

/// Parse an unsigned LEB128 encoded integer.
#[inline]
pub fn parse_unsigned_leb(mut input: &[u8]) -> Result<(&[u8], u64)> {
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
pub fn parse_signed_leb(mut input: &[u8]) -> Result<(&[u8], i64)> {
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
pub fn parse_initial_length<Endian>(input: EndianBuf<Endian>)
                                    -> Result<(EndianBuf<Endian>, (u64, Format))>
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

/// Parse the size of addresses (in bytes) on the target architecture.
pub fn parse_address_size<Endian>(input: EndianBuf<Endian>) -> Result<(EndianBuf<Endian>, u8)>
    where Endian: Endianity
{
    parse_u8(input.into()).map(|(r, u)| (EndianBuf::new(r), u))
}

/// Take a slice of size `bytes` from the input.
#[inline]
pub fn take<Endian>(bytes: usize,
                    input: EndianBuf<Endian>)
                    -> Result<(EndianBuf<Endian>, EndianBuf<Endian>)>
    where Endian: Endianity
{
    if input.len() < bytes {
        Err(Error::UnexpectedEof)
    } else {
        Ok((input.range_from(bytes..), input.range_to(..bytes)))
    }
}

/// Parse a length as an unsigned LEB128 from the input, then take
/// that many bytes from the input.  These bytes are returned as the
/// second element of the result tuple.
#[doc(hidden)]
pub fn parse_length_uleb_value<Endian>(input: EndianBuf<Endian>)
                                       -> Result<(EndianBuf<Endian>, EndianBuf<Endian>)>
    where Endian: Endianity
{
    let (rest, len) = try!(parse_unsigned_leb(input.into()));
    take(len as usize, EndianBuf::new(rest))
}

#[cfg(test)]
mod tests {
    extern crate test_assembler;

    use super::*;
    use endianity::{EndianBuf, LittleEndian};
    use self::test_assembler::{Endian, Section};

    #[test]
    fn test_parse_initial_length_32_ok() {
        let section = Section::with_endian(Endian::Little).L32(0x78563412);
        let buf = section.get_contents().unwrap();

        match parse_initial_length(EndianBuf::<LittleEndian>::new(&buf)) {
            Ok((rest, (length, format))) => {
                assert_eq!(rest.len(), 0);
                assert_eq!(format, Format::Dwarf32);
                assert_eq!(0x78563412, length);
            }
            otherwise => panic!("Unexpected result: {:?}", otherwise),
        }
    }

    #[test]
    fn test_parse_initial_length_64_ok() {
        let section = Section::with_endian(Endian::Little)
            // Dwarf_64_INITIAL_UNIT_LENGTH
            .L32(0xffffffff)
            // Actual length
            .L64(0xffdebc9a78563412);
        let buf = section.get_contents().unwrap();

        match parse_initial_length(EndianBuf::<LittleEndian>::new(&buf)) {
            Ok((rest, (length, format))) => {
                assert_eq!(rest.len(), 0);
                assert_eq!(format, Format::Dwarf64);
                assert_eq!(0xffdebc9a78563412, length);
            }
            otherwise => panic!("Unexpected result: {:?}", otherwise),
        }
    }

    #[test]
    fn test_parse_initial_length_unknown_reserved_value() {
        let section = Section::with_endian(Endian::Little).L32(0xfffffffe);
        let buf = section.get_contents().unwrap();

        match parse_initial_length(EndianBuf::<LittleEndian>::new(&buf)) {
            Err(Error::UnknownReservedLength) => assert!(true),
            otherwise => panic!("Unexpected result: {:?}", otherwise),
        };
    }

    #[test]
    fn test_parse_initial_length_incomplete() {
        let buf = [0xff, 0xff, 0xff]; // Need at least 4 bytes.

        match parse_initial_length(EndianBuf::<LittleEndian>::new(&buf)) {
            Err(Error::UnexpectedEof) => assert!(true),
            otherwise => panic!("Unexpected result: {:?}", otherwise),
        };
    }

    #[test]
    fn test_parse_initial_length_64_incomplete() {
        let section = Section::with_endian(Endian::Little)
            // Dwarf_64_INITIAL_UNIT_LENGTH
            .L32(0xffffffff)
            // Actual length is not long enough.
            .L32(0x78563412);
        let buf = section.get_contents().unwrap();

        match parse_initial_length(EndianBuf::<LittleEndian>::new(&buf)) {
            Err(Error::UnexpectedEof) => assert!(true),
            otherwise => panic!("Unexpected result: {:?}", otherwise),
        };
    }

    #[test]
    fn test_parse_offset_32() {
        let section = Section::with_endian(Endian::Little).L32(0x01234567);
        let buf = section.get_contents().unwrap();

        match parse_offset(EndianBuf::<LittleEndian>::new(&buf), Format::Dwarf32) {
            Ok((rest, val)) => {
                assert_eq!(rest.len(), 0);
                assert_eq!(val, 0x01234567);
            }
            otherwise => panic!("Unexpected result: {:?}", otherwise),
        };
    }

    #[test]
    fn test_parse_offset_64_small() {
        let section = Section::with_endian(Endian::Little).L64(0x01234567);
        let buf = section.get_contents().unwrap();

        match parse_offset(EndianBuf::<LittleEndian>::new(&buf), Format::Dwarf64) {
            Ok((rest, val)) => {
                assert_eq!(rest.len(), 0);
                assert_eq!(val, 0x01234567);
            }
            otherwise => panic!("Unexpected result: {:?}", otherwise),
        };
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn test_parse_offset_64_large() {
        let section = Section::with_endian(Endian::Little).L64(0x0123456789abcdef);
        let buf = section.get_contents().unwrap();

        match parse_offset(EndianBuf::<LittleEndian>::new(&buf), Format::Dwarf64) {
            Ok((rest, val)) => {
                assert_eq!(rest.len(), 0);
                assert_eq!(val, 0x0123456789abcdef);
            }
            otherwise => panic!("Unexpected result: {:?}", otherwise),
        };
    }

    #[test]
    #[cfg(target_pointer_width = "32")]
    fn test_parse_offset_64_large() {
        let section = Section::with_endian(Endian::Little).L64(0x0123456789abcdef);
        let buf = section.get_contents().unwrap();

        match parse_offset(EndianBuf::<LittleEndian>::new(&buf), Format::Dwarf64) {
            Err(Error::UnsupportedOffset) => assert!(true),
            otherwise => panic!("Unexpected result: {:?}", otherwise),
        };
    }

    #[test]
    fn test_parse_address_size_ok() {
        let buf = [0x04];

        match parse_address_size(EndianBuf::<LittleEndian>::new(&buf)) {
            Ok((_, val)) => assert_eq!(val, 4),
            otherwise => panic!("Unexpected result: {:?}", otherwise),
        };
    }
}
