//! Functions for parsing DWARF `.debug_info` and `.debug_types` sections.

use constants;
#[cfg(test)]
use leb128;
use abbrev::{DebugAbbrev, DebugAbbrevOffset, Abbreviations, Abbreviation, AttributeSpecification};
use endianity::{Endianity, EndianBuf};
#[cfg(test)]
use endianity::LittleEndian;
use fallible_iterator::FallibleIterator;
use line::DebugLineOffset;
use loc::DebugLocOffset;
use parser::{Error, Result, Format, DebugMacinfoOffset, parse_u8, parse_u16, parse_u32, parse_u64,
             parse_unsigned_leb, parse_signed_leb, parse_word, parse_address, parse_address_size,
             parse_initial_length, parse_length_uleb_value, parse_null_terminated_string, take};
use ranges::DebugRangesOffset;
use std::cell::Cell;
use std::ffi;
use std::marker::PhantomData;
use std::ops::{Range, RangeFrom, RangeTo};
use std::{u8, u16};
use str::DebugStrOffset;

/// An offset into the `.debug_types` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugTypesOffset(pub u64);

/// A type signature as used in the `.debug_types` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugTypeSignature(pub u64);

/// An offset into the `.debug_info` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugInfoOffset(pub u64);

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
    /// let mut iter = debug_info.units();
    /// while let Some(unit) = iter.next().unwrap() {
    ///     println!("unit's length is {}", unit.unit_length());
    /// }
    /// ```
    ///
    /// Can be [used with
    /// `FallibleIterator`](./index.html#using-with-fallibleiterator).
    pub fn units(&self) -> UnitHeadersIter<'input, Endian> {
        UnitHeadersIter { input: self.debug_info_section }
    }

    /// Get the UnitHeader located at offset from this .debug_info section.
    ///
    ///
    pub fn header_from_offset(&self,
                              offset: DebugInfoOffset)
                              -> Result<UnitHeader<'input, Endian>> {
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
/// `DebugInfo::units`](./struct.DebugInfo.html#method.units) for more detail.
pub struct UnitHeadersIter<'input, Endian>
    where Endian: Endianity
{
    input: EndianBuf<'input, Endian>,
}

impl<'input, Endian> UnitHeadersIter<'input, Endian>
    where Endian: Endianity
{
    /// Advance the iterator to the next unit header.
    pub fn next(&mut self) -> Result<Option<UnitHeader<'input, Endian>>> {
        if self.input.is_empty() {
            Ok(None)
        } else {
            match parse_unit_header(self.input) {
                Ok((rest, header)) => {
                    self.input = rest;
                    Ok(Some(header))
                }
                Err(e) => {
                    self.input = self.input.range_to(..0);
                    Err(e)
                }
            }
        }
    }
}

impl<'input, Endian> FallibleIterator for UnitHeadersIter<'input, Endian>
    where Endian: Endianity
{
    type Item = UnitHeader<'input, Endian>;
    type Error = Error;

    fn next(&mut self) -> ::std::result::Result<Option<Self::Item>, Self::Error> {
        UnitHeadersIter::next(self)
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
        Ok(Some(header)) => {
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
        Ok(Some(header)) => {
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

    assert!(units.next().unwrap().is_none());
}

/// Parse the DWARF version from the compilation unit header.
fn parse_version<Endian>(input: EndianBuf<Endian>) -> Result<(EndianBuf<Endian>, u16)>
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
                                     -> Result<(EndianBuf<Endian>, DebugAbbrevOffset)>
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
                                       -> Result<(EndianBuf<Endian>, DebugInfoOffset)>
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
                                        -> Result<(EndianBuf<Endian>, DebugTypesOffset)>
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

    /// The serialized size of the header for this compilation unit.
    pub fn header_size(&self) -> usize {
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
    pub fn abbreviations(&self, debug_abbrev: DebugAbbrev<Endian>) -> Result<Abbreviations> {
        debug_abbrev.abbreviations(self.debug_abbrev_offset())
    }
}

/// Parse a compilation unit header.
fn parse_unit_header<Endian>(input: EndianBuf<Endian>)
                             -> Result<(EndianBuf<Endian>, UnitHeader<Endian>)>
    where Endian: Endianity
{
    let (rest, (unit_length, format)) = try!(parse_initial_length(input));
    if unit_length as usize > rest.len() {
        return Err(Error::UnexpectedEof);
    }
    let after_unit = rest.range_from(unit_length as usize..);
    let rest = rest.range_to(..unit_length as usize);

    let (rest, version) = try!(parse_version(rest));
    let (rest, offset) = try!(parse_debug_abbrev_offset(rest, format));
    let (rest, address_size) = try!(parse_address_size(rest.into()));

    Ok((after_unit,
        UnitHeader::new(unit_length,
                        version,
                        offset,
                        address_size,
                        format,
                        rest.into())))
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
    ///
    /// Can be [used with
    /// `FallibleIterator`](./index.html#using-with-fallibleiterator).
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
    /// "Refers to some location in the address space of the described program."
    Addr(u64),

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

    /// An offset into the `.debug_loc` section.
    DebugLocRef(DebugLocOffset),

    /// An offset into the `.debug_macinfo` section.
    DebugMacinfoRef(DebugMacinfoOffset),

    /// An offset into the `.debug_ranges` section.
    DebugRangesRef(DebugRangesOffset),

    /// A type signature.
    DebugTypesRef(DebugTypeSignature),

    /// An offset into the `.debug_str` section.
    DebugStrRef(DebugStrOffset),

    /// A null terminated C string, including the final null byte. Not
    /// guaranteed to be UTF-8 or anything like that.
    String(&'input ffi::CStr),

    /// The value of a `DW_AT_encoding` attribute.
    Encoding(constants::DwAte),

    /// The value of a `DW_AT_decimal_sign` attribute.
    DecimalSign(constants::DwDs),

    /// The value of a `DW_AT_endianity` attribute.
    Endianity(constants::DwEnd),

    /// The value of a `DW_AT_accessibility` attribute.
    Accessibility(constants::DwAccess),

    /// The value of a `DW_AT_visibility` attribute.
    Visibility(constants::DwVis),

    /// The value of a `DW_AT_virtuality` attribute.
    Virtuality(constants::DwVirtuality),

    /// The value of a `DW_AT_language` attribute.
    Language(constants::DwLang),

    /// The value of a `DW_AT_address_class` attribute.
    AddressClass(constants::DwAddr),

    /// The value of a `DW_AT_identifier_case` attribute.
    IdentifierCase(constants::DwId),

    /// The value of a `DW_AT_calling_convention` attribute.
    CallingConvention(constants::DwCc),

    /// The value of a `DW_AT_inline` attribute.
    Inline(constants::DwInl),

    /// The value of a `DW_AT_ordering` attribute.
    Ordering(constants::DwOrd),
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
    ///
    /// See "Figure 20. Attribute encodings" and "Figure 21. Attribute form encodings".
    pub fn value(&self) -> AttributeValue<'input, Endian> {
        // Figure 20 shows the possible attribute classes for each name.
        // Figure 21 shows the possible attribute classes for each form.
        // For each attribute name, we need to match on the form, and
        // convert it to one of the classes that is allowed for both
        // the name and the form.
        //
        // The individual class conversions rarely vary for each name,
        // so for each class conversion we define a macro that matches
        // on the allowed forms for that class.
        //
        // For some classes, we don't need to do any conversion, so their
        // macro is empty.  In the future we may want to fill them in to
        // provide strict checking of the forms for each class.  For now,
        // they simply provide a way to document the allowed classes for
        // each name.
        macro_rules! address {
            () => ();
        }
        macro_rules! block {
            () => ();
        }
        macro_rules! constant {
            ($value:ident, $variant:ident) => (
                if let Some(value) = self.$value() {
                    return AttributeValue::$variant(value);
                });
            ($value:ident, $variant:ident, $constant:ident) => (
                if let Some(value) = self.$value() {
                    return AttributeValue::$variant(constants::$constant(value));
                });
        }
        macro_rules! exprloc {
            () => (
                if let Some(value) = self.exprloc_value() {
                    return AttributeValue::Exprloc(value);
                });
        }
        macro_rules! flag {
            () => ();
        }
        macro_rules! loclistptr {
            () => (
                if let Some(offset) = self.offset_value() {
                    return AttributeValue::DebugLocRef(DebugLocOffset(offset));
                });
        }
        macro_rules! lineptr {
            () => (
                if let Some(offset) = self.offset_value() {
                    return AttributeValue::DebugLineRef(DebugLineOffset(offset));
                });
        }
        macro_rules! macptr {
            () => (
                if let Some(offset) = self.offset_value() {
                    return AttributeValue::DebugMacinfoRef(DebugMacinfoOffset(offset));
                });
        }
        macro_rules! rangelistptr {
            () => (
                if let Some(offset) = self.offset_value() {
                    return AttributeValue::DebugRangesRef(DebugRangesOffset(offset));
                });
        }
        macro_rules! reference {
            () => ();
        }
        macro_rules! string {
            () => ();
        }

        // Perform the allowed class conversions for each attribute name.
        match self.name {
            constants::DW_AT_sibling => {
                reference!();
            }
            constants::DW_AT_location => {
                exprloc!();
                loclistptr!();
            }
            constants::DW_AT_name => {
                string!();
            }
            constants::DW_AT_ordering => {
                constant!(u8_value, Ordering, DwOrd);
            }
            constants::DW_AT_byte_size |
            constants::DW_AT_bit_offset |
            constants::DW_AT_bit_size => {
                constant!(udata_value, Udata);
                exprloc!();
                reference!();
            }
            constants::DW_AT_stmt_list => {
                lineptr!();
            }
            constants::DW_AT_low_pc => {
                address!();
            }
            constants::DW_AT_high_pc => {
                address!();
                constant!(udata_value, Udata);
            }
            constants::DW_AT_language => {
                constant!(u16_value, Language, DwLang);
            }
            constants::DW_AT_discr => {
                reference!();
            }
            constants::DW_AT_discr_value => {
                // constant: depends on type of DW_TAG_variant_part,
                // so caller must normalize.
            }
            constants::DW_AT_visibility => {
                constant!(u8_value, Visibility, DwVis);
            }
            constants::DW_AT_import => {
                reference!();
            }
            constants::DW_AT_string_length => {
                exprloc!();
                loclistptr!();
            }
            constants::DW_AT_common_reference => {
                reference!();
            }
            constants::DW_AT_comp_dir => {
                string!();
            }
            constants::DW_AT_const_value => {
                // block, constant, string
            }
            constants::DW_AT_containing_type => {
                reference!();
            }
            constants::DW_AT_default_value => {
                reference!();
            }
            constants::DW_AT_inline => {
                constant!(u8_value, Inline, DwInl);
            }
            constants::DW_AT_is_optional => {
                flag!();
            }
            constants::DW_AT_lower_bound => {
                constant!(udata_value, Udata);
                exprloc!();
                reference!();
            }
            constants::DW_AT_producer => {
                string!();
            }
            constants::DW_AT_prototyped => {
                flag!();
            }
            constants::DW_AT_return_addr => {
                exprloc!();
                loclistptr!();
            }
            constants::DW_AT_start_scope => {
                // TODO: constant
                rangelistptr!();
            }
            constants::DW_AT_bit_stride => {
                constant!(udata_value, Udata);
                exprloc!();
                reference!();
            }
            constants::DW_AT_upper_bound => {
                constant!(udata_value, Udata);
                exprloc!();
                reference!();
            }
            constants::DW_AT_abstract_origin => {
                reference!();
            }
            constants::DW_AT_accessibility => {
                constant!(u8_value, Accessibility, DwAccess);
            }
            constants::DW_AT_address_class => {
                constant!(udata_value, AddressClass, DwAddr);
            }
            constants::DW_AT_artificial => {
                flag!();
            }
            constants::DW_AT_base_types => {
                reference!();
            }
            constants::DW_AT_calling_convention => {
                constant!(u8_value, CallingConvention, DwCc);
            }
            constants::DW_AT_count => {
                // TODO: constant
                exprloc!();
                reference!();
            }
            constants::DW_AT_data_member_location => {
                // TODO: constant
                exprloc!();
                loclistptr!();
            }
            constants::DW_AT_decl_column |
            constants::DW_AT_decl_file |
            constants::DW_AT_decl_line => {
                constant!(udata_value, Udata);
            }
            constants::DW_AT_declaration => {
                flag!();
            }
            constants::DW_AT_discr_list => {
                block!();
            }
            constants::DW_AT_encoding => {
                constant!(u8_value, Encoding, DwAte);
            }
            constants::DW_AT_external => {
                flag!();
            }
            constants::DW_AT_frame_base => {
                exprloc!();
                loclistptr!();
            }
            constants::DW_AT_friend => {
                reference!();
            }
            constants::DW_AT_identifier_case => {
                constant!(u8_value, IdentifierCase, DwId);
            }
            constants::DW_AT_macro_info => {
                macptr!();
            }
            constants::DW_AT_namelist_item => {
                reference!();
            }
            constants::DW_AT_priority => {
                reference!();
            }
            constants::DW_AT_segment => {
                exprloc!();
                loclistptr!();
            }
            constants::DW_AT_specification => {
                reference!();
            }
            constants::DW_AT_static_link => {
                exprloc!();
                loclistptr!();
            }
            constants::DW_AT_type => {
                reference!();
            }
            constants::DW_AT_use_location => {
                exprloc!();
                loclistptr!();
            }
            constants::DW_AT_variable_parameter => {
                flag!();
            }
            constants::DW_AT_virtuality => {
                constant!(u8_value, Virtuality, DwVirtuality);
            }
            constants::DW_AT_vtable_elem_location => {
                exprloc!();
                loclistptr!();
            }
            constants::DW_AT_allocated => {
                // TODO: constant
                exprloc!();
                reference!();
            }
            constants::DW_AT_associated => {
                // TODO: constant
                exprloc!();
                reference!();
            }
            constants::DW_AT_data_location => {
                exprloc!();
            }
            constants::DW_AT_byte_stride => {
                constant!(udata_value, Udata);
                exprloc!();
                reference!();
            }
            constants::DW_AT_entry_pc => {
                address!();
            }
            constants::DW_AT_use_UTF8 => {
                flag!();
            }
            constants::DW_AT_extension => {
                reference!();
            }
            constants::DW_AT_ranges => {
                rangelistptr!();
            }
            constants::DW_AT_trampoline => {
                address!();
                flag!();
                reference!();
                string!();
            }
            constants::DW_AT_call_column |
            constants::DW_AT_call_file |
            constants::DW_AT_call_line => {
                constant!(udata_value, Udata);
            }
            constants::DW_AT_description => {
                string!();
            }
            constants::DW_AT_binary_scale => {
                // TODO: constant
            }
            constants::DW_AT_decimal_scale => {
                // TODO: constant
            }
            constants::DW_AT_small => {
                reference!();
            }
            constants::DW_AT_decimal_sign => {
                constant!(u8_value, DecimalSign, DwDs);
            }
            constants::DW_AT_digit_count => {
                // TODO: constant
            }
            constants::DW_AT_picture_string => {
                string!();
            }
            constants::DW_AT_mutable => {
                flag!();
            }
            constants::DW_AT_threads_scaled => {
                flag!();
            }
            constants::DW_AT_explicit => {
                flag!();
            }
            constants::DW_AT_object_pointer => {
                reference!();
            }
            constants::DW_AT_endianity => {
                constant!(u8_value, Endianity, DwEnd);
            }
            constants::DW_AT_elemental => {
                flag!();
            }
            constants::DW_AT_pure => {
                flag!();
            }
            constants::DW_AT_recursive => {
                flag!();
            }
            constants::DW_AT_signature => {
                reference!();
            }
            constants::DW_AT_main_subprogram => {
                flag!();
            }
            constants::DW_AT_data_bit_offset => {
                // TODO: constant
            }
            constants::DW_AT_const_expr => {
                flag!();
            }
            constants::DW_AT_enum_class => {
                flag!();
            }
            constants::DW_AT_linkage_name => {
                string!();
            }
            _ => {}
        }
        self.value
    }

    /// Try to convert this attribute's value to a u8.
    pub fn u8_value(&self) -> Option<u8> {
        if let Some(value) = self.udata_value() {
            if value <= u8::MAX as u64 {
                return Some(value as u8);
            }
        }
        None
    }

    /// Try to convert this attribute's value to a u16.
    pub fn u16_value(&self) -> Option<u16> {
        if let Some(value) = self.udata_value() {
            if value <= u16::MAX as u64 {
                return Some(value as u16);
            }
        }
        None
    }

    /// Try to convert this attribute's value to an unsigned integer.
    pub fn udata_value(&self) -> Option<u64> {
        Some(match self.value {
            AttributeValue::Data(data) if data.len() == 1 => data[0] as u64,
            AttributeValue::Data(data) if data.len() == 2 => Endian::read_u16(data.into()) as u64,
            AttributeValue::Data(data) if data.len() == 4 => Endian::read_u32(data.into()) as u64,
            AttributeValue::Data(data) if data.len() == 8 => Endian::read_u64(data.into()),
            AttributeValue::Udata(data) => data,
            _ => return None,
        })
    }

    /// Try to convert this attribute's value to an offset.
    ///
    /// Offsets will be `Data` in DWARF version 2/3, and `SecOffset` otherwise.
    pub fn offset_value(&self) -> Option<u64> {
        Some(match self.value {
            AttributeValue::Data(data) if data.len() == 4 => Endian::read_u32(data.into()) as u64,
            AttributeValue::Data(data) if data.len() == 8 => Endian::read_u64(data.into()),
            AttributeValue::SecOffset(offset) => offset,
            _ => return None,
        })
    }

    /// Try to convert this attribute's value to an expression or location.
    ///
    /// Expressions and locations may be `DW_FORM_block*` or `DW_FORM_exprloc`.
    /// The standard doesn't mention `DW_FORM_block*` as a possible form, but
    /// it is encountered in practice.
    fn exprloc_value(&self) -> Option<EndianBuf<'input, Endian>> {
        Some(match self.value {
            AttributeValue::Block(data) => data,
            AttributeValue::Exprloc(data) => data,
            _ => return None,
        })
    }
}

#[test]
fn test_attribute_value() {
    let bytes = [0, 1, 2, 3];
    let buf = EndianBuf::<LittleEndian>::new(&bytes);

    let tests = [(constants::DW_AT_data_member_location,
                  AttributeValue::Block(buf),
                  AttributeValue::Exprloc(buf))];

    for test in tests.iter() {
        let (name, value, expect) = *test;
        let attribute = Attribute {
            name: name,
            value: value,
        };
        assert_eq!(attribute.value(), expect);
    }
}

fn length_u8_value<Endian>(input: EndianBuf<Endian>)
                           -> Result<(EndianBuf<Endian>, EndianBuf<Endian>)>
    where Endian: Endianity
{
    let (rest, len) = try!(parse_u8(input.into()));
    take(len as usize, EndianBuf::new(rest))
}

fn length_u16_value<Endian>(input: EndianBuf<Endian>)
                            -> Result<(EndianBuf<Endian>, EndianBuf<Endian>)>
    where Endian: Endianity
{
    let (rest, len) = try!(parse_u16(input));
    take(len as usize, rest)
}

fn length_u32_value<Endian>(input: EndianBuf<Endian>)
                            -> Result<(EndianBuf<Endian>, EndianBuf<Endian>)>
    where Endian: Endianity
{
    let (rest, len) = try!(parse_u32(input));
    take(len as usize, rest)
}

fn parse_attribute<'input, 'unit, Endian>
    (mut input: EndianBuf<'input, Endian>,
     unit: &'unit UnitHeader<'input, Endian>,
     spec: AttributeSpecification)
     -> Result<(EndianBuf<'input, Endian>, Attribute<'input, Endian>)>
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
                return parse_address(input, unit.address_size()).map(|(rest, addr)| {
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
                return parse_length_uleb_value(input.into()).map(|(rest, block)| {
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
                return parse_length_uleb_value(input.into()).map(|(rest, block)| {
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
                // This is an offset, but DWARF version 2 specifies that DW_FORM_ref_addr
                // has the same size as an address on the target system.  This was changed
                // in DWARF version 3.
                if unit.version() == 2 {
                    return parse_address(input, unit.address_size()).map(|(rest, offset)| {
                        let offset = DebugInfoOffset(offset);
                        let attr = Attribute {
                            name: spec.name(),
                            value: AttributeValue::DebugInfoRef(offset),
                        };
                        (rest, attr)
                    });
                } else {
                    return parse_word(input, unit.format()).map(|(rest, offset)| {
                        let offset = DebugInfoOffset(offset);
                        let attr = Attribute {
                            name: spec.name(),
                            value: AttributeValue::DebugInfoRef(offset),
                        };
                        (rest, attr)
                    });
                }
            }
            constants::DW_FORM_ref_sig8 => {
                return parse_u64(input.into()).map(|(rest, signature)| {
                    let signature = DebugTypeSignature(signature);
                    let attr = Attribute {
                        name: spec.name(),
                        value: AttributeValue::DebugTypesRef(signature),
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
    let value = AttributeValue::Addr(0x04030201);
    test_parse_attribute(&buf, 4, &unit, form, value);
}

#[test]
fn test_parse_attribute_addr8() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let unit = test_parse_attribute_unit::<LittleEndian>(8, Format::Dwarf32);
    let form = constants::DW_FORM_addr;
    let value = AttributeValue::Addr(0x0807060504030201);
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
fn test_parse_attribute_refaddr_version2() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x99, 0x99];
    let mut unit = test_parse_attribute_unit::<LittleEndian>(4, Format::Dwarf32);
    unit.version = 2;
    let form = constants::DW_FORM_ref_addr;
    let value = AttributeValue::DebugInfoRef(DebugInfoOffset(0x04030201));
    test_parse_attribute(&buf, 4, &unit, form, value);
}

#[test]
fn test_parse_attribute_refaddr8_version2() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x99, 0x99];
    let mut unit = test_parse_attribute_unit::<LittleEndian>(8, Format::Dwarf32);
    unit.version = 2;
    let form = constants::DW_FORM_ref_addr;
    let value = AttributeValue::DebugInfoRef(DebugInfoOffset(0x0807060504030201));
    test_parse_attribute(&buf, 8, &unit, form, value);
}

#[test]
fn test_parse_attribute_refsig8() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x99, 0x99];
    let unit = test_parse_attribute_unit_default();
    let form = constants::DW_FORM_ref_sig8;
    let value = AttributeValue::DebugTypesRef(DebugTypeSignature(578437695752307201));
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
///
/// Can be [used with
/// `FallibleIterator`](./index.html#using-with-fallibleiterator).
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
    pub fn next(&mut self) -> Result<Option<Attribute<'input, Endian>>> {
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

impl<'input, 'abbrev, 'entry, 'unit, Endian> FallibleIterator for AttrsIter<'input,
                                                                            'abbrev,
                                                                            'entry,
                                                                            'unit,
                                                                            Endian>
    where Endian: Endianity
{
    type Item = Attribute<'input, Endian>;
    type Error = Error;

    fn next(&mut self) -> ::std::result::Result<Option<Self::Item>, Self::Error> {
        AttrsIter::next(self)
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
                           value: AttributeValue::Addr(0x2a),
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
                           value: AttributeValue::Addr(0x539),
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
    fn after_entry(&self) -> Result<&'input [u8]> {
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
    pub fn next_entry(&mut self) -> Result<Option<()>> {
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
    pub fn next_dfs<'me>
        (&'me mut self)
         -> Result<Option<(isize, &'me DebuggingInformationEntry<'input, 'abbrev, 'unit, Endian>)>> {
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
         -> Result<Option<(&'me DebuggingInformationEntry<'input, 'abbrev, 'unit, Endian>)>> {
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
fn parse_type_signature<Endian>(input: EndianBuf<Endian>)
                                -> Result<(EndianBuf<Endian>, DebugTypeSignature)>
    where Endian: Endianity
{
    let (rest, offset) = try!(parse_u64(input));
    Ok((rest, DebugTypeSignature(offset)))
}

#[test]
fn test_parse_type_signature_ok() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    match parse_type_signature(EndianBuf::<LittleEndian>::new(&buf)) {
        Ok((_, val)) => assert_eq!(val, DebugTypeSignature(0x0807060504030201)),
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
                             -> Result<(EndianBuf<Endian>, DebugTypesOffset)>
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
    /// let mut iter = debug_types.units();
    /// while let Some(unit) = iter.next().unwrap() {
    ///     println!("unit's length is {}", unit.unit_length());
    /// }
    /// ```
    ///
    /// Can be [used with
    /// `FallibleIterator`](./index.html#using-with-fallibleiterator).
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

impl<'input, Endian> TypeUnitHeadersIter<'input, Endian>
    where Endian: Endianity
{
    /// Advance the iterator to the next type unit header.
    pub fn next(&mut self) -> Result<Option<TypeUnitHeader<'input, Endian>>> {
        if self.input.is_empty() {
            Ok(None)
        } else {
            match parse_type_unit_header(self.input) {
                Ok((rest, header)) => {
                    self.input = rest;
                    Ok(Some(header))
                }
                Err(e) => {
                    self.input = self.input.range_to(..0);
                    Err(e)
                }
            }
        }
    }
}

impl<'input, Endian> FallibleIterator for TypeUnitHeadersIter<'input, Endian>
    where Endian: Endianity
{
    type Item = TypeUnitHeader<'input, Endian>;
    type Error = Error;

    fn next(&mut self) -> ::std::result::Result<Option<Self::Item>, Self::Error> {
        TypeUnitHeadersIter::next(self)
    }
}

/// The header of a type unit's debugging information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypeUnitHeader<'input, Endian>
    where Endian: Endianity
{
    header: UnitHeader<'input, Endian>,
    type_signature: DebugTypeSignature,
    type_offset: DebugTypesOffset,
}

impl<'input, Endian> TypeUnitHeader<'input, Endian>
    where Endian: Endianity
{
    /// Construct a new `TypeUnitHeader`.
    fn new(header: UnitHeader<'input, Endian>,
           type_signature: DebugTypeSignature,
           type_offset: DebugTypesOffset)
           -> TypeUnitHeader<'input, Endian> {
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

    /// Whether this type unit is encoded in 64- or 32-bit DWARF.
    pub fn format(&self) -> Format {
        self.header.format
    }

    /// Get the unique type signature for this type unit.
    pub fn type_signature(&self) -> DebugTypeSignature {
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
    pub fn abbreviations(&self, debug_abbrev: DebugAbbrev<Endian>) -> Result<Abbreviations> {
        debug_abbrev.abbreviations(self.debug_abbrev_offset())
    }
}

/// Parse a type unit header.
fn parse_type_unit_header<Endian>(input: EndianBuf<Endian>)
                                  -> Result<(EndianBuf<Endian>, TypeUnitHeader<Endian>)>
    where Endian: Endianity
{
    let (after_unit, mut header) = try!(parse_unit_header(input));
    let (rest, signature) = try!(parse_type_signature(header.entries_buf));
    let (rest, offset) = try!(parse_type_offset(rest, header.format()));
    header.entries_buf = rest;
    Ok((after_unit, TypeUnitHeader::new(header, signature, offset)))
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
                                                           &[]),
                                           DebugTypeSignature(0xdeadbeefdeadbeef),
                                           DebugTypesOffset(0x7856341278563412)))
        },
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    }
}
