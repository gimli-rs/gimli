//! Functions for parsing DWARF `.debug_info` and `.debug_types` sections.

use constants;
use abbrev::{DebugAbbrev, DebugAbbrevOffset, Abbreviations, Abbreviation, AttributeSpecification};
use endianity::{Endianity, EndianBuf};
use fallible_iterator::FallibleIterator;
use line::DebugLineOffset;
use loc::DebugLocOffset;
use parser::{Error, Result, Format, DebugMacinfoOffset, parse_u8, parse_u16, parse_u32, parse_u64,
             parse_unsigned_leb, parse_signed_leb, parse_offset, parse_address,
             parse_address_size, parse_initial_length, parse_length_uleb_value,
             parse_null_terminated_string, take, parse_u64_as_offset, parse_uleb_as_offset,
             parse_address_as_offset, u64_to_offset};
use ranges::DebugRangesOffset;
use std::cell::Cell;
use std::ffi;
use std::marker::PhantomData;
use std::ops::{Range, RangeFrom, RangeTo};
use std::{u8, u16};
use str::{DebugStr, DebugStrOffset};

/// An offset into the `.debug_types` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugTypesOffset(pub usize);

/// A type signature as used in the `.debug_types` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugTypeSignature(pub u64);

/// An offset into the `.debug_info` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugInfoOffset(pub usize);

/// An offset into the current compilation or type unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub struct UnitOffset(pub usize);

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
    pub fn units(&self) -> CompilationUnitHeadersIter<'input, Endian> {
        CompilationUnitHeadersIter {
            input: self.debug_info_section,
            offset: DebugInfoOffset(0),
        }
    }

    /// Get the CompilationUnitHeader located at offset from this .debug_info section.
    ///
    ///
    pub fn header_from_offset(&self,
                              offset: DebugInfoOffset)
                              -> Result<CompilationUnitHeader<'input, Endian>> {
        if self.debug_info_section.len() < offset.0 {
            return Err(Error::UnexpectedEof);
        }

        let input = self.debug_info_section.range_from(offset.0..);
        match CompilationUnitHeader::parse(input, offset) {
            Ok((_, header)) => Ok(header),
            Err(e) => Err(e),
        }
    }
}

/// An iterator over the compilation- and partial-units of a section.
///
/// See the [documentation on
/// `DebugInfo::units`](./struct.DebugInfo.html#method.units) for more detail.
#[derive(Clone, Debug)]
pub struct CompilationUnitHeadersIter<'input, Endian>
    where Endian: Endianity
{
    input: EndianBuf<'input, Endian>,
    offset: DebugInfoOffset,
}

impl<'input, Endian> CompilationUnitHeadersIter<'input, Endian>
    where Endian: Endianity
{
    /// Advance the iterator to the next unit header.
    pub fn next(&mut self) -> Result<Option<CompilationUnitHeader<'input, Endian>>> {
        if self.input.is_empty() {
            Ok(None)
        } else {
            match CompilationUnitHeader::parse(self.input, self.offset) {
                Ok((rest, header)) => {
                    self.offset.0 += self.input.len() - rest.len();
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

impl<'input, Endian> FallibleIterator for CompilationUnitHeadersIter<'input, Endian>
    where Endian: Endianity
{
    type Item = CompilationUnitHeader<'input, Endian>;
    type Error = Error;

    fn next(&mut self) -> ::std::result::Result<Option<Self::Item>, Self::Error> {
        CompilationUnitHeadersIter::next(self)
    }
}

/// The header of a compilation unit's debugging information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompilationUnitHeader<'input, Endian>
    where Endian: Endianity
{
    header: UnitHeader<'input, Endian>,
    offset: DebugInfoOffset,
}

impl<'input, Endian> CompilationUnitHeader<'input, Endian>
    where Endian: Endianity
{
    /// Return the serialized size of the compilation unit header for the given
    /// DWARF format.
    pub fn size_of_header(format: Format) -> usize {
        UnitHeader::<Endian>::size_of_header(format)
    }

    /// Get the offset of this compilation unit within the .debug_info section.
    pub fn offset(&self) -> DebugInfoOffset {
        self.offset
    }

    /// Get the length of the debugging info for this compilation unit, not
    /// including the byte length of the encoded length itself.
    pub fn unit_length(&self) -> u64 {
        self.header.unit_length
    }

    /// Get the length of the debugging info for this compilation unit,
    /// including the byte length of the encoded length itself.
    pub fn length_including_self(&self) -> u64 {
        self.header.length_including_self()
    }

    /// Get the DWARF version of the debugging info for this compilation unit.
    pub fn version(&self) -> u16 {
        self.header.version
    }

    /// The offset into the `.debug_abbrev` section for this compilation unit's
    /// debugging information entries' abbreviations.
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

    /// The serialized size of the header for this compilation unit.
    pub fn header_size(&self) -> usize {
        self.header.header_size()
    }

    /// Navigate this compilation unit's `DebuggingInformationEntry`s.
    pub fn entries<'me, 'abbrev>(&'me self,
                                 abbreviations: &'abbrev Abbreviations)
                                 -> Result<EntriesCursor<'input, 'abbrev, 'me, Endian>> {
        self.header.entries(abbreviations)
    }

    /// Navigate this compilation unit's `DebuggingInformationEntry`s as a tree.
    pub fn entries_tree<'me, 'abbrev>(&'me self,
                                      abbreviations: &'abbrev Abbreviations)
                                      -> Result<EntriesTree<'input, 'abbrev, 'me, Endian>> {
        self.header.entries_tree(abbreviations)
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
        self.header.abbreviations(debug_abbrev)
    }

    /// Parse a compilation unit header.
    fn parse(input: EndianBuf<Endian>,
             offset: DebugInfoOffset)
             -> Result<(EndianBuf<Endian>, CompilationUnitHeader<Endian>)> {
        let (after_unit, header) = try!(parse_unit_header(input));
        Ok((after_unit,
            CompilationUnitHeader {
            header: header,
            offset: offset,
        }))
    }
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

/// Parse the `debug_abbrev_offset` in the compilation unit header.
fn parse_debug_abbrev_offset<Endian>(input: EndianBuf<Endian>,
                                     format: Format)
                                     -> Result<(EndianBuf<Endian>, DebugAbbrevOffset)>
    where Endian: Endianity
{
    parse_offset(input, format).map(|(rest, offset)| (rest, DebugAbbrevOffset(offset)))
}

/// Parse the `debug_info_offset` in the arange header.
pub fn parse_debug_info_offset<Endian>(input: EndianBuf<Endian>,
                                       format: Format)
                                       -> Result<(EndianBuf<Endian>, DebugInfoOffset)>
    where Endian: Endianity
{
    parse_offset(input, format).map(|(rest, offset)| (rest, DebugInfoOffset(offset)))
}

/// Parse the `debug_types_offset` in the pubtypes header.
pub fn parse_debug_types_offset<Endian>(input: EndianBuf<Endian>,
                                        format: Format)
                                        -> Result<(EndianBuf<Endian>, DebugTypesOffset)>
    where Endian: Endianity
{
    parse_offset(input, format).map(|(rest, offset)| (rest, DebugTypesOffset(offset)))
}

/// The common fields for the headers of compilation units and
/// type units.
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

    /// Return the serialized size of the common unit header for the given
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
    /// including the byte length of the encoded length itself.
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
        self.length_including_self() as usize - self.entries_buf.len()
    }

    fn is_valid_offset(&self, offset: UnitOffset) -> bool {
        let size_of_header = self.header_size();
        if offset.0 < size_of_header {
            return false;
        }

        let relative_to_entries_buf = offset.0 - size_of_header;
        relative_to_entries_buf < self.entries_buf.len()
    }

    /// Get the underlying bytes for the supplied range.
    pub fn range(&self, idx: Range<UnitOffset>) -> &'input [u8] {
        assert!(self.is_valid_offset(idx.start));
        assert!(self.is_valid_offset(idx.end));
        assert!(idx.start <= idx.end);
        let size_of_header = self.header_size();
        let start = idx.start.0 - size_of_header;
        let end = idx.end.0 - size_of_header;
        &self.entries_buf.0[start..end]
    }

    /// Get the underlying bytes for the supplied range.
    pub fn range_from(&self, idx: RangeFrom<UnitOffset>) -> &'input [u8] {
        assert!(self.is_valid_offset(idx.start));
        let start = idx.start.0 - self.header_size();
        &self.entries_buf.0[start..]
    }

    /// Get the underlying bytes for the supplied range.
    pub fn range_to(&self, idx: RangeTo<UnitOffset>) -> &'input [u8] {
        assert!(self.is_valid_offset(idx.end));
        let end = idx.end.0 - self.header_size();
        &self.entries_buf.0[..end]
    }

    /// Navigate this unit's `DebuggingInformationEntry`s.
    pub fn entries<'me, 'abbrev>(&'me self,
                                 abbreviations: &'abbrev Abbreviations)
                                 -> Result<EntriesCursor<'input, 'abbrev, 'me, Endian>> {
        EntriesCursor::new(self.entries_buf.into(), self, abbreviations)
    }

    /// Navigate this unit's `DebuggingInformationEntry`s as a tree.
    pub fn entries_tree<'me, 'abbrev>(&'me self,
                                      abbreviations: &'abbrev Abbreviations)
                                      -> Result<EntriesTree<'input, 'abbrev, 'me, Endian>> {
        let cursor = try!(self.entries(abbreviations));
        Ok(cursor.tree())
    }

    /// Parse this unit's abbreviations.
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

/// A Debugging Information Entry (DIE).
///
/// DIEs have a set of attributes and optionally have children DIEs as well.
#[derive(Clone, Debug)]
pub struct DebuggingInformationEntry<'input, 'abbrev, 'unit, Endian>
    where 'input: 'unit,
          Endian: Endianity + 'unit
{
    offset: UnitOffset,
    attrs_slice: &'input [u8],
    after_attrs: Cell<Option<&'input [u8]>>,
    abbrev: &'abbrev Abbreviation,
    unit: &'unit UnitHeader<'input, Endian>,
}

impl<'input, 'abbrev, 'unit, Endian> DebuggingInformationEntry<'input, 'abbrev, 'unit, Endian>
    where Endian: Endianity
{
    /// Get this entry's code.
    pub fn code(&self) -> u64 {
        self.abbrev.code()
    }

    /// Get this entry's offset.
    pub fn offset(&self) -> UnitOffset {
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
    /// # let mut cursor = unit.entries(&abbrevs).unwrap();
    /// # let mut get_some_entry = || cursor.current().unwrap();
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
    /// let cursor = unit.entries(&abbrevs).expect("Should parse root entry");
    /// let entry = cursor.current().expect("Should have at least one entry");
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

    #[inline(always)]
    fn parse(input: &'input [u8], unit: &'unit UnitHeader<'input, Endian>, abbreviations: &'abbrev Abbreviations)
        -> Result<(&'input [u8], Option<Self>)>
    {
        let (rest, code) = try!(parse_unsigned_leb(input));
        if code == 0 {
            return Ok((rest, None));
        }
        let abbrev = match abbreviations.get(code) {
            Some(abbrev) => abbrev,
            None => return Err(Error::UnknownAbbreviation),
        };

        let ptr = input.as_ptr() as *const u8 as usize;
        let start_ptr = unit.entries_buf.as_ptr() as *const u8 as usize;
        let offset = UnitOffset(ptr - start_ptr + unit.header_size());

        Ok((rest, Some(DebuggingInformationEntry {
                offset: offset,
                attrs_slice: rest,
                after_attrs: Cell::new(None),
                abbrev: abbrev,
                unit: unit,
            })))
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
    SecOffset(usize),

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

    /// An index into the filename entries from the line number information
    /// table for the compilation unit containing this value.
    FileIndex(u64),
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
                // TODO: constant: sign depends on DW_AT_type.
                block!();
                string!();
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
                // TODO: constant: sign depends on DW_AT_type.
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
                // TODO: constant: sign depends on DW_AT_type.
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
                // Constants must be handled before loclistptr so that DW_FORM_data4/8
                // are correctly interpreted for DWARF version 4+.
                constant!(udata_value, Udata);
                exprloc!();
                loclistptr!();
            }
            constants::DW_AT_decl_column => {
                constant!(udata_value, Udata);
            }
            constants::DW_AT_decl_file => {
                constant!(udata_value, FileIndex);
            }
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
            constants::DW_AT_call_column => {
                constant!(udata_value, Udata);
            }
            constants::DW_AT_call_file => {
                constant!(udata_value, FileIndex);
            }
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

    /// Try to convert this attribute's value to a signed integer.
    pub fn sdata_value(&self) -> Option<i64> {
        Some(match self.value {
            AttributeValue::Data(data) if data.len() == 1 => data[0] as i8 as i64,
            AttributeValue::Data(data) if data.len() == 2 => {
                Endian::read_u16(data.into()) as i16 as i64
            }
            AttributeValue::Data(data) if data.len() == 4 => {
                Endian::read_u32(data.into()) as i32 as i64
            }
            AttributeValue::Data(data) if data.len() == 8 => Endian::read_u64(data.into()) as i64,
            AttributeValue::Sdata(data) => data,
            _ => return None,
        })
    }

    /// Try to convert this attribute's value to an offset.
    ///
    /// Offsets will be `Data` in DWARF version 2/3, and `SecOffset` otherwise.
    pub fn offset_value(&self) -> Option<usize> {
        match self.value {
            AttributeValue::Data(data) => {
                let offset = match data.len() {
                    4 => Endian::read_u32(data.into()) as u64,
                    8 => Endian::read_u64(data.into()),
                    _ => return None,
                };
                u64_to_offset(offset).ok()
            }
            AttributeValue::SecOffset(offset) => Some(offset),
            _ => None,
        }
    }

    /// Try to convert this attribute's value to an expression or location buffer.
    ///
    /// Expressions and locations may be `DW_FORM_block*` or `DW_FORM_exprloc`.
    /// The standard doesn't mention `DW_FORM_block*` as a possible form, but
    /// it is encountered in practice.
    fn exprloc_value(&self) -> Option<EndianBuf<'input, Endian>> {
        Some(match self.value {
            AttributeValue::Block(data) |
            AttributeValue::Exprloc(data) => data,
            _ => return None,
        })
    }

    /// Try to return this attribute's value as a string reference.
    ///
    /// If this attribute's value is either an inline `DW_FORM_string` string,
    /// or a `DW_FORM_strp` reference to an offset into the `.debug_str`
    /// section, return the attribute's string value as `Some`. Other attribute
    /// value forms are returned as `None`.
    pub fn string_value(&self, debug_str: &DebugStr<'input, Endian>) -> Option<&'input ffi::CStr> {
        match self.value {
            AttributeValue::String(string) => Some(string),
            AttributeValue::DebugStrRef(offset) => debug_str.get_str(offset).ok(),
            _ => None,
        }
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
                // DWARF version 2/3 may use DW_FORM_data4/8 for section offsets.
                // Generally we can defer interpretation of these until
                // `AttributeValue::value()`, but this is ambiguous for
                // `DW_AT_data_member_location`.
                if (unit.version() == 2 || unit.version() == 3) &&
                   spec.name() == constants::DW_AT_data_member_location {
                    let (rest, offset) = try!(parse_u32(input.into()));
                    let offset = try!(u64_to_offset(offset as u64));
                    let attr = Attribute {
                        name: spec.name(),
                        value: AttributeValue::SecOffset(offset as usize),
                    };
                    return Ok((rest, attr));
                } else {
                    return take(4, input.into()).map(|(rest, data)| {
                        let attr = Attribute {
                            name: spec.name(),
                            value: AttributeValue::Data(data),
                        };
                        (rest, attr)
                    });
                }
            }
            constants::DW_FORM_data8 => {
                // DWARF version 2/3 may use DW_FORM_data4/8 for section offsets.
                // Generally we can defer interpretation of these until
                // `AttributeValue::value()`, but this is ambiguous for
                // `DW_AT_data_member_location`.
                if (unit.version() == 2 || unit.version() == 3) &&
                   spec.name() == constants::DW_AT_data_member_location {
                    let (rest, offset) = try!(parse_u64(input.into()));
                    let offset = try!(u64_to_offset(offset));
                    let attr = Attribute {
                        name: spec.name(),
                        value: AttributeValue::SecOffset(offset as usize),
                    };
                    return Ok((rest, attr));
                } else {
                    return take(8, input.into()).map(|(rest, data)| {
                        let attr = Attribute {
                            name: spec.name(),
                            value: AttributeValue::Data(data),
                        };
                        (rest, attr)
                    });
                }
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
                return parse_offset(input.into(), unit.format()).map(|(rest, offset)| {
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
                        value: AttributeValue::UnitRef(UnitOffset(reference as usize)),
                    };
                    (EndianBuf::new(rest), attr)
                });
            }
            constants::DW_FORM_ref2 => {
                return parse_u16(input.into()).map(|(rest, reference)| {
                    let attr = Attribute {
                        name: spec.name(),
                        value: AttributeValue::UnitRef(UnitOffset(reference as usize)),
                    };
                    (rest, attr)
                });
            }
            constants::DW_FORM_ref4 => {
                return parse_u32(input.into()).map(|(rest, reference)| {
                    let attr = Attribute {
                        name: spec.name(),
                        value: AttributeValue::UnitRef(UnitOffset(reference as usize)),
                    };
                    (rest, attr)
                });
            }
            constants::DW_FORM_ref8 => {
                return parse_u64_as_offset(input.into()).map(|(rest, reference)| {
                    let attr = Attribute {
                        name: spec.name(),
                        value: AttributeValue::UnitRef(UnitOffset(reference)),
                    };
                    (rest, attr)
                });
            }
            constants::DW_FORM_ref_udata => {
                return parse_uleb_as_offset(input.into()).map(|(rest, reference)| {
                    let attr = Attribute {
                        name: spec.name(),
                        value: AttributeValue::UnitRef(UnitOffset(reference)),
                    };
                    (rest, attr)
                });
            }
            constants::DW_FORM_ref_addr => {
                // This is an offset, but DWARF version 2 specifies that DW_FORM_ref_addr
                // has the same size as an address on the target system.  This was changed
                // in DWARF version 3.
                if unit.version() == 2 {
                    return parse_address_as_offset(input, unit.address_size())
                        .map(|(rest, offset)| {
                            let offset = DebugInfoOffset(offset);
                            let attr = Attribute {
                                name: spec.name(),
                                value: AttributeValue::DebugInfoRef(offset),
                            };
                            (rest, attr)
                        });
                } else {
                    return parse_offset(input, unit.format()).map(|(rest, offset)| {
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
                return parse_offset(input.into(), unit.format()).map(|(rest, offset)| {
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
    #[inline(always)]
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

impl<'input, 'abbrev, 'entry, 'unit, Endian> FallibleIterator
    for AttrsIter<'input, 'abbrev, 'entry, 'unit, Endian>
    where Endian: Endianity
{
    type Item = Attribute<'input, Endian>;
    type Error = Error;

    fn next(&mut self) -> ::std::result::Result<Option<Self::Item>, Self::Error> {
        AttrsIter::next(self)
    }
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
    abbreviations: &'abbrev Abbreviations,
    current: DebuggingInformationEntry<'input, 'abbrev, 'unit, Endian>,
}

impl<'input, 'abbrev, 'unit, Endian> EntriesCursor<'input, 'abbrev, 'unit, Endian>
    where Endian: Endianity
{
    fn new(input: &'input [u8], unit: &'unit UnitHeader<'input, Endian>, abbreviations: &'abbrev Abbreviations) -> Result<Self> {
        match try!(DebuggingInformationEntry::parse(input, unit, abbreviations)) {
            (_, Some(entry)) => Ok(EntriesCursor {
                abbreviations: abbreviations,
                current: entry,
            }),
            (_, None) => Err(Error::UnexpectedNull),
        }
    }

    /// Get a reference to the entry that the cursor is currently pointing to.
    ///
    /// If the cursor is not pointing at an entry, or if the current entry is a
    /// null entry, then `None` is returned.
    #[inline]
    pub fn current(&self) -> &DebuggingInformationEntry<'input, 'abbrev, 'unit, Endian> {
        &self.current
    }

    /// Return the input buffer after the current entry.
    fn after_entry(&self) -> Result<&'input [u8]> {
        if let Some(after_attrs) = self.current.after_attrs.get() {
            Ok(after_attrs)
        } else {
            let mut attrs = self.current.attrs();
            while let Some(_) = try!(attrs.next()) {
            }
            Ok(self.current.after_attrs
                .get()
                .expect("should have after_attrs after iterating attrs"))
        }
    }

    /// Move the cursor to the next DIE in the tree.
    ///
    /// Returns `Some` if there is a next entry, even if this entry is null.
    /// If there is no next entry, then `None` is returned.
    pub fn next_entry(&mut self) -> Result<Option<()>> {
        Ok(None)
            /*
        let input = try!(self.after_entry());
        if input.len() == 0 {
            self.input = input;
            return Ok(None);
        }

        match try!(DebuggingInformationEntry::parse(input, self.current.unit, self.abbreviations)) {
            (_, Some(entry)) => {
                self.input = &[];
                self.current = entry;
                self.current_valid = true;
            }
            (rest, None) => {
                self.input = rest;
                self.current_valid = false;
            }
        }
        Ok(Some(()))
        */
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
    /// let mut cursor = unit.entries(&abbrevs).unwrap();
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
    pub fn next_dfs
        (&mut self)
         -> Result<Option<(isize, &DebuggingInformationEntry<'input, 'abbrev, 'unit, Endian>)>> {
        let mut delta_depth = self.current.abbrev.has_children() as isize;
        let mut input = try!(self.after_entry());
        loop {
            // Keep eating null entries that mark the end of an entry's children.
            // This is a micro optimization; parse() can handle reading null
            // entries, but this while loop is slightly more efficient.
            // Note that this doesn't handle unusual LEB128 encodings of zero
            // such as [0x80, 0x00]; they are still handled by parse().
            while input.len() > 0 && input[0] == 0 {
                delta_depth -= 1;
                input = &input[1..];
            }
            if input.len() == 0 {
                return Ok(None);
            }
            // The next entry should be the one we want.
            match try!(DebuggingInformationEntry::parse(input, self.current.unit, self.abbreviations)) {
                (_, Some(entry)) => {
                    self.current = entry;
                    return Ok(Some((delta_depth, &self.current)));
                }
                (rest, None) => {
                    // parse() read a null entry.  These are normally handled above,
                    // so this must have been an unusual LEB 128 encoding of zero.
                    delta_depth -= 1;
                    input = rest;
                }
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
    /// let mut cursor = unit.entries(&abbrevs).unwrap();
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
    pub fn next_sibling
        (&mut self)
         -> Result<Option<(&DebuggingInformationEntry<'input, 'abbrev, 'unit, Endian>)>> {
        // Loop until we find an entry at the current level.
        let mut entry = self.current.clone();
        let mut depth = 0;
        loop {
            let mut input;
            if entry.has_children() {
                // This entry has children, so the next entry is
                // down one level.
                depth += 1;

                let sibling_ptr = entry.attr_value(constants::DW_AT_sibling);
                if let Some(AttributeValue::UnitRef(offset)) = sibling_ptr {
                    if entry.unit.is_valid_offset(offset) {
                        // Fast path: this entry has a DW_AT_sibling
                        // attribute pointing to its sibling, so jump
                        // to it (which takes us back up a level).
                        input = self.current.unit.range_from(offset..);
                        depth -= 1;
                    } else {
                        input = try!(self.after_entry());
                    }
                } else {
                    input = try!(self.after_entry());
                }
            } else {
                input = try!(self.after_entry());
            }

            loop {
                if input.len() == 0 {
                    // TODO: set self.input
                    return Ok(None);
                }
                match try!(DebuggingInformationEntry::parse(input, self.current.unit, self.abbreviations)) {
                    (_, Some(next_entry)) => {
                        entry = next_entry;
                        break;
                    }
                    (rest, None) => {
                        if depth == 0 {
                            // TODO: set self.input
                            return Ok(None);
                        }
                        depth -= 1;
                        input = rest;
                    }
                }
            }

            if depth == 0 {
                // Found an entry at the current level.
                self.current = entry;
                return Ok(Some(&self.current));
            }
        }
    }

    /// Return a tree view of the entries that have the current entry as the root.
    pub fn tree(self) -> EntriesTree<'input, 'abbrev, 'unit, Endian> {
        EntriesTree::new(self)
    }
}

/// The state information for a tree view of the Debugging Information Entries.
///
/// The `EntriesTree` can be used to recursively iterate through the DIE
/// tree, following the parent/child relationships. It maintains a single
/// `EntriesCursor` that is used to parse the entries, allowing it to avoid
/// any duplicate parsing of entries.
///
/// ## Example Usage
/// ```rust,no_run
/// extern crate gimli;
///
/// # fn example() -> Result<(), gimli::Error> {
/// # let debug_info = gimli::DebugInfo::<gimli::LittleEndian>::new(&[]);
/// # let get_some_unit = || debug_info.units().next().unwrap().unwrap();
/// let unit = get_some_unit();
/// # let debug_abbrev = gimli::DebugAbbrev::<gimli::LittleEndian>::new(&[]);
/// # let get_abbrevs_for_unit = |_| unit.abbreviations(debug_abbrev).unwrap();
/// let abbrevs = get_abbrevs_for_unit(&unit);
///
/// let mut tree = try!(unit.entries_tree(&abbrevs));
/// try!(process_tree(tree.iter()));
/// # Ok(())
/// # }
///
/// fn process_tree<E>(mut iter: gimli::EntriesTreeIter<E>) -> gimli::Result<()>
///     where E: gimli::Endianity
/// {
///     if let Some(entry) = iter.entry() {
///         // Examine the entry attributes.
///     }
///     while let Some(child) = try!(iter.next()) {
///         // Recursively process a child.
///         process_tree(child);
///     }
///     Ok(())
/// }
/// ```
#[derive(Clone, Debug)]
pub struct EntriesTree<'input, 'abbrev, 'unit, Endian>
    where 'input: 'unit,
          Endian: Endianity + 'unit
{
    start: EntriesCursor<'input, 'abbrev, 'unit, Endian>,
    cursor: EntriesCursor<'input, 'abbrev, 'unit, Endian>,
    // The depth of the entry that cursor::next_sibling() will return.
    depth: isize,
}

impl<'input, 'abbrev, 'unit, Endian> EntriesTree<'input, 'abbrev, 'unit, Endian>
    where Endian: Endianity
{
    fn new(cursor: EntriesCursor<'input, 'abbrev, 'unit, Endian>) -> Self {
        let start = cursor.clone();
        EntriesTree {
            start: start,
            cursor: cursor,
            depth: 0,
        }
    }

    /// Returns an iterator for the entries that are children of the current entry.
    pub fn iter<'me>(&'me mut self) -> EntriesTreeIter<'input, 'abbrev, 'unit, 'me, Endian> {
        self.cursor = self.start.clone();
        self.depth = 0;
        EntriesTreeIter::new(self, 1)
    }

    /// Move the cursor to the next entry at the specified depth.
    ///
    /// Requires `depth <= self.depth + 1`.
    ///
    /// Returns `true` if successful.
    fn next(&mut self, _depth: isize) -> Result<bool> {
        Ok(false)
        /*
        if self.depth < depth {
            debug_assert_eq!(self.depth + 1, depth);
            if !self.cursor.current().map(|entry| entry.has_children()).unwrap_or(false) {
                // Never any children.
                return Ok(false);
            }
            // The next entry is the child.
            try!(self.cursor.next_entry());
            if self.cursor.current().is_none() {
                // No children, don't adjust depth.
                return Ok(false);
            } else {
                // Got a child, next_sibling is now at the child depth.
                self.depth += 1;
                return Ok(true);
            }
        }

        loop {
            if self.cursor.current().is_some() {
                try!(self.cursor.next_sibling());
            } else {
                try!(self.cursor.next_entry());
            }
            if self.depth == depth {
                if self.cursor.current().is_none() {
                    // No more entries at the target depth.
                    self.depth -= 1;
                    return Ok(false);
                } else {
                    // Got a child at the target depth.
                    return Ok(true);
                }
            }
            if self.cursor.current().is_none() {
                self.depth -= 1;
            }
        }
        */
    }
}

/// An iterator that allows recursive traversal of the Debugging
/// Information Entry tree.
///
/// An `EntriesTreeIter` for the root node of a tree can be obtained
/// via [`EntriesTree::iter`](./struct.EntriesTree.html#method.iter).
///
/// The items returned by this iterator are also `EntriesTreeIter`s,
/// which allow traversal of grandchildren, etc.
#[derive(Debug)]
pub struct EntriesTreeIter<'input, 'abbrev, 'unit, 'tree, Endian>
    where 'input: 'unit,
          'abbrev: 'tree,
          'unit: 'tree,
          Endian: Endianity + 'unit
{
    tree: &'tree mut EntriesTree<'input, 'abbrev, 'unit, Endian>,
    depth: isize,
    state: EntriesTreeIterState,
}

#[derive(Debug, PartialEq, Eq)]
enum EntriesTreeIterState {
    Parent,
    Child,
    None,
}

impl<'input, 'abbrev, 'unit, 'tree, Endian> EntriesTreeIter<'input, 'abbrev, 'unit, 'tree, Endian>
    where Endian: Endianity
{
    fn new(tree: &'tree mut EntriesTree<'input, 'abbrev, 'unit, Endian>,
           depth: isize)
           -> EntriesTreeIter<'input, 'abbrev, 'unit, 'tree, Endian> {
        EntriesTreeIter {
            tree: tree,
            depth: depth,
            state: EntriesTreeIterState::Parent,
        }
    }

    /// Returns the current entry in the tree.
    ///
    /// This function should only be called when the `EntriesTreeIter`
    /// is first created.  This will return the parent entry of the iterator.
    /// TODO: prevent calling after `next`.
    pub fn entry(&self) -> &DebuggingInformationEntry<'input, 'abbrev, 'unit, Endian> {
        self.tree.cursor.current()
    }

    /// Returns an iterator for the next child entry.
    ///
    /// The returned iterator can be used to both obtain the child entry, and recursively
    /// iterate over the children of the child entry.
    ///
    /// Returns `None` if there are no more children.
    pub fn next<'me>(&'me mut self)
                     -> Result<Option<EntriesTreeIter<'input, 'abbrev, 'unit, 'me, Endian>>> {
        if self.state == EntriesTreeIterState::None {
            Ok(None)
        } else if try!(self.tree.next(self.depth)) {
            self.state = EntriesTreeIterState::Child;
            Ok(Some(EntriesTreeIter::new(self.tree, self.depth + 1)))
        } else {
            self.state = EntriesTreeIterState::None;
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

/// Parse a type unit header's type offset.
fn parse_type_offset<Endian>(input: EndianBuf<Endian>,
                             format: Format)
                             -> Result<(EndianBuf<Endian>, UnitOffset)>
    where Endian: Endianity
{
    parse_offset(input, format).map(|(rest, offset)| (rest, UnitOffset(offset)))
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
        TypeUnitHeadersIter {
            input: self.debug_types_section,
            offset: DebugTypesOffset(0),
        }
    }
}

/// An iterator over the type-units of this `.debug_types` section.
///
/// See the [documentation on
/// `DebugTypes::units`](./struct.DebugTypes.html#method.units) for
/// more detail.
#[derive(Clone, Debug)]
pub struct TypeUnitHeadersIter<'input, Endian>
    where Endian: Endianity
{
    input: EndianBuf<'input, Endian>,
    offset: DebugTypesOffset,
}

impl<'input, Endian> TypeUnitHeadersIter<'input, Endian>
    where Endian: Endianity
{
    /// Advance the iterator to the next type unit header.
    pub fn next(&mut self) -> Result<Option<TypeUnitHeader<'input, Endian>>> {
        if self.input.is_empty() {
            Ok(None)
        } else {
            match parse_type_unit_header(self.input, self.offset) {
                Ok((rest, header)) => {
                    self.offset.0 += self.input.len() - rest.len();
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
    offset: DebugTypesOffset,
    type_signature: DebugTypeSignature,
    type_offset: UnitOffset,
}

impl<'input, Endian> TypeUnitHeader<'input, Endian>
    where Endian: Endianity
{
    /// Construct a new `TypeUnitHeader`.
    fn new(header: UnitHeader<'input, Endian>,
           offset: DebugTypesOffset,
           type_signature: DebugTypeSignature,
           type_offset: UnitOffset)
           -> TypeUnitHeader<'input, Endian> {
        TypeUnitHeader {
            header: header,
            offset: offset,
            type_signature: type_signature,
            type_offset: type_offset,
        }
    }

    /// Return the serialized size of the type-unit header for the given
    /// DWARF format.
    pub fn size_of_header(format: Format) -> usize {
        let unit_header_size = UnitHeader::<Endian>::size_of_header(format);
        let type_signature_size = 8;
        let type_offset_size = match format {
            Format::Dwarf32 => 4,
            Format::Dwarf64 => 8,
        };
        unit_header_size + type_signature_size + type_offset_size
    }

    /// Get the offset of this compilation unit within the .debug_info section.
    pub fn offset(&self) -> DebugTypesOffset {
        self.offset
    }

    /// Get the length of the debugging info for this type-unit.
    pub fn unit_length(&self) -> u64 {
        self.header.unit_length
    }

    /// Get the length of the debugging info for this type-unit,
    /// including the byte length of the encoded length itself.
    pub fn length_including_self(&self) -> u64 {
        self.header.length_including_self()
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

    /// The serialized size of the header for this type-unit.
    pub fn header_size(&self) -> usize {
        self.header.header_size()
    }

    /// Get the unique type signature for this type unit.
    pub fn type_signature(&self) -> DebugTypeSignature {
        self.type_signature
    }

    /// Get the offset within this type unit where the type is defined.
    pub fn type_offset(&self) -> UnitOffset {
        self.type_offset
    }

    /// Navigate this type unit's `DebuggingInformationEntry`s.
    pub fn entries<'me, 'abbrev>(&'me self,
                                 abbreviations: &'abbrev Abbreviations)
                                 -> Result<EntriesCursor<'input, 'abbrev, 'me, Endian>> {
        self.header.entries(abbreviations)
    }

    /// Navigate this type unit's `DebuggingInformationEntry`s as a tree.
    pub fn entries_tree<'me, 'abbrev>(&'me self,
                                      abbreviations: &'abbrev Abbreviations)
                                      -> Result<EntriesTree<'input, 'abbrev, 'me, Endian>> {
        self.header.entries_tree(abbreviations)
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
        self.header.abbreviations(debug_abbrev)
    }
}

/// Parse a type unit header.
fn parse_type_unit_header<Endian>(input: EndianBuf<Endian>,
                                  offset: DebugTypesOffset)
                                  -> Result<(EndianBuf<Endian>, TypeUnitHeader<Endian>)>
    where Endian: Endianity
{
    let (after_unit, mut header) = try!(parse_unit_header(input));
    let (rest, signature) = try!(parse_type_signature(header.entries_buf));
    let (rest, type_offset) = try!(parse_type_offset(rest, header.format()));
    header.entries_buf = rest;
    Ok((after_unit, TypeUnitHeader::new(header, offset, signature, type_offset)))
}

#[cfg(test)]
mod tests {
    extern crate test_assembler;

    use super::*;
    use super::{parse_version, parse_debug_abbrev_offset, parse_type_offset, parse_unit_header,
                parse_type_unit_header, parse_attribute};
    use abbrev::{DebugAbbrev, DebugAbbrevOffset, Abbreviation, AttributeSpecification};
    use abbrev::tests::AbbrevSectionMethods;
    use constants;
    use constants::*;
    use endianity::{EndianBuf, Endianity, LittleEndian};
    use leb128;
    use loc::DebugLocOffset;
    use parser::{Error, Format, Result};
    use self::test_assembler::{Endian, Label, LabelMaker, Section};
    use str::DebugStrOffset;
    use std;
    use std::cell::Cell;
    use std::ffi;
    use test_util::GimliSectionMethods;

    // Mixin methods for `Section` to help define binary test data.

    trait UnitSectionMethods {
        fn comp_unit<'input, E>(self, unit: &mut CompilationUnitHeader<'input, E>) -> Self
            where E: Endianity;
        fn type_unit<'input, E>(self, unit: &mut TypeUnitHeader<'input, E>) -> Self
            where E: Endianity;
        fn unit<'input, E>(self, unit: &mut UnitHeader<'input, E>, extra_header: &[u8]) -> Self
            where E: Endianity;
        fn die<F>(self, code: u64, attr: F) -> Self where F: Fn(Section) -> Section;
        fn die_null(self) -> Self;
        fn attr_string(self, s: &str) -> Self;
        fn attr_ref1(self, o: u8) -> Self;
        fn offset(self, offset: usize, format: Format) -> Self;
    }

    impl UnitSectionMethods for Section {
        fn comp_unit<'input, E>(self, unit: &mut CompilationUnitHeader<'input, E>) -> Self
            where E: Endianity
        {
            unit.offset = DebugInfoOffset(self.size() as usize);
            self.unit(&mut unit.header, &[])
        }

        fn type_unit<'input, E>(self, unit: &mut TypeUnitHeader<'input, E>) -> Self
            where E: Endianity
        {
            unit.offset = DebugTypesOffset(self.size() as usize);
            let section = Section::with_endian(Endian::Little)
                .L64(unit.type_signature.0)
                .offset(unit.type_offset.0, unit.header.format);
            let extra_header = section.get_contents().unwrap();
            self.unit(&mut unit.header, &extra_header)
        }

        fn unit<'input, E>(self, unit: &mut UnitHeader<'input, E>, extra_header: &[u8]) -> Self
            where E: Endianity
        {
            let length = Label::new();
            let start = Label::new();
            let end = Label::new();

            let section = match unit.format {
                Format::Dwarf32 => self.L32(&length),
                Format::Dwarf64 => {
                    self.L32(0xffffffff)
                        .L64(&length)
                }
            };

            let section = section.mark(&start)
                .L16(unit.version)
                .offset(unit.debug_abbrev_offset.0, unit.format)
                .D8(unit.address_size)
                .append_bytes(extra_header)
                .append_bytes(unit.entries_buf.into())
                .mark(&end);

            unit.unit_length = (&end - &start) as u64;
            length.set_const(unit.unit_length);

            section
        }

        fn die<F>(self, code: u64, attr: F) -> Self
            where F: Fn(Section) -> Section
        {
            let section = self.uleb(code);
            attr(section)
        }

        fn die_null(self) -> Self {
            self.D8(0)
        }

        fn attr_string(self, attr: &str) -> Self {
            self.append_bytes(attr.as_bytes()).D8(0)
        }

        fn attr_ref1(self, attr: u8) -> Self {
            self.D8(attr)
        }

        fn offset(self, offset: usize, format: Format) -> Self {
            match format {
                Format::Dwarf32 => self.L32(offset as u32),
                Format::Dwarf64 => self.L64(offset as u64),
            }
        }
    }

    #[test]
    fn test_parse_debug_abbrev_offset_32() {
        let section = Section::with_endian(Endian::Little).L32(0x04030201);
        let buf = section.get_contents().unwrap();

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
    #[cfg(target_pointer_width = "64")]
    fn test_parse_debug_abbrev_offset_64() {
        let section = Section::with_endian(Endian::Little).L64(0x0807060504030201);
        let buf = section.get_contents().unwrap();

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

    #[test]
    fn test_parse_debug_info_offset_32() {
        let section = Section::with_endian(Endian::Little).L32(0x04030201);
        let buf = section.get_contents().unwrap();

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
    #[cfg(target_pointer_width = "64")]
    fn test_parse_debug_info_offset_64() {
        let section = Section::with_endian(Endian::Little).L64(0x0807060504030201);
        let buf = section.get_contents().unwrap();

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

    #[test]
    fn test_parse_debug_types_offset_32() {
        let section = Section::with_endian(Endian::Little).L32(0x04030201);
        let buf = section.get_contents().unwrap();

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
    #[cfg(target_pointer_width = "64")]
    fn test_parse_debug_types_offset_64() {
        let section = Section::with_endian(Endian::Little).L64(0x0807060504030201);
        let buf = section.get_contents().unwrap();

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

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn test_units() {
        let expected_rest = &[1, 2, 3, 4, 5, 6, 7, 8, 9];
        let mut unit64 = CompilationUnitHeader {
            header: UnitHeader {
                unit_length: 0,
                version: 4,
                debug_abbrev_offset: DebugAbbrevOffset(0x0102030405060708),
                address_size: 8,
                format: Format::Dwarf64,
                entries_buf: EndianBuf::new(expected_rest),
            },
            offset: DebugInfoOffset(0),
        };
        let mut unit32 = CompilationUnitHeader {
            header: UnitHeader {
                unit_length: 0,
                version: 4,
                debug_abbrev_offset: DebugAbbrevOffset(0x08070605),
                address_size: 4,
                format: Format::Dwarf32,
                entries_buf: EndianBuf::new(expected_rest),
            },
            offset: DebugInfoOffset(0),
        };
        let section = Section::with_endian(Endian::Little)
            .comp_unit(&mut unit64)
            .comp_unit(&mut unit32);
        let buf = section.get_contents().unwrap();

        let debug_info = DebugInfo::<LittleEndian>::new(&buf);
        let mut units = debug_info.units();

        assert_eq!(units.next(), Ok(Some(unit64)));
        assert_eq!(units.next(), Ok(Some(unit32)));
        assert_eq!(units.next(), Ok(None));
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

    #[test]
    fn test_parse_unit_header_32_ok() {
        let expected_rest = &[1, 2, 3, 4, 5, 6, 7, 8, 9];
        let mut expected_unit = UnitHeader {
            unit_length: 0,
            version: 4,
            debug_abbrev_offset: DebugAbbrevOffset(0x08070605),
            address_size: 4,
            format: Format::Dwarf32,
            entries_buf: EndianBuf::new(expected_rest),
        };
        let section = Section::with_endian(Endian::Little)
            .unit(&mut expected_unit, &[])
            .append_bytes(expected_rest);
        let buf = section.get_contents().unwrap();

        assert_eq!(parse_unit_header(EndianBuf::<LittleEndian>::new(&buf)),
                   Ok((EndianBuf::new(expected_rest), expected_unit)));
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn test_parse_unit_header_64_ok() {
        let expected_rest = &[1, 2, 3, 4, 5, 6, 7, 8, 9];
        let mut expected_unit = UnitHeader {
            unit_length: 0,
            version: 4,
            debug_abbrev_offset: DebugAbbrevOffset(0x0102030405060708),
            address_size: 8,
            format: Format::Dwarf64,
            entries_buf: EndianBuf::new(expected_rest),
        };
        let section = Section::with_endian(Endian::Little)
            .unit(&mut expected_unit, &[])
            .append_bytes(expected_rest);
        let buf = section.get_contents().unwrap();

        assert_eq!(parse_unit_header(EndianBuf::<LittleEndian>::new(&buf)),
                   Ok((EndianBuf::new(expected_rest), expected_unit)));
    }

    #[test]
    fn test_parse_type_offset_32_ok() {
        let buf = [0x12, 0x34, 0x56, 0x78, 0x00];

        match parse_type_offset(EndianBuf::<LittleEndian>::new(&buf), Format::Dwarf32) {
            Ok((rest, offset)) => {
                assert_eq!(rest.len(), 1);
                assert_eq!(UnitOffset(0x78563412), offset);
            }
            otherwise => panic!("Unexpected result: {:?}", otherwise),
        }
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn test_parse_type_offset_64_ok() {
        let buf = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xff, 0x00];

        match parse_type_offset(EndianBuf::<LittleEndian>::new(&buf), Format::Dwarf64) {
            Ok((rest, offset)) => {
                assert_eq!(rest.len(), 1);
                assert_eq!(UnitOffset(0xffdebc9a78563412), offset);
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

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn test_parse_type_unit_header_64_ok() {
        let expected_rest = &[1, 2, 3, 4, 5, 6, 7, 8, 9];
        let mut expected_unit = TypeUnitHeader {
            header: UnitHeader {
                unit_length: 0,
                version: 4,
                debug_abbrev_offset: DebugAbbrevOffset(0x08070605),
                address_size: 8,
                format: Format::Dwarf64,
                entries_buf: EndianBuf::new(expected_rest),
            },
            offset: DebugTypesOffset(0),
            type_signature: DebugTypeSignature(0xdeadbeefdeadbeef),
            type_offset: UnitOffset(0x7856341278563412),
        };
        let section = Section::with_endian(Endian::Little)
            .type_unit(&mut expected_unit)
            .append_bytes(expected_rest);
        let buf = section.get_contents().unwrap();

        assert_eq!(parse_type_unit_header(EndianBuf::<LittleEndian>::new(&buf),
                                          DebugTypesOffset(0)),
                   Ok((EndianBuf::new(expected_rest), expected_unit)));
    }

    fn section_contents<F>(f: F) -> Vec<u8>
        where F: Fn(Section) -> Section
    {
        f(Section::with_endian(Endian::Little)).get_contents().unwrap()
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn test_attribute_value() {
        let mut unit = test_parse_attribute_unit_default();

        let block_data = &[1, 2, 3, 4];
        let buf = section_contents(|s| s.uleb(block_data.len() as u64).append_bytes(block_data));
        let block = EndianBuf::<LittleEndian>::new(&buf);

        let buf = section_contents(|s| s.L32(0x01020304));
        let data4 = EndianBuf::<LittleEndian>::new(&buf);

        let buf = section_contents(|s| s.L64(0x0102030405060708));
        let data8 = EndianBuf::<LittleEndian>::new(&buf);

        let tests = [(2,
                      constants::DW_AT_data_member_location,
                      constants::DW_FORM_block,
                      block,
                      AttributeValue::Block(EndianBuf::new(block_data)),
                      AttributeValue::Exprloc(EndianBuf::new(block_data))),
                     (2,
                      constants::DW_AT_data_member_location,
                      constants::DW_FORM_data4,
                      data4,
                      AttributeValue::SecOffset(0x01020304),
                      AttributeValue::DebugLocRef(DebugLocOffset(0x01020304))),
                     (4,
                      constants::DW_AT_data_member_location,
                      constants::DW_FORM_data4,
                      data4,
                      AttributeValue::Data(data4),
                      AttributeValue::Udata(0x01020304)),
                     (2,
                      constants::DW_AT_data_member_location,
                      constants::DW_FORM_data8,
                      data8,
                      AttributeValue::SecOffset(0x0102030405060708),
                      AttributeValue::DebugLocRef(DebugLocOffset(0x0102030405060708))),
                     (4,
                      constants::DW_AT_data_member_location,
                      constants::DW_FORM_data8,
                      data8,
                      AttributeValue::Data(data8),
                      AttributeValue::Udata(0x0102030405060708))];

        for test in tests.iter() {
            let (version, name, form, input, expect_raw, expect_value) = *test;
            unit.version = version;
            let spec = AttributeSpecification::new(name, form);
            let (_, attribute) = parse_attribute(input, &unit, spec)
                .expect("Should parse attribute");
            assert_eq!(attribute.raw_value(), expect_raw);
            assert_eq!(attribute.value(), expect_value);
        }
    }

    #[test]
    fn test_attribute_udata_sdata_value() {
        let buf = section_contents(|s| s.D8(1));
        let p1i8 = EndianBuf::<LittleEndian>::new(&buf);
        let buf = section_contents(|s| s.D8(std::u8::MAX));
        let n1i8 = EndianBuf::<LittleEndian>::new(&buf);
        let buf = section_contents(|s| s.D16(1));
        let p1i16 = EndianBuf::<LittleEndian>::new(&buf);
        let buf = section_contents(|s| s.D16(std::u16::MAX));
        let n1i16 = EndianBuf::<LittleEndian>::new(&buf);
        let buf = section_contents(|s| s.D32(1));
        let p1i32 = EndianBuf::<LittleEndian>::new(&buf);
        let buf = section_contents(|s| s.D32(std::u32::MAX));
        let n1i32 = EndianBuf::<LittleEndian>::new(&buf);
        let buf = section_contents(|s| s.D64(1));
        let p1i64 = EndianBuf::<LittleEndian>::new(&buf);
        let buf = section_contents(|s| s.D64(std::u64::MAX));
        let n1i64 = EndianBuf::<LittleEndian>::new(&buf);

        let tests = [(AttributeValue::Data(p1i8), Some(1), Some(1)),
                     (AttributeValue::Data(n1i8), Some(std::u8::MAX as u64), Some(-1)),
                     (AttributeValue::Data(p1i16), Some(1), Some(1)),
                     (AttributeValue::Data(n1i16), Some(std::u16::MAX as u64), Some(-1)),
                     (AttributeValue::Data(p1i32), Some(1), Some(1)),
                     (AttributeValue::Data(n1i32), Some(std::u32::MAX as u64), Some(-1)),
                     (AttributeValue::Data(p1i64), Some(1), Some(1)),
                     (AttributeValue::Data(n1i64), Some(std::u64::MAX), Some(-1)),
                     (AttributeValue::Sdata(1), None, Some(1)),
                     (AttributeValue::Udata(1), Some(1), None)];
        for test in tests.iter() {
            let (value, expect_udata, expect_sdata) = *test;
            let attribute = Attribute {
                name: DW_AT_data_member_location,
                value: value,
            };
            assert_eq!(attribute.udata_value(), expect_udata);
            assert_eq!(attribute.sdata_value(), expect_sdata);
        }
    }

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

    fn test_parse_attribute_unit_default() -> UnitHeader<'static, LittleEndian> {
        test_parse_attribute_unit(4, Format::Dwarf32)
    }

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
    #[cfg(target_pointer_width = "64")]
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
    #[cfg(target_pointer_width = "64")]
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
    #[cfg(target_pointer_width = "64")]
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
    #[cfg(target_pointer_width = "64")]
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
    #[cfg(target_pointer_width = "64")]
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
        let buf = [0x66, 0x6f, 0x6f, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x39, 0x05, 0x00, 0x00, 0xaa,
                   0xaa, 0xaa, 0xaa];

        let entry = DebuggingInformationEntry {
            offset: UnitOffset(0),
            attrs_slice: &buf,
            after_attrs: Cell::new(None),
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
                               value:
                                   AttributeValue::String(ffi::CStr::from_bytes_with_nul(b"foo\0")
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
            offset: UnitOffset(0),
            attrs_slice: &buf,
            after_attrs: Cell::new(None),
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
                               value:
                                   AttributeValue::String(ffi::CStr::from_bytes_with_nul(b"foo\0")
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

    fn assert_entry_name<Endian>(entry: &DebuggingInformationEntry<Endian>, name: &str)
        where Endian: Endianity
    {
        let value = entry.attr_value(constants::DW_AT_name)
            .expect("Should have found the name attribute");

        let mut with_null: Vec<u8> = name.as_bytes().into();
        with_null.push(0);

        assert_eq!(value,
                   AttributeValue::String(ffi::CStr::from_bytes_with_nul(&with_null).unwrap()));
    }

    fn assert_current_name<Endian>(cursor: &EntriesCursor<Endian>, name: &str)
        where Endian: Endianity
    {
        let entry = cursor.current();
        assert_entry_name(entry, name);
    }

    fn assert_next_entry<Endian>(cursor: &mut EntriesCursor<Endian>, name: &str)
        where Endian: Endianity
    {
        cursor.next_entry()
            .expect("Should parse next entry")
            .expect("Should have an entry");
        assert_current_name(cursor, name);
    }

    /*
    fn assert_next_entry_null<Endian>(cursor: &mut EntriesCursor<Endian>)
        where Endian: Endianity
    {
        cursor.next_entry()
            .expect("Should parse next entry")
            .expect("Should have an entry");
        assert!(cursor.current().is_none());
    }
    */

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

    fn assert_valid_sibling_ptr<Endian>(cursor: &EntriesCursor<Endian>)
        where Endian: Endianity
    {
        let sibling_ptr = cursor.current().attr_value(constants::DW_AT_sibling);
        match sibling_ptr {
            Some(AttributeValue::UnitRef(offset)) => {
                cursor.current.unit.range_from(offset..);
            }
            _ => panic!("Invalid sibling pointer {:?}", sibling_ptr),
        }
    }

    fn entries_cursor_tests_abbrev_buf() -> Vec<u8> {
        let section = Section::with_endian(Endian::Little)
            .abbrev(1, DW_TAG_subprogram, DW_CHILDREN_yes)
            .abbrev_attr(DW_AT_name, DW_FORM_string)
            .abbrev_attr_null()
            .abbrev_null();
        section.get_contents().unwrap()
    }

    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn entries_cursor_tests_debug_info_buf() -> Vec<u8> {
        let section = Section::with_endian(Endian::Little)
            .die(1, |s| s.attr_string("001"))
                .die(1, |s| s.attr_string("002"))
                    .die(1, |s| s.attr_string("003"))
                        .die_null()
                    .die_null()
                .die(1, |s| s.attr_string("004"))
                    .die(1, |s| s.attr_string("005"))
                        .die_null()
                    .die(1, |s| s.attr_string("006"))
                        .die_null()
                    .die_null()
                .die(1, |s| s.attr_string("007"))
                    .die(1, |s| s.attr_string("008"))
                        .die(1, |s| s.attr_string("009"))
                            .die_null()
                        .die_null()
                    .die_null()
                .die(1, |s| s.attr_string("010"))
                    .die_null()
                .die_null();
        let entries_buf = section.get_contents().unwrap();

        let mut unit = CompilationUnitHeader::<LittleEndian> {
            header: UnitHeader {
                unit_length: 0,
                version: 4,
                debug_abbrev_offset: DebugAbbrevOffset(0),
                address_size: 4,
                format: Format::Dwarf32,
                entries_buf: EndianBuf::new(&entries_buf),
            },
            offset: DebugInfoOffset(0),
        };
        let section = Section::with_endian(Endian::Little).comp_unit(&mut unit);
        section.get_contents().unwrap()
    }

    #[test]
    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn test_cursor_next_entry_incomplete() {
        let section = Section::with_endian(Endian::Little)
            .die(1, |s| s.attr_string("001"))
                .die(1, |s| s.attr_string("002"))
                    .die(1, |s| s);
        let entries_buf = section.get_contents().unwrap();

        let mut unit = CompilationUnitHeader::<LittleEndian> {
            header: UnitHeader {
                unit_length: 0,
                version: 4,
                debug_abbrev_offset: DebugAbbrevOffset(0),
                address_size: 4,
                format: Format::Dwarf32,
                entries_buf: EndianBuf::new(&entries_buf),
            },
            offset: DebugInfoOffset(0),
        };
        let section = Section::with_endian(Endian::Little).comp_unit(&mut unit);
        let info_buf = &section.get_contents().unwrap();
        let debug_info = DebugInfo::<LittleEndian>::new(info_buf);

        let unit = debug_info.units().next()
            .expect("should have a unit result")
            .expect("and it should be ok");

        let abbrevs_buf = &entries_cursor_tests_abbrev_buf();
        let debug_abbrev = DebugAbbrev::<LittleEndian>::new(abbrevs_buf);

        let abbrevs = unit.abbreviations(debug_abbrev)
            .expect("Should parse abbreviations");

        let mut cursor = unit.entries(&abbrevs).expect("Should have cursor");
        assert_current_name(&mut cursor, "001");

        assert_next_entry(&mut cursor, "002");

        {
            // Entry code is present, but none of the attributes.
            cursor.next_entry()
                .expect("Should parse next entry")
                .expect("Should have an entry");
            let entry = cursor.current();
            assert!(entry.attrs().next().is_err());
        }

        assert!(cursor.next_entry().is_err());
        assert!(cursor.next_entry().is_err());
    }

    /*
    #[test]
    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn test_cursor_next_entry() {
        let info_buf = &entries_cursor_tests_debug_info_buf();
        let debug_info = DebugInfo::<LittleEndian>::new(info_buf);

        let unit = debug_info.units().next()
            .expect("should have a unit result")
            .expect("and it should be ok");

        let abbrevs_buf = &entries_cursor_tests_abbrev_buf();
        let debug_abbrev = DebugAbbrev::<LittleEndian>::new(abbrevs_buf);

        let abbrevs = unit.abbreviations(debug_abbrev)
            .expect("Should parse abbreviations");

        let mut cursor = unit.entries(&abbrevs).expect("Should have cursor");
        assert_current_name(&mut cursor, "001");

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
    }
    */

    #[test]
    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn test_cursor_next_dfs() {
        let info_buf = &entries_cursor_tests_debug_info_buf();
        let debug_info = DebugInfo::<LittleEndian>::new(info_buf);

        let unit = debug_info.units().next()
            .expect("should have a unit result")
            .expect("and it should be ok");

        let abbrevs_buf = &entries_cursor_tests_abbrev_buf();
        let debug_abbrev = DebugAbbrev::<LittleEndian>::new(abbrevs_buf);

        let abbrevs = unit.abbreviations(debug_abbrev)
            .expect("Should parse abbreviations");

        let mut cursor = unit.entries(&abbrevs).expect("Should have cursor");
        assert_current_name(&mut cursor, "001");

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
    }

    /*
    #[test]
    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn test_cursor_next_sibling_no_sibling_ptr() {
        let info_buf = &entries_cursor_tests_debug_info_buf();
        let debug_info = DebugInfo::<LittleEndian>::new(info_buf);

        let unit = debug_info.units().next()
            .expect("should have a unit result")
            .expect("and it should be ok");

        let abbrevs_buf = &entries_cursor_tests_abbrev_buf();
        let debug_abbrev = DebugAbbrev::<LittleEndian>::new(abbrevs_buf);

        let abbrevs = unit.abbreviations(debug_abbrev)
            .expect("Should parse abbreviations");

        let mut cursor = unit.entries(&abbrevs).expect("Should have cursor");
        assert_current_name(&mut cursor, "001");

        // Down to the first child of the root entry.

        assert_next_dfs(&mut cursor, "002", 1);

        // Now iterate all children of the root via `next_sibling`.

        assert_next_sibling(&mut cursor, "004");
        assert_next_sibling(&mut cursor, "007");
        assert_next_sibling(&mut cursor, "010");

        // There should be no more siblings.

        assert!(cursor.next_sibling().expect("Should parse next sibling").is_none());
    }

    #[test]
    fn test_cursor_next_sibling_continuation() {
        let info_buf = &entries_cursor_tests_debug_info_buf();
        let debug_info = DebugInfo::<LittleEndian>::new(info_buf);

        let unit = debug_info.units()
            .next()
            .expect("should have a unit result")
            .expect("and it should be ok");

        let abbrevs_buf = &entries_cursor_tests_abbrev_buf();
        let debug_abbrev = DebugAbbrev::<LittleEndian>::new(abbrevs_buf);

        let abbrevs = unit.abbreviations(debug_abbrev)
            .expect("Should parse abbreviations");

        let mut cursor = unit.entries(&abbrevs).expect("Should have cursor");
        assert_current_name(&mut cursor, "001");

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

        // FIXME: dfs should be -1
        assert_next_dfs(&mut cursor, "007", 1);
        assert_next_sibling(&mut cursor, "010");

        // There should be no more siblings.

        assert!(cursor.next_sibling().expect("Should parse next sibling").is_none());
    }

    fn entries_cursor_sibling_abbrev_buf() -> Vec<u8> {
        let section = Section::with_endian(Endian::Little)
            .abbrev(1, DW_TAG_subprogram, DW_CHILDREN_yes)
            .abbrev_attr(DW_AT_name, DW_FORM_string)
            .abbrev_attr(DW_AT_sibling, DW_FORM_ref1)
            .abbrev_attr_null()
            .abbrev(2, DW_TAG_subprogram, DW_CHILDREN_yes)
            .abbrev_attr(DW_AT_name, DW_FORM_string)
            .abbrev_attr_null()
            .abbrev_null();
        section.get_contents().unwrap()
    }

    fn entries_cursor_sibling_entries_buf(header_size: usize) -> Vec<u8> {
        let start = Label::new();
        let sibling004_ref = Label::new();
        let sibling004 = Label::new();
        let sibling009_ref = Label::new();
        let sibling009 = Label::new();

        let section = Section::with_endian(Endian::Little)
            .mark(&start)
            .die(2, |s| s.attr_string("001"))
                // Valid sibling attribute.
                .die(1, |s| s.attr_string("002").D8(&sibling004_ref))
                    // Invalid code to ensure the sibling attribute was used.
                    .die(10, |s| s.attr_string("003"))
                        .die_null()
                    .die_null()
                .mark(&sibling004)
                // Invalid sibling attribute.
                .die(1, |s| s.attr_string("004").attr_ref1(255))
                    .die(2, |s| s.attr_string("005"))
                        .die_null()
                    .die_null()
                // Sibling attribute in child only.
                .die(2, |s| s.attr_string("006"))
                    // Valid sibling attribute.
                    .die(1, |s| s.attr_string("007").D8(&sibling009_ref))
                        // Invalid code to ensure the sibling attribute was used.
                        .die(10, |s| s.attr_string("008"))
                            .die_null()
                        .die_null()
                    .mark(&sibling009)
                    .die(2, |s| s.attr_string("009"))
                        .die_null()
                    .die_null()
                // No sibling attribute.
                .die(2, |s| s.attr_string("010"))
                    .die(2, |s| s.attr_string("011"))
                        .die_null()
                    .die_null()
                .die_null();

        let offset = header_size as u64 + (&sibling004 - &start) as u64;
        sibling004_ref.set_const(offset);

        let offset = header_size as u64 + (&sibling009 - &start) as u64;
        sibling009_ref.set_const(offset);

        section.get_contents().unwrap()
    }

    fn test_cursor_next_sibling_with_ptr(cursor: &mut EntriesCursor<LittleEndian>) {
        assert_current_name(cursor, "001");

        // Down to the first child of the root.

        assert_next_dfs(cursor, "002", 1);

        // Now iterate all children of the root via `next_sibling`.

        assert_valid_sibling_ptr(cursor);
        assert_next_sibling(cursor, "004");
        assert_next_sibling(cursor, "006");
        assert_next_sibling(cursor, "010");

        // There should be no more siblings.

        assert!(cursor.next_sibling().expect("Should parse next sibling").is_none());
    }

    #[test]
    fn test_debug_info_next_sibling_with_ptr() {
        let format = Format::Dwarf32;
        let header_size = CompilationUnitHeader::<LittleEndian>::size_of_header(format);
        let entries_buf = entries_cursor_sibling_entries_buf(header_size);

        let mut unit = CompilationUnitHeader::<LittleEndian> {
            header: UnitHeader {
                unit_length: 0,
                version: 4,
                debug_abbrev_offset: DebugAbbrevOffset(0),
                address_size: 4,
                format: format,
                entries_buf: EndianBuf::new(&entries_buf),
            },
            offset: DebugInfoOffset(0),
        };
        let section = Section::with_endian(Endian::Little).comp_unit(&mut unit);
        let info_buf = section.get_contents().unwrap();
        let debug_info = DebugInfo::<LittleEndian>::new(&info_buf);

        let unit = debug_info.units()
            .next()
            .expect("should have a unit result")
            .expect("and it should be ok");

        let abbrev_buf = entries_cursor_sibling_abbrev_buf();
        let debug_abbrev = DebugAbbrev::<LittleEndian>::new(&abbrev_buf);

        let abbrevs = unit.abbreviations(debug_abbrev)
            .expect("Should parse abbreviations");

        let mut cursor = unit.entries(&abbrevs).expect("Should have cursor");
        test_cursor_next_sibling_with_ptr(&mut cursor);
    }

    #[test]
    fn test_debug_types_next_sibling_with_ptr() {
        let format = Format::Dwarf32;
        let header_size = TypeUnitHeader::<LittleEndian>::size_of_header(format);
        let entries_buf = entries_cursor_sibling_entries_buf(header_size);

        let mut unit = TypeUnitHeader::<LittleEndian> {
            header: UnitHeader {
                unit_length: 0,
                version: 4,
                debug_abbrev_offset: DebugAbbrevOffset(0),
                address_size: 4,
                format: format,
                entries_buf: EndianBuf::new(&entries_buf),
            },
            type_signature: DebugTypeSignature(0),
            type_offset: UnitOffset(0),
            offset: DebugTypesOffset(0),
        };
        let section = Section::with_endian(Endian::Little).type_unit(&mut unit);
        let info_buf = section.get_contents().unwrap();
        let debug_types = DebugTypes::<LittleEndian>::new(&info_buf);

        let unit = debug_types.units()
            .next()
            .expect("should have a unit result")
            .expect("and it should be ok");

        let abbrev_buf = entries_cursor_sibling_abbrev_buf();
        let debug_abbrev = DebugAbbrev::<LittleEndian>::new(&abbrev_buf);

        let abbrevs = unit.abbreviations(debug_abbrev)
            .expect("Should parse abbreviations");

        let mut cursor = unit.entries(&abbrevs).expect("Should have cursor");
        test_cursor_next_sibling_with_ptr(&mut cursor);
    }
    */

    /*
    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn entries_tree_tests_debug_abbrevs_buf() -> Vec<u8> {
        Section::with_endian(Endian::Little)
            .abbrev(1, DW_TAG_subprogram, DW_CHILDREN_yes)
                .abbrev_attr(DW_AT_name, DW_FORM_string)
                .abbrev_attr_null()
            .abbrev(2, DW_TAG_subprogram, DW_CHILDREN_no)
                .abbrev_attr(DW_AT_name, DW_FORM_string)
                .abbrev_attr_null()
            .abbrev_null()
            .get_contents()
            .unwrap()
    }

    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn entries_tree_tests_debug_info_buf() -> Vec<u8> {
        Section::with_endian(Endian::Little)
            .die(1, |s| s.attr_string("root"))
                .die(1, |s| s.attr_string("1"))
                    .die(1, |s| s.attr_string("1a"))
                        .die_null()
                    .die(2, |s| s.attr_string("1b"))
                    .die_null()
                .die(1, |s| s.attr_string("2"))
                    .die(1, |s| s.attr_string("2a"))
                        .die(1, |s| s.attr_string("2a1"))
                            .die_null()
                        .die_null()
                    .die(1, |s| s.attr_string("2b"))
                        .die(2, |s| s.attr_string("2b1"))
                        .die_null()
                    .die_null()
                .die(1, |s| s.attr_string("3"))
                    .die(1, |s| s.attr_string("3a"))
                        .die(2, |s| s.attr_string("3a1"))
                        .die(2, |s| s.attr_string("3a2"))
                        .die_null()
                    .die(2, |s| s.attr_string("3b"))
                    .die_null()
                .die(2, |s| s.attr_string("final"))
                .die_null()
            .get_contents()
            .unwrap()
    }

    #[test]
    fn test_entries_tree() {
        fn assert_entry<'input, 'abbrev, 'unit, 'tree, Endian>
            (iter: Result<Option<EntriesTreeIter<'input, 'abbrev, 'unit, 'tree, Endian>>>,
             name: &str)
             -> EntriesTreeIter<'input, 'abbrev, 'unit, 'tree, Endian>
            where Endian: Endianity
        {
            let iter = iter.expect("Should parse entry").expect("Should have entry");
            assert_entry_name(iter.entry(), name);
            iter
        }

        fn assert_null<E: Endianity>(iter: Result<Option<EntriesTreeIter<E>>>) {
            match iter {
                Ok(None) => {}
                otherwise => {
                    println!("Unexpected parse result = {:#?}", otherwise);
                    assert!(false);
                }
            }
        }

        let abbrevs_buf = entries_tree_tests_debug_abbrevs_buf();
        let debug_abbrev = DebugAbbrev::<LittleEndian>::new(&abbrevs_buf);

        let entries_buf = entries_tree_tests_debug_info_buf();
        let mut unit = CompilationUnitHeader::<LittleEndian> {
            header: UnitHeader {
                unit_length: 0,
                version: 4,
                debug_abbrev_offset: DebugAbbrevOffset(0),
                address_size: 4,
                format: Format::Dwarf32,
                entries_buf: EndianBuf::new(&entries_buf),
            },
            offset: DebugInfoOffset(0),
        };
        let info_buf =
            Section::with_endian(Endian::Little).comp_unit(&mut unit).get_contents().unwrap();
        let debug_info = DebugInfo::<LittleEndian>::new(&info_buf);

        let unit = debug_info.units()
            .next()
            .expect("Should parse unit")
            .expect("and it should be some");
        let abbrevs = unit.abbreviations(debug_abbrev).expect("Should parse abbreviations");
        let mut tree = unit.entries_tree(&abbrevs).expect("Should have entries tree");

        // Test we can restart iteration of the tree.
        {
            let mut iter = tree.iter();
            assert_entry_name(iter.entry(), "root");
            assert_entry(iter.next(), "1");
        }
        {
            let mut iter = tree.iter();
            assert_entry_name(iter.entry(), "root");
            assert_entry(iter.next(), "1");
        }

        let mut iter = tree.iter();
        assert_entry_name(iter.entry(), "root");
        {
            // Test iteration with children.
            let mut iter = assert_entry(iter.next(), "1");
            {
                // Test iteration with children flag, but no children.
                let mut iter = assert_entry(iter.next(), "1a");
                assert_null(iter.next());
                assert_null(iter.next());
            }
            {
                // Test iteration without children flag.
                let mut iter = assert_entry(iter.next(), "1b");
                assert_null(iter.next());
                assert_null(iter.next());
            }
            //assert!(iter.entry().is_none());
            assert_null(iter.next());
            //assert!(iter.entry().is_none());
            assert_null(iter.next());
        }
        {
            // Test skipping over children.
            let mut iter = assert_entry(iter.next(), "2");
            assert_entry(iter.next(), "2a");
            assert_entry(iter.next(), "2b");
            assert_null(iter.next());
        }
        {
            // Test skipping after partial iteration.
            let mut iter = assert_entry(iter.next(), "3");
            {
                let mut iter = assert_entry(iter.next(), "3a");
                assert_entry(iter.next(), "3a1");
                // Parent iter should be able to skip over "3a2".
            }
            assert_entry(iter.next(), "3b");
            assert_null(iter.next());
        }
        assert_entry(iter.next(), "final");
        assert_null(iter.next());
    }
    */
}
