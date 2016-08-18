#![deny(missing_docs)]

use endianity::{Endianity, EndianBuf};
use parser::{parse_u16, parse_uN_as_u64, parse_unit_length, parse_word, parse_debug_info_offset,
             parse_debug_types_offset, parse_address_size, parse_null_terminated_string,
             DebugInfoOffset, DebugTypesOffset, Format, ParseResult, Error};
use std::cmp::Ordering;
use std::ffi;
use std::marker::PhantomData;
use std::rc::Rc;

// The various "Accelerated Access" sections (DWARF standard v4 Section 6.1) all have
// similar structures. They consist of a header with metadata and an offset into the
// .debug_info or .debug_types sections for the entire compilation unit, and a series
// of following entries that list addresses (for .debug_aranges) or names
// (for .debug_pubnames and .debug_pubtypes) that are covered.
//
// Because these three tables all have similar structures, we abstract out some of
// the parsing mechanics.

pub trait LookupParser<'input, Endian>
    where Endian: Endianity
{
    /// The type of the produced header.
    type Header;
    /// The type of the produced entry.
    type Entry;

    /// Parse a header from `input`. Returns a tuple of `input` sliced beyond this header and
    /// all of its entries, `input` sliced to contain just the entries corresponding to this
    /// header (without the header itself), and the parsed representation of the header itself.
    fn parse_header(input: EndianBuf<Endian>)
                    -> ParseResult<(EndianBuf<Endian>, EndianBuf<Endian>, Rc<Self::Header>)>;

    /// Parse a single entry from `input`. Returns a tuple of the amount of `input` remaining
    /// and either a parsed representation of the entry or None if `input` is exhausted.
    fn parse_entry(input: EndianBuf<'input, Endian>,
                   header: &Rc<Self::Header>)
                   -> ParseResult<(EndianBuf<'input, Endian>, Option<Self::Entry>)>;
}

pub struct DebugLookup<'input, Endian, Parser>
    where Endian: Endianity,
          Parser: LookupParser<'input, Endian>
{
    input_buffer: EndianBuf<'input, Endian>,
    phantom: PhantomData<Parser>,
}

impl<'input, Endian, Parser> DebugLookup<'input, Endian, Parser>
    where Endian: Endianity,
          Parser: LookupParser<'input, Endian>
{
    pub fn new(input_buffer: &'input [u8]) -> DebugLookup<'input, Endian, Parser> {
        DebugLookup {
            input_buffer: EndianBuf(input_buffer, PhantomData),
            phantom: PhantomData,
        }
    }

    pub fn items(&self) -> LookupEntryIter<'input, Endian, Parser> {
        LookupEntryIter {
            current_header: None,
            current_set: EndianBuf::new(&[]),
            remaining_input: self.input_buffer,
        }
    }
}

pub struct LookupEntryIter<'input, Endian, Parser>
    where Endian: Endianity,
          Parser: LookupParser<'input, Endian>
{
    current_header: Option<Rc<Parser::Header>>, // Only none at the very beginning and end.
    current_set: EndianBuf<'input, Endian>,
    remaining_input: EndianBuf<'input, Endian>,
}

impl<'input, Endian, Parser> LookupEntryIter<'input, Endian, Parser>
    where Endian: Endianity,
          Parser: LookupParser<'input, Endian>
{
    /// Advance the iterator and return the next entry.
    ///
    /// Returns the newly parsed entry as `Ok(Some(Parser::Entry))`. Returns
    /// `Ok(None)` when iteration is complete and all entries have already been
    /// parsed and yielded. If an error occurs while parsing the next entry,
    /// then this error is returned on all subsequent calls as `Err(e)`.
    pub fn next_entry(&mut self) -> ParseResult<Option<Parser::Entry>> {
        if self.current_set.is_empty() {
            if self.remaining_input.is_empty() {
                self.current_header = None;
                Ok(None)
            } else {
                // Parse the next header.
                match Parser::parse_header(self.remaining_input) {
                    Ok((input, set, header)) => {
                        self.remaining_input = input;
                        self.current_set = set;
                        self.current_header = Some(header);
                        // Header is parsed, go parse the first entry.
                        self.next_entry()
                    }
                    Err(e) => {
                        self.remaining_input = self.remaining_input.range_to(..0);
                        self.current_header = None;
                        Err(e)
                    }
                }
            }
        } else {
            match Parser::parse_entry(self.current_set,
                                      self.current_header.as_ref().expect("How did this happen?")) {
                Ok((remaining_set, entry)) => {
                    self.current_set = remaining_set;
                    match entry {
                        None => {
                            // Last entry for this header, go around again and parse a new header.
                            // NB: There could be padding, so we must explicitly truncate
                            // current_set.
                            self.current_set = self.current_set.range_to(..0);
                            self.next_entry()
                        }
                        Some(entry) => Ok(Some(entry)),
                    }
                }
                Err(e) => {
                    self.current_set = self.current_set.range_to(..0);
                    self.current_header = None;
                    // Should we blow away all other sets too? Maybe not ...
                    self.remaining_input = self.remaining_input.range_to(..0);
                    Err(e)
                }
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ArangeHeader {
    format: Format,
    length: u64,
    version: u16,
    offset: DebugInfoOffset,
    address_size: u8,
    segment_size: u8,
}

/// A single parsed arange.
#[derive(Debug, Clone, Eq)]
pub struct ArangeEntry {
    segment: u64,
    offset: u64,
    length: u64,
    header: Rc<ArangeHeader>,
}

impl ArangeEntry {
    /// Return the beginning address of this arange.
    pub fn start(&self) -> u64 {
        debug_assert!(self.segment == 0); // Dunno what to do with this
        self.offset
    }

    /// Return the length of this arange.
    pub fn len(&self) -> u64 {
        self.length
    }

    /// Return the offset into the .debug_info section for this arange.
    pub fn debug_info_offset(&self) -> DebugInfoOffset {
        self.header.offset
    }
}

impl PartialEq for ArangeEntry {
    fn eq(&self, other: &ArangeEntry) -> bool {
        // The expected comparison, but verify that header matches if everything else does.
        match (self.segment == other.segment,
               self.offset == other.offset,
               self.length == other.length) {
            (true, true, true) => {
                debug_assert!(self.header == other.header);
                true
            }
            _ => false,
        }
    }
}

impl PartialOrd for ArangeEntry {
    fn partial_cmp(&self, other: &ArangeEntry) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ArangeEntry {
    fn cmp(&self, other: &ArangeEntry) -> Ordering {
        // The expected comparison, but ignore header.
        match (self.segment.cmp(&other.segment),
               self.offset.cmp(&other.offset),
               self.length.cmp(&other.length)) {
            (Ordering::Equal, Ordering::Equal, Ordering::Equal) => Ordering::Equal,
            (Ordering::Less, _, _) |
            (Ordering::Equal, Ordering::Less, _) |
            (Ordering::Equal, Ordering::Equal, Ordering::Less) => Ordering::Less,
            (Ordering::Greater, _, _) |
            (Ordering::Equal, Ordering::Greater, _) |
            (Ordering::Equal, Ordering::Equal, Ordering::Greater) => Ordering::Greater,
        }
    }
}

pub struct ArangeParser<'input, Endian>
    where Endian: 'input + Endianity
{
    // This struct is never instantiated.
    phantom: PhantomData<&'input Endian>,
}

impl<'input, Endian> LookupParser<'input, Endian> for ArangeParser<'input, Endian>
    where Endian: Endianity
{
    type Header = ArangeHeader;
    type Entry = ArangeEntry;

    /// Parse an arange set header. Returns a tuple of the remaining arange sets, the aranges to be
    /// parsed for this set, and the newly created ArangeHeader struct.
    fn parse_header(input: EndianBuf<Endian>)
                    -> ParseResult<(EndianBuf<Endian>, EndianBuf<Endian>, Rc<Self::Header>)> {
        let (rest, (length, format)) = try!(parse_unit_length(input.into()));
        let (rest, version) = try!(parse_u16(rest.into()));

        if version != 2 {
            return Err(Error::UnknownVersion);
        }

        let (rest, offset) = try!(parse_debug_info_offset(rest.into(), format));
        let (rest, address_size) = try!(parse_address_size(rest.into()));
        let (rest, segment_size) = try!(parse_address_size(rest.into()));

        let header_length = match format {
            Format::Dwarf32 => 8,
            Format::Dwarf64 => 12,
        };
        let dividing_line: usize = try!(length.checked_sub(header_length)
            .ok_or(Error::BadLength)) as usize;

        Ok((rest.range_from(dividing_line..),
            rest.range_to(..dividing_line),
            Rc::new(ArangeHeader {
            format: format,
            length: length,
            version: version,
            offset: offset,
            address_size: address_size,
            segment_size: segment_size,
        })))
    }

    /// Parse a single arange. Return `None` for the null arange, `Some` for an actual arange.
    fn parse_entry(input: EndianBuf<'input, Endian>,
                   header: &Rc<Self::Header>)
                   -> ParseResult<(EndianBuf<'input, Endian>, Option<Self::Entry>)> {
        let address_size = header.address_size;
        let segment_size = header.segment_size; // May be zero!

        let (rest, segment) = try!(parse_uN_as_u64(segment_size, input));
        let (rest, offset) = try!(parse_uN_as_u64(address_size, rest));
        let (rest, length) = try!(parse_uN_as_u64(address_size, rest));

        Ok((rest,
            match (segment, offset, length) {
            (0, 0, 0) => None,
            _ => {
                Some(ArangeEntry {
                    segment: segment,
                    offset: offset,
                    length: length,
                    header: header.clone(),
                })
            }
        }))
    }
}

/// The `DebugAranges` struct represents the DWARF address range information
/// found in the `.debug_aranges` section.
///
/// Provides:
///   new(input: EndianBuf<'input, Endian>) -> DebugAranges<'input, Endian>
///
///   Construct a new `DebugAranges` instance from the data in the `.debug_aranges`
///   section.
///
///   It is the caller's responsibility to read the `.debug_aranges` section and
///   present it as a `&[u8]` slice. That means using some ELF loader on
///   Linux, a Mach-O loader on OSX, etc.
///
///   ```
///   use gimli::{DebugAranges, LittleEndian};
///
///   # let buf = [];
///   # let read_debug_aranges_section_somehow = || &buf;
///   let debug_aranges = DebugAranges::<LittleEndian>::new(read_debug_aranges_section_somehow());
///   ```
///
///   items(&self) -> ArangeEntryIter<'input, Endian>
///
///   Iterate the aranges in the `.debug_aranges` section.
///
///   ```
///   use gimli::{DebugAranges, LittleEndian};
///
///   # let buf = [];
///   # let read_debug_aranges_section_somehow = || &buf;
///   let debug_aranges = DebugAranges::<LittleEndian>::new(read_debug_aranges_section_somehow());
///
///   let mut iter = debug_aranges.items();
///   while let Some(arange) = iter.next_entry().unwrap() {
///     println!("arange starts at {}, has length {}", arange.start(), arange.len());
///   }
///   ```
pub type DebugAranges<'input, Endian> = DebugLookup<'input, Endian, ArangeParser<'input, Endian>>;

/// An iterator over the aranges from a .debug_aranges section.
///
/// Provides:
///   next_entry(self: &mut) -> ParseResult<Option<ArangeEntry>>
///
///   Advance the iterator and return the next arange.
///
///   Returns the newly parsed arange as `Ok(Some(arange))`. Returns
///   `Ok(None)` when iteration is complete and all aranges have already been
///   parsed and yielded. If an error occurs while parsing the next arange,
///   then this error is returned on all subsequent calls as `Err(e)`.
pub type ArangeEntryIter<'input, Endian> = LookupEntryIter<'input,
                                                           Endian,
                                                           ArangeParser<'input, Endian>>;

/// `.debug_pubnames` and `.debug_pubtypes` differ only in which section their offsets point into.
pub trait NamesOrTypesSwitch<'input, Endian>
    where Endian: Endianity
{
    type Header;
    type Entry;
    type Offset;

    fn new_header(format: Format,
                  set_length: u64,
                  version: u16,
                  offset: Self::Offset,
                  length: u64)
                  -> Rc<Self::Header>;

    fn new_entry(offset: u64, name: &'input ffi::CStr, header: &Rc<Self::Header>) -> Self::Entry;

    fn parse_offset(input: EndianBuf<Endian>,
                    format: Format)
                    -> ParseResult<(EndianBuf<Endian>, Self::Offset)>;

    fn format_from(header: &Self::Header) -> Format;
}

pub struct PubStuffParser<'input, Endian, Switch>
    where Endian: 'input + Endianity,
          Switch: 'input + NamesOrTypesSwitch<'input, Endian>
{
    // This struct is never instantiated.
    phantom: PhantomData<&'input (Endian, Switch)>,
}

impl<'input, Endian, Switch> LookupParser<'input, Endian> for PubStuffParser<'input, Endian, Switch>
    where Endian: Endianity,
          Switch: NamesOrTypesSwitch<'input, Endian>
{
    type Header = Switch::Header;
    type Entry = Switch::Entry;

    /// Parse an pubthings set header. Returns a tuple of the remaining pubthings sets, the pubthings
    /// to be parsed for this set, and the newly created PubThingHeader struct.
    fn parse_header(input: EndianBuf<Endian>)
                    -> ParseResult<(EndianBuf<Endian>, EndianBuf<Endian>, Rc<Self::Header>)> {
        let (rest, (set_length, format)) = try!(parse_unit_length(input.into()));
        let (rest, version) = try!(parse_u16(rest.into()));

        if version != 2 {
            return Err(Error::UnknownVersion);
        }

        let (rest, info_offset) = try!(Switch::parse_offset(rest.into(), format));
        let (rest, info_length) = try!(parse_word(rest.into(), format));

        let header_length = match format {
            Format::Dwarf32 => 10,
            Format::Dwarf64 => 18,
        };
        let dividing_line: usize = try!(set_length.checked_sub(header_length)
            .ok_or(Error::BadLength)) as usize;

        Ok((rest.range_from(dividing_line..),
            rest.range_to(..dividing_line),
            Switch::new_header(format, set_length, version, info_offset, info_length)))
    }

    /// Parse a single pubthing. Return `None` for the null pubthing, `Some` for an actual pubthing.
    fn parse_entry(input: EndianBuf<'input, Endian>,
                   header: &Rc<Self::Header>)
                   -> ParseResult<(EndianBuf<'input, Endian>, Option<Self::Entry>)> {
        let (rest, offset) = try!(parse_word(input.into(), Switch::format_from(header)));

        if offset == 0 {
            Ok((rest, None))
        } else {
            let (rest, name) = try!(parse_null_terminated_string(rest.into()));

            Ok((EndianBuf::new(rest), Some(Switch::new_entry(offset, name, header))))
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct PubNamesHeader {
    format: Format,
    length: u64,
    version: u16,
    info_offset: DebugInfoOffset,
    info_length: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct PubTypesHeader {
    format: Format,
    length: u64,
    version: u16,
    types_offset: DebugTypesOffset,
    types_length: u64,
}

/// A single parsed pubname.
#[derive(Debug, Clone)]
pub struct PubNamesEntry<'input> {
    offset: u64,
    name: &'input ffi::CStr,
    header: Rc<PubNamesHeader>,
}

impl<'input> PubNamesEntry<'input> {
    /// Returns the name this entry refers to.
    pub fn name(&self) -> &'input ffi::CStr {
        self.name
    }

    /// Returns the offset into the .debug_info section for this name.
    pub fn info_offset(&self) -> DebugInfoOffset {
        self.header.info_offset
    }
}

/// A single parsed pubtype.
#[derive(Debug, Clone)]
pub struct PubTypesEntry<'input> {
    offset: u64,
    name: &'input ffi::CStr,
    header: Rc<PubTypesHeader>,
}

impl<'input> PubTypesEntry<'input> {
    /// Returns the name of the type this entry refers to.
    pub fn name(&self) -> &'input ffi::CStr {
        self.name
    }

    /// Returns the offset into the .debug_types section for this type.
    pub fn types_offset(&self) -> DebugTypesOffset {
        self.header.types_offset
    }
}

pub struct NamesSwitch<'input, Endian>
    where Endian: 'input + Endianity
{
    phantom: PhantomData<&'input Endian>,
}

impl<'input, Endian> NamesOrTypesSwitch<'input, Endian> for NamesSwitch<'input, Endian>
    where Endian: Endianity
{
    type Header = PubNamesHeader;
    type Entry = PubNamesEntry<'input>;
    type Offset = DebugInfoOffset;

    fn new_header(format: Format,
                  set_length: u64,
                  version: u16,
                  offset: DebugInfoOffset,
                  length: u64)
                  -> Rc<PubNamesHeader> {
        Rc::new(PubNamesHeader {
            format: format,
            length: set_length,
            version: version,
            info_offset: offset,
            info_length: length,
        })
    }

    fn new_entry(offset: u64,
                 name: &'input ffi::CStr,
                 header: &Rc<PubNamesHeader>)
                 -> PubNamesEntry<'input> {
        PubNamesEntry {
            offset: offset,
            name: name,
            header: header.clone(),
        }
    }

    fn parse_offset(input: EndianBuf<Endian>,
                    format: Format)
                    -> ParseResult<(EndianBuf<Endian>, Self::Offset)> {
        parse_debug_info_offset(input, format)
    }

    fn format_from(header: &PubNamesHeader) -> Format {
        header.format
    }
}

pub struct TypesSwitch<'input, Endian>
    where Endian: 'input + Endianity
{
    phantom: PhantomData<&'input Endian>,
}

impl<'input, Endian> NamesOrTypesSwitch<'input, Endian> for TypesSwitch<'input, Endian>
    where Endian: Endianity
{
    type Header = PubTypesHeader;
    type Entry = PubTypesEntry<'input>;
    type Offset = DebugTypesOffset;

    fn new_header(format: Format,
                  set_length: u64,
                  version: u16,
                  offset: DebugTypesOffset,
                  length: u64)
                  -> Rc<PubTypesHeader> {
        Rc::new(PubTypesHeader {
            format: format,
            length: set_length,
            version: version,
            types_offset: offset,
            types_length: length,
        })
    }

    fn new_entry(offset: u64,
                 name: &'input ffi::CStr,
                 header: &Rc<PubTypesHeader>)
                 -> PubTypesEntry<'input> {
        PubTypesEntry {
            offset: offset,
            name: name,
            header: header.clone(),
        }
    }

    fn parse_offset(input: EndianBuf<Endian>,
                    format: Format)
                    -> ParseResult<(EndianBuf<Endian>, Self::Offset)> {
        parse_debug_types_offset(input, format)
    }

    fn format_from(header: &PubTypesHeader) -> Format {
        header.format
    }
}

/// The `DebugPubNames` struct represents the DWARF public names information
/// found in the `.debug_pubnames` section.
///
/// Provides:
///   new(input: EndianBuf<'input, Endian>) -> DebugPubNames<'input, Endian>
///
///   Construct a new `DebugPubNames` instance from the data in the `.debug_pubnames`
///   section.
///
///   It is the caller's responsibility to read the `.debug_pubnames` section and
///   present it as a `&[u8]` slice. That means using some ELF loader on
///   Linux, a Mach-O loader on OSX, etc.
///
///   ```
///   use gimli::{DebugPubNames, LittleEndian};
///
///   # let buf = [];
///   # let read_debug_pubnames_section_somehow = || &buf;
///   let debug_pubnames =
///       DebugPubNames::<LittleEndian>::new(read_debug_pubnames_section_somehow());
///   ```
///
///   items(&self) -> PubNamesEntryIter<'input, Endian>
///
///   Iterate the pubnames in the `.debug_pubnames` section.
///
///   ```
///   use gimli::{DebugPubNames, LittleEndian};
///
///   # let buf = [];
///   # let read_debug_pubnames_section_somehow = || &buf;
///   let debug_pubnames =
///       DebugPubNames::<LittleEndian>::new(read_debug_pubnames_section_somehow());
///
///   let mut iter = debug_pubnames.items();
///   while let Some(pubname) = iter.next_entry().unwrap() {
///     println!("pubname {} found!", pubname.name().to_string_lossy());
///   }
///   ```
pub type DebugPubNames<'input, Endian> = DebugLookup<'input,
                                                     Endian,
                                                     PubStuffParser<'input,
                                                                    Endian,
                                                                    NamesSwitch<'input, Endian>>>;

/// An iterator over the pubnames from a .debug_pubnames section.
///
/// Provides:
///   next_entry(self: &mut) -> ParseResult<Option<PubNamesEntry>>
///
///   Advance the iterator and return the next pubname.
///
///   Returns the newly parsed pubname as `Ok(Some(pubname))`. Returns
///   `Ok(None)` when iteration is complete and all pubnames have already been
///   parsed and yielded. If an error occurs while parsing the next pubname,
///   then this error is returned on all subsequent calls as `Err(e)`.
pub type PubNamesEntryIter<'input, Endian> = LookupEntryIter<'input,
                                                             Endian,
                                                             PubStuffParser<'input,
                                                                            Endian,
                                                                            NamesSwitch<'input,
                                                                                        Endian>>>;

/// The `DebugPubTypes` struct represents the DWARF public types information
/// found in the `.debug_types` section.
///
/// Provides:
///   new(input: EndianBuf<'input, Endian>) -> DebugPubTypes<'input, Endian>
///
///   Construct a new `DebugPubTypes` instance from the data in the `.debug_pubtypes`
///   section.
///
///   It is the caller's responsibility to read the `.debug_pubtypes` section and
///   present it as a `&[u8]` slice. That means using some ELF loader on
///   Linux, a Mach-O loader on OSX, etc.
///
///   ```
///   use gimli::{DebugPubTypes, LittleEndian};
///
///   # let buf = [];
///   # let read_debug_pubtypes_section_somehow = || &buf;
///   let debug_pubtypes =
///       DebugPubTypes::<LittleEndian>::new(read_debug_pubtypes_section_somehow());
///   ```
///
///   items(&self) -> PubTypesEntryIter<'input, Endian>
///
///   Iterate the pubtypes in the `.debug_pubtypes` section.
///
///   ```
///   use gimli::{DebugPubTypes, LittleEndian};
///
///   # let buf = [];
///   # let read_debug_pubtypes_section_somehow = || &buf;
///   let debug_pubtypes =
///       DebugPubTypes::<LittleEndian>::new(read_debug_pubtypes_section_somehow());
///
///   let mut iter = debug_pubtypes.items();
///   while let Some(pubtype) = iter.next_entry().unwrap() {
///     println!("pubtype {} found!", pubtype.name().to_string_lossy());
///   }
///   ```
pub type DebugPubTypes<'input, Endian> = DebugLookup<'input,
                                                     Endian,
                                                     PubStuffParser<'input,
                                                                    Endian,
                                                                    TypesSwitch<'input, Endian>>>;

/// An iterator over the pubtypes from a .debug_pubtypes section.
///
/// Provides:
///   next_entry(self: &mut) -> ParseResult<Option<PubTypesEntry>>
///
///   Advance the iterator and return the next pubtype.
///
///   Returns the newly parsed pubtype as `Ok(Some(pubtype))`. Returns
///   `Ok(None)` when iteration is complete and all pubtypes have already been
///   parsed and yielded. If an error occurs while parsing the next pubtype,
///   then this error is returned on all subsequent calls as `Err(e)`.
pub type PubTypesEntryIter<'input, Endian> = LookupEntryIter<'input,
                                                             Endian,
                                                             PubStuffParser<'input,
                                                                            Endian,
                                                                            TypesSwitch<'input,
                                                                                        Endian>>>;
