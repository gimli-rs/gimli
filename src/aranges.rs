#![deny(missing_docs)]

use endianity::{Endianity, EndianBuf};
use parser::{parse_u16, parse_uN_as_u64, parse_unit_length, parse_debug_info_offset,
             parse_address_size, DebugInfoOffset, Format, ParseResult, Error};
use std::cmp::Ordering;
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

pub trait LookupParser<Endian>
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
    fn parse_entry<'input>(input: EndianBuf<'input, Endian>,
                           header: &Rc<Self::Header>)
                           -> ParseResult<(EndianBuf<'input, Endian>, Option<Self::Entry>)>;
}

pub struct DebugLookup<'input, Endian, Parser>
    where Endian: Endianity,
          Parser: LookupParser<Endian>
{
    input_buffer: EndianBuf<'input, Endian>,
    phantom: PhantomData<Parser>,
}

impl<'input, Endian, Parser> DebugLookup<'input, Endian, Parser>
    where Endian: Endianity,
          Parser: LookupParser<Endian>
{
    pub fn new(input_buffer: &'input [u8]) -> DebugLookup<'input, Endian, Parser> {
        DebugLookup {
            input_buffer: EndianBuf(input_buffer, PhantomData),
            phantom: PhantomData,
        }
    }

    pub fn items(&self) -> LookupEntryIter<Endian, Parser> {
        LookupEntryIter {
            current_header: None,
            current_set: EndianBuf::new(&[]),
            remaining_input: self.input_buffer,
        }
    }
}

pub struct LookupEntryIter<'input, Endian, Parser>
    where Endian: Endianity,
          Parser: LookupParser<Endian>
{
    current_header: Option<Rc<Parser::Header>>, // Only none at the very beginning and end.
    current_set: EndianBuf<'input, Endian>,
    remaining_input: EndianBuf<'input, Endian>,
}

impl<'input, Endian, Parser> LookupEntryIter<'input, Endian, Parser>
    where Endian: Endianity,
          Parser: LookupParser<Endian>
{
    /// Advance the iterator and return the next entry.
    ///
    /// Returns the newly parsed arange as `Ok(Some(arange))`. Returns
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

pub struct ArangeParser<Endian>
    where Endian: Endianity
{
    phantom: PhantomData<Endian>,
}

impl<Endian> LookupParser<Endian> for ArangeParser<Endian>
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
    fn parse_entry<'input>(input: EndianBuf<'input, Endian>,
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
pub type DebugAranges<'input, Endian> = DebugLookup<'input, Endian, ArangeParser<Endian>>;

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
pub type ArangeEntryIter<'input, Endian> = LookupEntryIter<'input, Endian, ArangeParser<Endian>>;
