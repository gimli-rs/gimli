use parser::{parse_initial_length, Format, Result, Error};
use reader::Reader;
use std::marker::PhantomData;
use unit::{DebugInfoOffset, UnitOffset, parse_debug_info_offset};

// The various "Accelerated Access" sections (DWARF standard v4 Section 6.1) all have
// similar structures. They consist of a header with metadata and an offset into the
// .debug_info section for the entire compilation unit, and a series
// of following entries that list addresses (for .debug_aranges) or names
// (for .debug_pubnames and .debug_pubtypes) that are covered.
//
// Because these three tables all have similar structures, we abstract out some of
// the parsing mechanics.

pub trait LookupParser<R: Reader> {
    /// The type of the produced header.
    type Header;
    /// The type of the produced entry.
    type Entry;

    /// Parse a header from `input`. Returns a tuple of `input` sliced to contain just the entries
    /// corresponding to this header (without the header itself), and the parsed representation of
    /// the header itself.
    fn parse_header(input: &mut R) -> Result<(R, Self::Header)>;

    /// Parse a single entry from `input`. Returns either a parsed representation of the entry
    /// or None if `input` is exhausted.
    fn parse_entry(input: &mut R, header: &Self::Header) -> Result<Option<Self::Entry>>;
}

#[derive(Clone, Debug)]
pub struct DebugLookup<R, Parser>
    where R: Reader,
          Parser: LookupParser<R>
{
    input_buffer: R,
    phantom: PhantomData<Parser>,
}

impl<R, Parser> From<R> for DebugLookup<R, Parser>
    where R: Reader,
          Parser: LookupParser<R>
{
    fn from(input_buffer: R) -> Self {
        DebugLookup {
            input_buffer: input_buffer,
            phantom: PhantomData,
        }
    }
}

impl<R, Parser> DebugLookup<R, Parser>
    where R: Reader,
          Parser: LookupParser<R>
{
    pub fn items(&self) -> LookupEntryIter<R, Parser> {
        LookupEntryIter {
            current_set: None,
            remaining_input: self.input_buffer.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct LookupEntryIter<R, Parser>
    where R: Reader,
          Parser: LookupParser<R>
{
    current_set: Option<(R, Parser::Header)>, // Only none at the very beginning and end.
    remaining_input: R,
}

impl<R, Parser> LookupEntryIter<R, Parser>
    where R: Reader,
          Parser: LookupParser<R>
{
    /// Advance the iterator and return the next entry.
    ///
    /// Returns the newly parsed entry as `Ok(Some(Parser::Entry))`. Returns
    /// `Ok(None)` when iteration is complete and all entries have already been
    /// parsed and yielded. If an error occurs while parsing the next entry,
    /// then this error is returned on all subsequent calls as `Err(e)`.
    ///
    /// Can be [used with `FallibleIterator`](./index.html#using-with-fallibleiterator).
    pub fn next(&mut self) -> Result<Option<Parser::Entry>> {
        loop {
            if let Some((ref mut input, ref header)) = self.current_set {
                if !input.is_empty() {
                    if let Some(entry) = Parser::parse_entry(input, header)? {
                        return Ok(Some(entry));
                    }
                }
            }
            if self.remaining_input.is_empty() {
                self.current_set = None;
                return Ok(None);
            }
            self.current_set = Some(Parser::parse_header(&mut self.remaining_input)?);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PubStuffHeader {
    format: Format,
    length: u64,
    version: u16,
    unit_offset: DebugInfoOffset,
    unit_length: u64,
}

pub trait PubStuffEntry<R: Reader> {
    fn new(die_offset: UnitOffset, name: R, unit_header_offset: DebugInfoOffset) -> Self;
}

#[derive(Clone, Debug)]
pub struct PubStuffParser<R, Entry>
    where R: Reader,
          Entry: PubStuffEntry<R>
{
    // This struct is never instantiated.
    phantom: PhantomData<(R, Entry)>,
}

impl<R, Entry> LookupParser<R> for PubStuffParser<R, Entry>
    where R: Reader,
          Entry: PubStuffEntry<R>
{
    type Header = PubStuffHeader;
    type Entry = Entry;

    /// Parse an pubthings set header. Returns a tuple of the
    /// pubthings to be parsed for this set, and the newly created PubThingHeader struct.
    fn parse_header(input: &mut R) -> Result<(R, Self::Header)> {
        let (length, format) = parse_initial_length(input)?;
        let mut rest = input.split(length as usize)?;

        let version = rest.read_u16()?;
        if version != 2 {
            return Err(Error::UnknownVersion);
        }

        let unit_offset = parse_debug_info_offset(&mut rest, format)?;
        let unit_length = rest.read_word(format)?;

        let header = PubStuffHeader {
            format,
            length,
            version,
            unit_offset,
            unit_length,
        };
        Ok((rest, header))
    }

    /// Parse a single pubthing. Return `None` for the null pubthing, `Some` for an actual pubthing.
    fn parse_entry(input: &mut R, header: &Self::Header) -> Result<Option<Self::Entry>> {
        let offset = input.read_word(header.format)?;

        if offset == 0 {
            input.empty();
            Ok(None)
        } else {
            let name = input.read_null_terminated_slice()?;
            Ok(Some(Self::Entry::new(UnitOffset(offset as usize), name, header.unit_offset)))
        }
    }
}
