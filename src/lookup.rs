use endianity::{Endianity, EndianBuf};
use fallible_iterator::FallibleIterator;
use parser::{parse_null_terminated_string, parse_initial_length, parse_u16, parse_word, take,
             Format, Result, Error};
use std::ffi;
use std::marker::PhantomData;
use std::rc::Rc;

// The various "Accelerated Access" sections (DWARF standard v4 Section 6.1) all have
// similar structures. They consist of a header with metadata and an offset into the
// .debug_info section for the entire compilation unit, and a series
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

    /// Parse a header from `input`. Returns a tuple of `input` sliced to contain just the entries
    /// corresponding to this header (without the header itself), and the parsed representation of
    /// the header itself.
    #[allow(type_complexity)]
    fn parse_header(input: &mut EndianBuf<'input, Endian>)
                    -> Result<(EndianBuf<'input, Endian>, Rc<Self::Header>)>;

    /// Parse a single entry from `input`. Returns either a parsed representation of the entry
    /// or None if `input` is exhausted.
    fn parse_entry(input: &mut EndianBuf<'input, Endian>,
                   header: &Rc<Self::Header>)
                   -> Result<Option<Self::Entry>>;
}

#[allow(missing_docs)]
#[derive(Clone, Debug)]
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
    #[allow(missing_docs)]
    pub fn new(input_buffer: &'input [u8]) -> DebugLookup<'input, Endian, Parser> {
        DebugLookup {
            input_buffer: EndianBuf::new(input_buffer),
            phantom: PhantomData,
        }
    }

    #[allow(missing_docs)]
    pub fn items(&self) -> LookupEntryIter<'input, Endian, Parser> {
        LookupEntryIter {
            current_header: None,
            current_set: EndianBuf::new(&[]),
            remaining_input: self.input_buffer,
        }
    }
}

#[allow(missing_docs)]
#[derive(Clone, Debug)]
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
    ///
    /// Can be [used with `FallibleIterator`](./index.html#using-with-fallibleiterator).
    pub fn next(&mut self) -> Result<Option<Parser::Entry>> {
        if self.current_set.is_empty() {
            if self.remaining_input.is_empty() {
                self.current_header = None;
                Ok(None)
            } else {
                // Parse the next header.
                let (set, header) = Parser::parse_header(&mut self.remaining_input)?;
                self.current_set = set;
                self.current_header = Some(header);
                // Header is parsed, go parse the first entry.
                self.next()
            }
        } else {
            let entry = Parser::parse_entry(&mut self.current_set,
                                            self.current_header.as_ref().unwrap())?;
            match entry {
                None => self.next(),
                Some(entry) => Ok(Some(entry)),
            }
        }
    }
}

impl<'input, Endian, Parser> FallibleIterator for LookupEntryIter<'input, Endian, Parser>
    where Endian: Endianity,
          Parser: LookupParser<'input, Endian>
{
    type Item = Parser::Entry;
    type Error = Error;

    fn next(&mut self) -> ::std::result::Result<Option<Self::Item>, Self::Error> {
        LookupEntryIter::next(self)
    }
}

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

    fn parse_offset(input: &mut EndianBuf<Endian>, format: Format) -> Result<Self::Offset>;

    fn format_from(header: &Self::Header) -> Format;
}

#[derive(Clone, Debug)]
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

    /// Parse an pubthings set header. Returns a tuple of the remaining pubthings sets, the
    /// pubthings to be parsed for this set, and the newly created PubThingHeader struct.
    #[allow(type_complexity)]
    fn parse_header(input: &mut EndianBuf<'input, Endian>)
                    -> Result<(EndianBuf<'input, Endian>, Rc<Self::Header>)> {
        let (set_length, format) = parse_initial_length(input)?;
        let rest = &mut take(set_length as usize, input)?;

        let version = parse_u16(rest)?;
        if version != 2 {
            return Err(Error::UnknownVersion);
        }

        let info_offset = Switch::parse_offset(rest, format)?;
        let info_length = parse_word(rest, format)?;

        Ok((*rest, Switch::new_header(format, set_length, version, info_offset, info_length)))
    }

    /// Parse a single pubthing. Return `None` for the null pubthing, `Some` for an actual pubthing.
    fn parse_entry(input: &mut EndianBuf<'input, Endian>,
                   header: &Rc<Self::Header>)
                   -> Result<Option<Self::Entry>> {
        let offset = parse_word(input, Switch::format_from(header))?;

        if offset == 0 {
            *input = EndianBuf::new(&[]);
            Ok(None)
        } else {
            let name = parse_null_terminated_string(input)?;
            Ok(Some(Switch::new_entry(offset, name, header)))
        }
    }
}
