use endianity::{Endianity, EndianBuf};
use lookup::{PubStuffParser, LookupEntryIter, DebugLookup, NamesOrTypesSwitch};
use parser::{Format, Result};
use reader::Reader;
use unit::{DebugInfoOffset, UnitOffset, parse_debug_info_offset};
use std::marker::PhantomData;
use Section;

#[derive(Debug, PartialEq, Eq)]
pub struct PubNamesHeader {
    format: Format,
    length: u64,
    version: u16,
    info_offset: DebugInfoOffset,
    info_length: u64,
}

/// A single parsed pubname.
#[derive(Debug, Clone)]
pub struct PubNamesEntry<R: Reader> {
    unit_header_offset: DebugInfoOffset,
    die_offset: UnitOffset,
    name: R,
}

impl<R: Reader> PubNamesEntry<R> {
    /// Returns the name this entry refers to.
    pub fn name(&self) -> &R {
        &self.name
    }

    /// Returns the offset into the .debug_info section for the header of the compilation unit
    /// which contains this name.
    pub fn unit_header_offset(&self) -> DebugInfoOffset {
        self.unit_header_offset
    }

    /// Returns the offset into the compilation unit for the debugging information entry which
    /// has this name.
    pub fn die_offset(&self) -> UnitOffset {
        self.die_offset
    }
}


#[derive(Clone, Debug)]
pub struct NamesSwitch<R: Reader> {
    phantom: PhantomData<R>,
}

impl<R: Reader> NamesOrTypesSwitch<R> for NamesSwitch<R> {
    type Header = PubNamesHeader;
    type Entry = PubNamesEntry<R>;
    type Offset = DebugInfoOffset;

    fn new_header(format: Format,
                  set_length: u64,
                  version: u16,
                  offset: DebugInfoOffset,
                  length: u64)
                  -> PubNamesHeader {
        PubNamesHeader {
            format: format,
            length: set_length,
            version: version,
            info_offset: offset,
            info_length: length,
        }
    }

    fn new_entry(offset: u64, name: R, header: &PubNamesHeader) -> PubNamesEntry<R> {
        PubNamesEntry {
            unit_header_offset: header.info_offset,
            die_offset: UnitOffset(offset as usize),
            name: name,
        }
    }

    fn parse_offset(input: &mut R, format: Format) -> Result<Self::Offset> {
        parse_debug_info_offset(input, format)
    }

    fn format_from(header: &PubNamesHeader) -> Format {
        header.format
    }
}

/// The `DebugPubNames` struct represents the DWARF public names information
/// found in the `.debug_pubnames` section.
///
/// Provides:
///
/// * `new(input: EndianBuf<'input, Endian>) -> DebugPubNames<EndianBuf<'input, Endian>>`
///
///   Construct a new `DebugPubNames` instance from the data in the `.debug_pubnames`
///   section.
///
///   It is the caller's responsibility to read the `.debug_pubnames` section and
///   present it as a `&[u8]` slice. That means using some ELF loader on
///   Linux, a Mach-O loader on OSX, etc.
///
///   ```
///   use gimli::{DebugPubNames, EndianBuf, LittleEndian};
///
///   # let buf = [];
///   # let read_debug_pubnames_section_somehow = || &buf;
///   let debug_pubnames =
///       DebugPubNames::<EndianBuf<LittleEndian>>::new(read_debug_pubnames_section_somehow());
///   ```
///
/// * `from_reader(input: R) -> DebugPubNames<R>`
///
///   Construct a new `DebugPubNames` instance from the data in the `.debug_pubnames`
///   section.
///
/// * `items(&self) -> PubNamesEntryIter<R>`
///
///   Iterate the pubnames in the `.debug_pubnames` section.
///
///   ```
///   use gimli::{DebugPubNames, EndianBuf, LittleEndian};
///
///   # let buf = [];
///   # let read_debug_pubnames_section_somehow = || &buf;
///   let debug_pubnames =
///       DebugPubNames::<EndianBuf<LittleEndian>>::new(read_debug_pubnames_section_somehow());
///
///   let mut iter = debug_pubnames.items();
///   while let Some(pubname) = iter.next().unwrap() {
///     println!("pubname {} found!", pubname.name().to_string_lossy());
///   }
///   ```
pub type DebugPubNames<R> = DebugLookup<R, PubStuffParser<R, NamesSwitch<R>>>;


impl<'input, Endian> Section<'input> for DebugPubNames<EndianBuf<'input, Endian>>
    where Endian: Endianity
{
    fn section_name() -> &'static str {
        ".debug_pubnames"
    }
}

impl<'input, Endian> From<&'input [u8]> for DebugPubNames<EndianBuf<'input, Endian>>
    where Endian: Endianity
{
    fn from(v: &'input [u8]) -> Self {
        Self::new(v)
    }
}

/// An iterator over the pubnames from a `.debug_pubnames` section.
///
/// Provides:
///
/// * `next(self: &mut) -> gimli::Result<Option<PubNamesEntry>>`
///
///   Advance the iterator and return the next pubname.
///
///   Returns the newly parsed pubname as `Ok(Some(pubname))`. Returns
///   `Ok(None)` when iteration is complete and all pubnames have already been
///   parsed and yielded. If an error occurs while parsing the next pubname,
///   then this error is returned on all subsequent calls as `Err(e)`.
///
///   Can be [used with
///   `FallibleIterator`](./index.html#using-with-fallibleiterator).
pub type PubNamesEntryIter<R> = LookupEntryIter<R, PubStuffParser<R, NamesSwitch<R>>>;
