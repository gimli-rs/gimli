use endianity::{Endianity, EndianBuf};
use fallible_iterator::FallibleIterator;
use lookup::{PubStuffParser, LookupEntryIter, DebugLookup, NamesOrTypesSwitch};
use parser::{Error, Format, Result};
use reader::Reader;
use unit::{DebugInfoOffset, UnitOffset, parse_debug_info_offset};
use std::marker::PhantomData;
use Section;

#[derive(Debug, Clone, PartialEq, Eq)]
struct PubTypesHeader {
    format: Format,
    length: u64,
    version: u16,
    info_offset: DebugInfoOffset,
    info_length: u64,
}

/// A single parsed pubtype.
#[derive(Debug, Clone)]
pub struct PubTypesEntry<R: Reader> {
    unit_header_offset: DebugInfoOffset,
    die_offset: UnitOffset,
    name: R,
}

impl<R: Reader> PubTypesEntry<R> {
    /// Returns the name of the type this entry refers to.
    pub fn name(&self) -> &R {
        &self.name
    }

    /// Returns the offset into the .debug_info section for the header of the compilation unit
    /// which contains the type with this name.
    pub fn unit_header_offset(&self) -> DebugInfoOffset {
        self.unit_header_offset
    }

    /// Returns the offset into the compilation unit for the debugging information entry which
    /// the type with this name.
    pub fn die_offset(&self) -> UnitOffset {
        self.die_offset
    }
}

#[derive(Clone, Debug)]
struct TypesSwitch<R: Reader> {
    phantom: PhantomData<R>,
}

impl<R: Reader> NamesOrTypesSwitch<R> for TypesSwitch<R> {
    type Header = PubTypesHeader;
    type Entry = PubTypesEntry<R>;
    type Offset = DebugInfoOffset;

    fn new_header(format: Format,
                  set_length: u64,
                  version: u16,
                  offset: DebugInfoOffset,
                  length: u64)
                  -> PubTypesHeader {
        PubTypesHeader {
            format: format,
            length: set_length,
            version: version,
            info_offset: offset,
            info_length: length,
        }
    }

    fn new_entry(offset: u64, name: R, header: &PubTypesHeader) -> PubTypesEntry<R> {
        PubTypesEntry {
            unit_header_offset: header.info_offset,
            die_offset: UnitOffset(offset as usize),
            name: name,
        }
    }

    fn parse_offset(input: &mut R, format: Format) -> Result<Self::Offset> {
        parse_debug_info_offset(input, format)
    }

    fn format_from(header: &PubTypesHeader) -> Format {
        header.format
    }
}

/// The `DebugPubTypes` struct represents the DWARF public types information
/// found in the `.debug_info` section.
#[derive(Debug, Clone)]
pub struct DebugPubTypes<R: Reader>(DebugLookup<R, PubStuffParser<R, TypesSwitch<R>>>);

impl<'input, Endian> DebugPubTypes<EndianBuf<'input, Endian>>
    where Endian: Endianity
{
    /// Construct a new `DebugPubTypes` instance from the data in the `.debug_pubtypes`
    /// section.
    ///
    /// It is the caller's responsibility to read the `.debug_pubtypes` section and
    /// present it as a `&[u8]` slice. That means using some ELF loader on
    /// Linux, a Mach-O loader on OSX, etc.
    ///
    /// ```
    /// use gimli::{DebugPubTypes, EndianBuf, LittleEndian};
    ///
    /// # let buf = [];
    /// # let read_debug_pubtypes_somehow = || &buf;
    /// let debug_pubtypes =
    ///     DebugPubTypes::<EndianBuf<LittleEndian>>::new(read_debug_pubtypes_somehow());
    /// ```
    pub fn new(debug_pubtypes_section: &'input [u8]) -> Self {
        Self::from(EndianBuf::new(debug_pubtypes_section))
    }
}

impl<R: Reader> DebugPubTypes<R> {
    /// Iterate the pubtypes in the `.debug_pubtypes` section.
    ///
    /// ```
    /// use gimli::{DebugPubTypes, EndianBuf, LittleEndian};
    ///
    /// # let buf = [];
    /// # let read_debug_pubtypes_section_somehow = || &buf;
    /// let debug_pubtypes =
    ///     DebugPubTypes::<EndianBuf<LittleEndian>>::new(read_debug_pubtypes_section_somehow());
    ///
    /// let mut iter = debug_pubtypes.items();
    /// while let Some(pubtype) = iter.next().unwrap() {
    ///   println!("pubtype {} found!", pubtype.name().to_string_lossy());
    /// }
    /// ```
    pub fn items(&self) -> PubTypesEntryIter<R> {
        PubTypesEntryIter(self.0.items())
    }
}

impl<R: Reader> Section<R> for DebugPubTypes<R> {
    fn section_name() -> &'static str {
        ".debug_pubtypes"
    }
}

impl<R: Reader> From<R> for DebugPubTypes<R> {
    fn from(debug_pubtypes_section: R) -> Self {
        DebugPubTypes(DebugLookup::from(debug_pubtypes_section))
    }
}

/// An iterator over the pubtypes from a `.debug_pubtypes` section.
///
/// Can be [used with
/// `FallibleIterator`](./index.html#using-with-fallibleiterator).
#[derive(Debug, Clone)]
pub struct PubTypesEntryIter<R: Reader>(LookupEntryIter<R, PubStuffParser<R, TypesSwitch<R>>>);

impl<R: Reader> PubTypesEntryIter<R> {
    /// Advance the iterator and return the next pubtype.
    ///
    /// Returns the newly parsed pubtype as `Ok(Some(pubtype))`. Returns
    /// `Ok(None)` when iteration is complete and all pubtypes have already been
    /// parsed and yielded. If an error occurs while parsing the next pubtype,
    /// then this error is returned on all subsequent calls as `Err(e)`.
    pub fn next(&mut self) -> Result<Option<PubTypesEntry<R>>> {
        self.0.next()
    }
}

impl<R: Reader> FallibleIterator for PubTypesEntryIter<R> {
    type Item = PubTypesEntry<R>;
    type Error = Error;

    fn next(&mut self) -> ::std::result::Result<Option<Self::Item>, Self::Error> {
        self.0.next()
    }
}
