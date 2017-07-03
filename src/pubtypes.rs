use endianity::{Endianity, EndianBuf};
use lookup::{PubStuffParser, LookupEntryIter, DebugLookup, NamesOrTypesSwitch};
use parser::{Format, Result};
use unit::{DebugInfoOffset, UnitOffset, parse_debug_info_offset};
use std::ffi;
use std::marker::PhantomData;
use Section;

#[derive(Debug, PartialEq, Eq)]
pub struct PubTypesHeader {
    format: Format,
    length: u64,
    version: u16,
    info_offset: DebugInfoOffset,
    info_length: u64,
}

/// A single parsed pubtype.
#[derive(Debug, Clone)]
pub struct PubTypesEntry<'input> {
    unit_header_offset: DebugInfoOffset,
    die_offset: UnitOffset,
    name: &'input ffi::CStr,
}

impl<'input> PubTypesEntry<'input> {
    /// Returns the name of the type this entry refers to.
    pub fn name(&self) -> &'input ffi::CStr {
        self.name
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

    fn new_entry(offset: u64,
                 name: &'input ffi::CStr,
                 header: &PubTypesHeader)
                 -> PubTypesEntry<'input> {
        PubTypesEntry {
            unit_header_offset: header.info_offset,
            die_offset: UnitOffset(offset as usize),
            name: name,
        }
    }

    fn parse_offset(input: &mut EndianBuf<Endian>, format: Format) -> Result<Self::Offset> {
        parse_debug_info_offset(input, format)
    }

    fn format_from(header: &PubTypesHeader) -> Format {
        header.format
    }
}

/// The `DebugPubTypes` struct represents the DWARF public types information
/// found in the `.debug_info` section.
///
/// Provides:
///
/// * `new(input: EndianBuf<'input, Endian>) -> DebugPubTypes<'input, Endian>`
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
///   # let read_debug_pubtypes_somehow = || &buf;
///   let debug_pubtypes = DebugPubTypes::<LittleEndian>::new(read_debug_pubtypes_somehow());
///   ```
///
/// * `items(&self) -> PubTypesEntryIter<'input, Endian>`
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
///   while let Some(pubtype) = iter.next().unwrap() {
///     println!("pubtype {} found!", pubtype.name().to_string_lossy());
///   }
///   ```
pub type DebugPubTypes<'input, Endian> = DebugLookup<'input,
                                                     Endian,
                                                     PubStuffParser<'input,
                                                                    Endian,
                                                                    TypesSwitch<'input, Endian>>>;

impl<'input, Endian> Section<'input> for DebugPubTypes<'input, Endian>
    where Endian: Endianity
{
    fn section_name() -> &'static str {
        ".debug_pubtypes"
    }
}

impl<'input, Endian> From<&'input [u8]> for DebugPubTypes<'input, Endian>
    where Endian: Endianity
{
    fn from(v: &'input [u8]) -> Self {
        Self::new(v)
    }
}

/// An iterator over the pubtypes from a `.debug_pubtypes` section.
///
/// Provides:
///
/// * `next(self: &mut) -> gimli::Result<Option<PubTypesEntry>>`
///
///   Advance the iterator and return the next pubtype.
///
///   Returns the newly parsed pubtype as `Ok(Some(pubtype))`. Returns
///   `Ok(None)` when iteration is complete and all pubtypes have already been
///   parsed and yielded. If an error occurs while parsing the next pubtype,
///   then this error is returned on all subsequent calls as `Err(e)`.
///
///   Can be [used with
///   `FallibleIterator`](./index.html#using-with-fallibleiterator).
pub type PubTypesEntryIter<'input, Endian> = LookupEntryIter<'input,
                                                             Endian,
                                                             PubStuffParser<'input,
                                                                            Endian,
                                                                            TypesSwitch<'input,
                                                                                        Endian>>>;
