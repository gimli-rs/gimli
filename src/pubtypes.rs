#![deny(missing_docs)]

use endianity::{Endianity, EndianBuf};
use lookup::{PubStuffParser, LookupEntryIter, DebugLookup, NamesOrTypesSwitch};
use parser::{Format, ParseResult};
use unit::DebugTypesOffset;
use std::ffi;
use std::marker::PhantomData;
use std::rc::Rc;

#[derive(Debug, PartialEq, Eq)]
pub struct PubTypesHeader {
    format: Format,
    length: u64,
    version: u16,
    types_offset: DebugTypesOffset,
    types_length: u64,
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
        DebugTypesOffset::parse(input, format)
    }

    fn format_from(header: &PubTypesHeader) -> Format {
        header.format
    }
}

/// The `DebugPubTypes` struct represents the DWARF public types information
/// found in the `.debug_types` section.
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

/// An iterator over the pubtypes from a .debug_pubtypes section.
///
/// Provides:
///
/// * `next_entry(self: &mut) -> ParseResult<Option<PubTypesEntry>>`
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
