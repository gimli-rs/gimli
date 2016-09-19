use endianity::{Endianity, EndianBuf};
use lookup::{PubStuffParser, LookupEntryIter, DebugLookup, NamesOrTypesSwitch};
use parser::{Format, Result};
use unit::{DebugInfoOffset, parse_debug_info_offset};
use std::ffi;
use std::marker::PhantomData;
use std::rc::Rc;

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


#[derive(Clone, Debug)]
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
                    -> Result<(EndianBuf<Endian>, Self::Offset)> {
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
/// * `new(input: EndianBuf<'input, Endian>) -> DebugPubNames<'input, Endian>`
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
/// * `items(&self) -> PubNamesEntryIter<'input, Endian>`
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
///   while let Some(pubname) = iter.next().unwrap() {
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
pub type PubNamesEntryIter<'input, Endian> = LookupEntryIter<'input,
                                                             Endian,
                                                             PubStuffParser<'input,
                                                                            Endian,
                                                                            NamesSwitch<'input,
                                                                                        Endian>>>;
