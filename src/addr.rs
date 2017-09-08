///! Functions for parsing DWARF `.debug_info` and `.debug_types` sections.

use endianity::{Endianity, EndianBuf};
use parser::{Result};
/// gchampagne: readd use fallible_iterator::FallibleIterator;
use reader::{Reader, ReaderOffset};
use Section;

/// An offset into the `.debug_addr` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DebugAddrOffset<T = usize>(pub T);

/// The `DebugAddr` struct represents the DWARF debugging information found in
/// the `.debug_addr` section.
#[derive(Debug, Clone, Copy)]
pub struct DebugAddr<R: Reader> {
    debug_addr_section: R,
}

impl<'input, Endian> DebugAddr<EndianBuf<'input, Endian>>
    where Endian: Endianity
{
    /// Construct a new `DebugAddr` instance from the data in the `.debug_addr`
    /// section.
    ///
    /// It is the caller's responsibility to read the `.debug_addr` section and
    /// present it as a `&[u8]` slice. That means using some ELF loader on
    /// Linux, a Mach-O loader on OSX, etc.
    ///
    /// ```
    /// use gimli::{DebugAddr, LittleEndian};
    /// gchampagne: compelete this
    /// ```
    pub fn new(debug_addr_section: &'input [u8], endian: Endian) -> Self {
        Self::from(EndianBuf::new(debug_addr_section, endian))
    }
}

impl <R: Reader> DebugAddr<R> {

    /// gchampagne: add comments + rename?
    pub fn set_of_entries(&self) -> AddressTableSetIter<R> {
        AddressTableSetIter {
            input: self.debug_addr_section.clone(),
            offset: DebugAddrOffset(R::Offset::from_u8(0)),
        }
    }
    
    /// cheezus
    pub fn len(&self) -> R::Offset {
        self.debug_addr_section.len()
    }
}

impl<R: Reader> Section<R> for DebugAddr<R> {
    fn section_name() -> &'static str {
        ".debug_info"
    }
}

impl<R: Reader> From<R> for DebugAddr<R> {
    fn from(debug_addr_section : R) -> Self {
        DebugAddr { debug_addr_section }
    }
}

/// An iterator over the sets of entry contained in the debug_addr section
#[derive(Clone, Debug)]
pub struct AddressTableSetIter<R: Reader> {
    input: R,
    offset: DebugAddrOffset<R::Offset>,
}

impl<R: Reader> AddressTableSetIter<R> {
    /// Advance the iterator to the next set on entries 
    pub fn next(&mut self) -> Result<Option<AddressTableEntryHeader<R, R::Offset>>> {
        Ok(None)
    }
}

/// Header of a set of entry 
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressTableEntryHeader<R, Offset = usize>
    where R : Reader<Offset = Offset>,
          Offset: ReaderOffset
{
    /// gchampagne: add comments
    unit_length: Offset,
    version: u16,
    address_size: u8,
    segment_size: u8,
    offset: DebugAddrOffset<Offset>,
    entries_buf: R,
}

