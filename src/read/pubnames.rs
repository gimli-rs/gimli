use crate::common::{DebugInfoOffset, SectionId};
use crate::endianity::Endianity;
use crate::read::lookup::{DebugPubSet, PubSetEntry, PubSetEntryIter};
use crate::read::{EndianSlice, Reader, Result, Section, UnitOffset};

/// A single parsed pubname.
#[derive(Debug, Clone)]
pub struct PubNamesEntry<R: Reader>(PubSetEntry<R>);

impl<R: Reader> PubNamesEntry<R> {
    /// Returns the name this entry refers to.
    pub fn name(&self) -> &R {
        &self.0.name
    }

    /// Returns the offset into the .debug_info section for the header of the compilation unit
    /// which contains this name.
    pub fn unit_header_offset(&self) -> DebugInfoOffset<R::Offset> {
        self.0.unit_header_offset
    }

    /// Returns the offset into the compilation unit for the debugging information entry which
    /// has this name.
    pub fn die_offset(&self) -> UnitOffset<R::Offset> {
        self.0.die_offset
    }
}

/// The `DebugPubNames` struct represents the DWARF public names information
/// found in the `.debug_pubnames` section.
#[derive(Debug, Clone)]
pub struct DebugPubNames<R: Reader>(DebugPubSet<R>);

impl<'input, Endian> DebugPubNames<EndianSlice<'input, Endian>>
where
    Endian: Endianity,
{
    /// Construct a new `DebugPubNames` instance from the data in the `.debug_pubnames`
    /// section.
    ///
    /// It is the caller's responsibility to read the `.debug_pubnames` section and
    /// present it as a `&[u8]` slice. That means using some ELF loader on
    /// Linux, a Mach-O loader on macOS, etc.
    ///
    /// ```
    /// use gimli::{DebugPubNames, LittleEndian};
    ///
    /// # let buf = [];
    /// # let read_debug_pubnames_section_somehow = || &buf;
    /// let debug_pubnames =
    ///     DebugPubNames::new(read_debug_pubnames_section_somehow(), LittleEndian);
    /// ```
    pub fn new(section: &'input [u8], endian: Endian) -> Self {
        Self::from(EndianSlice::new(section, endian))
    }
}

impl<R: Reader> DebugPubNames<R> {
    /// Iterate the pubnames in the `.debug_pubnames` section.
    ///
    /// ```
    /// use gimli::{DebugPubNames, EndianSlice, LittleEndian};
    ///
    /// # let buf = [];
    /// # let read_debug_pubnames_section_somehow = || &buf;
    /// let debug_pubnames =
    ///     DebugPubNames::new(read_debug_pubnames_section_somehow(), LittleEndian);
    ///
    /// let mut iter = debug_pubnames.items();
    /// while let Some(pubname) = iter.next().unwrap() {
    ///   println!("pubname {} found!", pubname.name().to_string_lossy());
    /// }
    /// ```
    pub fn items(&self) -> PubNamesEntryIter<R> {
        PubNamesEntryIter(self.0.items())
    }
}

impl<R: Reader> Section<R> for DebugPubNames<R> {
    fn id() -> SectionId {
        SectionId::DebugPubNames
    }

    fn reader(&self) -> &R {
        &self.0.section
    }
}

impl<R: Reader> From<R> for DebugPubNames<R> {
    fn from(section: R) -> Self {
        DebugPubNames(DebugPubSet { section })
    }
}

/// An iterator over the pubnames from a `.debug_pubnames` section.
#[derive(Debug, Clone)]
pub struct PubNamesEntryIter<R: Reader>(PubSetEntryIter<R>);

impl<R: Reader> PubNamesEntryIter<R> {
    /// Advance the iterator and return the next pubname.
    ///
    /// Returns the newly parsed pubname as `Ok(Some(pubname))`. Returns
    /// `Ok(None)` when iteration is complete and all pubnames have already been
    /// parsed and yielded. If an error occurs while parsing the next pubname,
    /// then this error is returned as `Err(e)`, and all subsequent calls return
    /// `Ok(None)`.
    pub fn next(&mut self) -> Result<Option<PubNamesEntry<R>>> {
        self.0.next().map(|x| x.map(PubNamesEntry))
    }
}

#[cfg(feature = "fallible-iterator")]
impl<R: Reader> fallible_iterator::FallibleIterator for PubNamesEntryIter<R> {
    type Item = PubNamesEntry<R>;
    type Error = crate::read::Error;

    fn next(&mut self) -> ::core::result::Result<Option<Self::Item>, Self::Error> {
        self.next()
    }
}

impl<R: Reader> Iterator for PubNamesEntryIter<R> {
    type Item = Result<PubNamesEntry<R>>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next().transpose()
    }
}
