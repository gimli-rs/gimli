//! Functions for parsing DWARF 5 `.debug_names` sections.
//!
//! The `.debug_names` section provides an accelerated access table for debugging
//! information entries (DIEs) organized by name. This section is defined in
//! DWARF 5 Section 6.1.1 and enables efficient lookup of symbols without
//! scanning the entire `.debug_info` section.
//!
//! # DWARF 5 Name Index
//!
//! A name index in the `.debug_names` section contains:
//! - **Header**: Format, version, and table counts
//! - **CU/TU Lists**: Lists of compilation and type units
//! - **Hash Table**: Bucket-based hash table for name lookup
//! - **Name Table**: String and entry offsets for each name
//! - **Abbreviation Table**: Describes entry structure and attributes
//! - **Entry Pool**: Series of entries with abbreviation codes and attributes
//!
//! Per DWARF 5 Section 6.1.1.3, a `.debug_names` section can contain multiple
//! name indexes. There are two strategies:
//! - **Per-module index**: Single index covering all compilation units (most common)
//! - **Per-CU indexes**: Separate indexes for individual compilation units
//!
//! The choice depends on the compiler/linker. When looking up names, all indexes
//! must be searched since a name could appear in any index.
//!
use crate::common::{
    DebugInfoOffset, DebugNamesOffset, DebugStrOffset, DebugTypeSignature, Format, SectionId,
};
use crate::constants;
use crate::endianity::Endianity;
use crate::read::{
    DebugStr, EndianSlice, Error, Reader, ReaderOffset, Result, Section, UnitOffset,
};
use alloc::vec::Vec;

/// The `DebugNames` struct represents the DWARF 5 name index information
/// found in the `.debug_names` section.
///
/// The `.debug_names` section provides an index for efficiently finding
/// debugging information entries (DIEs) by name. It contains hash tables
/// that map names to DIE offsets, allowing debuggers to quickly locate
/// functions, variables, types, and other named entities.
#[derive(Debug, Default, Clone, Copy)]
pub struct DebugNames<R> {
    section: R,
}

impl<'input, Endian> DebugNames<EndianSlice<'input, Endian>>
where
    Endian: Endianity,
{
    /// Construct a new `DebugNames` instance from the data in the `.debug_names`
    /// section.
    ///
    /// It is the caller's responsibility to read the `.debug_names` section and
    /// present it as a `&[u8]` slice. That means using some ELF loader on
    /// Linux, a Mach-O loader on macOS, etc.
    ///
    /// ```
    /// use gimli::{DebugNames, LittleEndian};
    ///
    /// # let buf = [0x00, 0x01, 0x02, 0x03];
    /// # let read_debug_names_section_somehow = || &buf;
    /// let debug_names =
    ///     DebugNames::new(read_debug_names_section_somehow(), LittleEndian);
    /// ```
    pub fn new(debug_names_section: &'input [u8], endian: Endian) -> Self {
        Self::from(EndianSlice::new(debug_names_section, endian))
    }
}

impl<T> DebugNames<T> {
    /// Create a `DebugNames` section that references the data in `self`.
    ///
    /// This is useful when `R` implements `Reader` but `T` does not.
    ///
    /// Used by `DwarfSections::borrow`.
    pub fn borrow<'a, F, R>(&'a self, mut borrow: F) -> DebugNames<R>
    where
        F: FnMut(&'a T) -> R,
    {
        borrow(&self.section).into()
    }
}

impl<R: Reader> DebugNames<R> {
    /// Iterate over all name indexes in the `.debug_names` section.
    pub fn headers(&self) -> NameIndexHeaderIter<R> {
        NameIndexHeaderIter {
            input: self.section.clone(),
            end_offset: self.section.len(),
        }
    }
}

impl<R> Section<R> for DebugNames<R> {
    fn id() -> SectionId {
        SectionId::DebugNames
    }

    fn reader(&self) -> &R {
        &self.section
    }
}

impl<R> From<R> for DebugNames<R> {
    fn from(debug_names_section: R) -> Self {
        DebugNames {
            section: debug_names_section,
        }
    }
}

/// An iterator over the name index headers in the `.debug_names` section.
#[derive(Debug, Clone)]
pub struct NameIndexHeaderIter<R: Reader> {
    input: R,
    end_offset: R::Offset,
}

impl<R: Reader> NameIndexHeaderIter<R> {
    /// Advance the iterator and return the next name index header.
    ///
    /// Returns `Ok(None)` when iteration is complete.
    pub fn next(&mut self) -> Result<Option<NameIndexHeader<R>>> {
        if self.input.is_empty() {
            return Ok(None);
        }

        let offset = DebugNamesOffset(self.end_offset - self.input.len());
        let result = NameIndexHeader::parse(&mut self.input, offset).map(Some);
        if result.is_err() {
            self.input.empty();
        }
        result
    }
}

impl<R: Reader> Iterator for NameIndexHeaderIter<R> {
    type Item = Result<NameIndexHeader<R>>;

    fn next(&mut self) -> Option<Self::Item> {
        NameIndexHeaderIter::next(self).transpose()
    }
}

/// The header of a name index in the `.debug_names` section.
#[derive(Debug, Clone)]
pub struct NameIndexHeader<R: Reader> {
    /// The section offset of the header.
    offset: DebugNamesOffset<R::Offset>,
    /// The length of this name index.
    length: R::Offset,
    /// The format of the unit.
    format: Format,
    /// Version of the name index format (should be 5 for DWARF 5).
    version: u16,
    /// Number of compilation units in the CU list.
    compile_unit_count: u32,
    /// Number of type units in the local TU list.
    local_type_unit_count: u32,
    /// Number of type units in the foreign TU list.
    foreign_type_unit_count: u32,
    /// Number of buckets in the hash table.
    bucket_count: u32,
    /// Number of unique name entries.
    name_count: u32,
    /// Size of the abbreviations table in bytes.
    abbrev_table_size: u32,
    /// The augmentation string.
    augmentation_string: Option<R>,
    /// The remaining unparsed contents of the index.
    content: R,
}

impl<R: Reader> NameIndexHeader<R> {
    /// Convert the header into a `NameIndex`.
    pub fn index(self) -> Result<NameIndex<R>> {
        NameIndex::new(self)
    }

    /// Return the section offset of this name index.
    #[inline]
    pub fn offset(&self) -> DebugNamesOffset<R::Offset> {
        self.offset
    }

    /// Return the version of this name index.
    #[inline]
    pub fn version(&self) -> u16 {
        self.version
    }

    /// Return the number of compilation units in this index.
    #[inline]
    pub fn compile_unit_count(&self) -> u32 {
        self.compile_unit_count
    }

    /// Return the number of local type units in this index.
    #[inline]
    pub fn local_type_unit_count(&self) -> u32 {
        self.local_type_unit_count
    }

    /// Return the number of foreign type units in this index.
    #[inline]
    pub fn foreign_type_unit_count(&self) -> u32 {
        self.foreign_type_unit_count
    }

    /// Return the number of buckets in the hash table.
    #[inline]
    pub fn bucket_count(&self) -> u32 {
        self.bucket_count
    }

    /// Return the number of unique name entries.
    #[inline]
    pub fn name_count(&self) -> u32 {
        self.name_count
    }

    /// Return the size of the abbreviations table in bytes.
    #[inline]
    pub fn abbrev_table_size(&self) -> u32 {
        self.abbrev_table_size
    }

    /// Return the augmentation string.
    #[inline]
    pub fn augmentation_string(&self) -> Option<&R> {
        self.augmentation_string.as_ref()
    }

    /// Return the index length.
    #[inline]
    pub fn length(&self) -> R::Offset {
        self.length
    }

    /// Return the format (DWARF32 or DWARF64).
    #[inline]
    pub fn format(&self) -> Format {
        self.format
    }

    fn parse(input: &mut R, offset: DebugNamesOffset<R::Offset>) -> Result<Self> {
        let (length, format) = input.read_initial_length()?;
        let mut input = input.split(length)?;

        let version = input.read_u16()?;

        if version != 5 {
            return Err(Error::UnknownVersion(version as u64));
        }

        input.skip(R::Offset::from_u8(2))?; // Padding
        let compile_unit_count = input.read_u32()?;
        let local_type_unit_count = input.read_u32()?;
        let foreign_type_unit_count = input.read_u32()?;
        let bucket_count = input.read_u32()?;
        let name_count = input.read_u32()?;
        let abbrev_table_size = input.read_u32()?;
        let augmentation_string_size = input.read_u32()?;

        let augmentation_string = if augmentation_string_size > 0 {
            Some(input.split(R::Offset::from_u64(augmentation_string_size as u64)?)?)
        } else {
            None
        };
        if augmentation_string_size & 3 != 0 {
            input.skip(R::Offset::from_u32(4 - (augmentation_string_size & 3)))?;
        }

        Ok(NameIndexHeader {
            offset,
            length,
            format,
            version,
            compile_unit_count,
            local_type_unit_count,
            foreign_type_unit_count,
            bucket_count,
            name_count,
            abbrev_table_size,
            augmentation_string,
            content: input,
        })
    }
}

/// An index into the name table of a `NameIndex`.
///
/// This is used as an index into the list of string offsets, the list of entry
/// offsets, and the list of hashes.
///
/// Note that while the DWARF standard specifies that indexes in the DWARF data
/// start at 1, we use a zero based index here. Functions that read an index from
/// the data will automatically adjust the index to start at 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NameTableIndex(pub u32);

/// A reference to a type unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameTypeUnit<T> {
    /// The offset of a local type unit in the `.debug_info` section.
    Local(DebugInfoOffset<T>),
    /// The type signature of a foreign type unit.
    Foreign(DebugTypeSignature),
}

/// A single name index from the `.debug_names` section.
///
/// It provides access to the compilation unit table, type unit tables, hash table, name
/// table, and entry pool that make up the accelerated lookup structure.
#[derive(Debug)]
pub struct NameIndex<R: Reader> {
    format: Format,
    comp_unit_count: u32,
    local_type_unit_count: u32,
    foreign_type_unit_count: u32,
    bucket_count: u32,
    name_count: u32,

    // Pre-sliced readers for each section
    compile_unit_list: R,
    local_type_unit_list: R,
    foreign_type_unit_list: R,
    bucket_data: R,
    hash_table_data: R,
    name_table_data: R,
    entry_offset_data: R,
    entry_pool: R,

    abbreviations: NameAbbreviations,
}

impl<R: Reader> NameIndex<R> {
    /// Create a new name index from a header.
    pub fn new(header: NameIndexHeader<R>) -> Result<Self> {
        let mut reader = header.content;

        // Calculate section sizes once
        let offset_size = header.format.word_size() as u64;

        let cu_list_size = header.compile_unit_count as u64 * offset_size;
        let local_tu_size = header.local_type_unit_count as u64 * offset_size;
        let foreign_tu_size = header.foreign_type_unit_count as u64 * 8; // Always 8 bytes per signature
        let buckets_size = header.bucket_count as u64 * 4;
        let hash_table_size = if header.bucket_count == 0 {
            0
        } else {
            header.name_count as u64 * 4
        };
        let name_table_size = header.name_count as u64 * offset_size;
        let abbrev_size = header.abbrev_table_size as u64;

        // Slice each section once (split() advances the reader automatically)
        let compile_unit_list = reader.split(R::Offset::from_u64(cu_list_size)?)?;
        let local_type_unit_list = reader.split(R::Offset::from_u64(local_tu_size)?)?;
        let foreign_type_unit_list = reader.split(R::Offset::from_u64(foreign_tu_size)?)?;
        let bucket_data = reader.split(R::Offset::from_u64(buckets_size)?)?;
        let hash_table_data = reader.split(R::Offset::from_u64(hash_table_size)?)?;
        let name_table_data = reader.split(R::Offset::from_u64(name_table_size)?)?;
        let entry_offset_data = reader.split(R::Offset::from_u64(name_table_size)?)?;
        let abbreviation_table = reader.split(R::Offset::from_u64(abbrev_size)?)?;

        let abbreviations = NameAbbreviations::parse(abbreviation_table)?;

        // Remaining data is the entry pool
        let entry_pool = reader;

        Ok(NameIndex {
            format: header.format,
            comp_unit_count: header.compile_unit_count,
            local_type_unit_count: header.local_type_unit_count,
            foreign_type_unit_count: header.foreign_type_unit_count,
            bucket_count: header.bucket_count,
            name_count: header.name_count,
            compile_unit_list,
            local_type_unit_list,
            foreign_type_unit_list,
            bucket_data,
            hash_table_data,
            name_table_data,
            entry_offset_data,
            entry_pool,
            abbreviations,
        })
    }

    /// Return the number of compilation units in this index.
    pub fn compile_unit_count(&self) -> u32 {
        self.comp_unit_count
    }

    /// Get the `.debug_info` offset of a compilation unit.
    ///
    /// `index` must be less than [`Self::comp_unit_count`].
    pub fn compile_unit_offset(&self, index: u32) -> Result<DebugInfoOffset<R::Offset>> {
        let mut reader = self.compile_unit_list.clone();
        reader.skip(R::Offset::from_u64(
            u64::from(index) * u64::from(self.format.word_size()),
        )?)?;
        reader.read_offset(self.format).map(DebugInfoOffset)
    }

    /// Return the `.debug_info` offset of the default compilation unit, if any.
    ///
    /// If there is only one compilation unit, then entries may omit the `DW_IDX_compile_unit`
    /// attribute.
    pub fn default_compile_unit(&self) -> Result<Option<DebugInfoOffset<R::Offset>>> {
        if self.comp_unit_count == 1 {
            self.compile_unit_offset(0).map(Some)
        } else {
            Ok(None)
        }
    }

    /// Return the number of local type units in this index.
    pub fn local_type_unit_count(&self) -> u32 {
        self.local_type_unit_count
    }

    /// Get the `.debug_info` offset of a local type unit.
    ///
    /// `index` must be less than [`Self::local_type_unit_count`].
    pub fn local_type_unit_offset(&self, index: u32) -> Result<DebugInfoOffset<R::Offset>> {
        let mut reader = self.local_type_unit_list.clone();
        reader.skip(R::Offset::from_u64(
            u64::from(index) * u64::from(self.format.word_size()),
        )?)?;
        reader.read_offset(self.format).map(DebugInfoOffset)
    }

    /// Return the number of foreign type units in this index.
    pub fn foreign_type_unit_count(&self) -> u32 {
        self.foreign_type_unit_count
    }

    /// Get the signature of a foreign type unit.
    ///
    /// `index` must be less than [`Self::foreign_type_unit_count`].
    pub fn foreign_type_unit_signature(&self, index: u32) -> Result<DebugTypeSignature> {
        let mut reader = self.foreign_type_unit_list.clone();
        reader.skip(R::Offset::from_u64(u64::from(index) * 8)?)?;
        reader.read_u64().map(DebugTypeSignature)
    }

    /// Return the number of type units in this index, both local and foreign
    pub fn type_unit_count(&self) -> u32 {
        self.local_type_unit_count + self.foreign_type_unit_count
    }

    /// Get a type unit reference.
    ///
    /// `index` must be less than [`Self::type_unit_count`], and normally is
    /// obtained from a `DW_IDX_type_unit` attribute.
    pub fn type_unit(&self, index: u32) -> Result<NameTypeUnit<R::Offset>> {
        if let Some(foreign_index) = index.checked_sub(self.local_type_unit_count) {
            self.foreign_type_unit_signature(foreign_index)
                .map(NameTypeUnit::Foreign)
        } else {
            self.local_type_unit_offset(index).map(NameTypeUnit::Local)
        }
    }

    /// Return the number of buckets in the hash table.
    pub fn bucket_count(&self) -> u32 {
        self.bucket_count
    }

    /// Iterate over the hash entries for a bucket in the hash table.
    ///
    /// This function is only for diagnostic uses. Usually [`Self::find_by_hash`] should be
    /// called instead.
    ///
    /// The given bucket index is 0 based, and must be less than [`Self::bucket_count`].
    ///
    /// Returns an error if there is no hash table.
    /// Returns `Ok(None)` if the bucket is empty.
    pub fn find_by_bucket(&self, bucket_index: u32) -> Result<Option<NameBucketIter<R>>> {
        NameBucketIter::new(self, bucket_index)
    }

    /// Iterate over the indexes of the names with the given hash value.
    ///
    /// The user must then check each name to see if it matches the desired name.
    ///
    /// Returns an error if there is no hash table.
    pub fn find_by_hash(&self, hash_value: u32) -> Result<NameHashIter<R>> {
        NameHashIter::new(self, hash_value)
    }

    /// Get the number of names in the name index.
    ///
    /// This is 1 greater than the maximum valid [`NameTableIndex`].
    pub fn name_count(&self) -> u32 {
        self.name_count
    }

    /// Iterate over the indexes of all names in the name table.
    pub fn names(&self) -> NameTableIter {
        NameTableIter::new(self)
    }

    /// Get the string table offset for the name at the given index.
    pub fn name_string_offset(&self, index: NameTableIndex) -> Result<DebugStrOffset<R::Offset>> {
        let mut reader = self.name_table_data.clone();
        reader.skip(R::Offset::from_u32(
            index.0 * u32::from(self.format.word_size()),
        ))?;
        reader.read_offset(self.format).map(DebugStrOffset)
    }

    /// Get the name at the given index using the provided `.debug_str` section.
    pub fn name_string(&self, index: NameTableIndex, debug_str: &DebugStr<R>) -> Result<R> {
        let offset = self.name_string_offset(index)?;
        debug_str.get_str(offset)
    }

    /// Iterate over the series of entries for the given name table index.
    ///
    /// Each name in the name table has a corresponding series of entries
    /// with that name in the entry pool.
    pub fn name_entries(&self, index: NameTableIndex) -> Result<NameEntryIter<'_, R>> {
        NameEntryIter::new(self, index)
    }

    /// Get the abbreviation table for name entries in this name index.
    pub fn abbreviations(&self) -> &NameAbbreviations {
        &self.abbreviations
    }
}

/// An iterator over the indexes of all names in a name index.
#[derive(Debug)]
pub struct NameTableIter {
    name_table_index: NameTableIndex,
    name_count: u32,
}

impl NameTableIter {
    fn new<R: Reader>(name_index: &NameIndex<R>) -> Self {
        NameTableIter {
            name_table_index: NameTableIndex(0),
            name_count: name_index.name_count,
        }
    }
}

impl Iterator for NameTableIter {
    type Item = NameTableIndex;

    fn next(&mut self) -> Option<Self::Item> {
        let name_table_index = self.name_table_index;
        if name_table_index.0 >= self.name_count {
            return None;
        }
        self.name_table_index.0 += 1;
        Some(name_table_index)
    }
}

/// An iterator over the hash entries for a bucket in a name index hash table.
#[derive(Debug)]
pub struct NameBucketIter<R: Reader> {
    reader: R,
    name_table_index: NameTableIndex,
    name_count: u32,
    bucket_index: u32,
    bucket_count: u32,
}

impl<R: Reader> NameBucketIter<R> {
    fn new(name_index: &NameIndex<R>, bucket_index: u32) -> Result<Option<Self>> {
        let mut bucket_reader = name_index.bucket_data.clone();
        bucket_reader.skip(R::Offset::from_u64(u64::from(bucket_index) * 4)?)?;
        let start = bucket_reader.read_u32()?;
        if start == 0 {
            return Ok(None);
        }
        let name_table_index = NameTableIndex(start - 1);

        let mut reader = name_index.hash_table_data.clone();
        reader.skip(R::Offset::from_u64(u64::from(name_table_index.0) * 4)?)?;

        Ok(Some(NameBucketIter {
            reader,
            name_table_index,
            name_count: name_index.name_count,
            bucket_index,
            bucket_count: name_index.bucket_count,
        }))
    }

    /// Advance the iterator and return the next name table index and hash.
    pub fn next(&mut self) -> Result<Option<(NameTableIndex, u32)>> {
        let name_table_index = self.name_table_index;
        if name_table_index.0 >= self.name_count {
            return Ok(None);
        }
        let hash = self.reader.read_u32()?;
        self.name_table_index.0 += 1;
        if hash % self.bucket_count != self.bucket_index {
            return Ok(None);
        }
        Ok(Some((name_table_index, hash)))
    }
}

#[cfg(feature = "fallible-iterator")]
impl<R: Reader> fallible_iterator::FallibleIterator for NameBucketIter<R> {
    type Item = (NameTableIndex, u32);
    type Error = Error;

    fn next(&mut self) -> ::core::result::Result<Option<Self::Item>, Self::Error> {
        NameBucketIter::next(self)
    }
}

impl<R: Reader> Iterator for NameBucketIter<R> {
    type Item = Result<(NameTableIndex, u32)>;

    fn next(&mut self) -> Option<Self::Item> {
        NameBucketIter::next(self).transpose()
    }
}

/// An iterator over the indexes of the names in a name index hash table that match a hash
/// value.
#[derive(Debug)]
pub struct NameHashIter<R: Reader> {
    bucket_iter: Option<NameBucketIter<R>>,
    hash: u32,
}

impl<R: Reader> NameHashIter<R> {
    fn new(name_index: &NameIndex<R>, hash: u32) -> Result<Self> {
        let bucket_index = if name_index.bucket_count == 0 {
            0
        } else {
            hash % name_index.bucket_count
        };
        let bucket_iter = NameBucketIter::new(name_index, bucket_index)?;

        Ok(NameHashIter { bucket_iter, hash })
    }

    /// Advance the iterator and return the next name table index.
    pub fn next(&mut self) -> Result<Option<NameTableIndex>> {
        let Some(bucket_iter) = &mut self.bucket_iter else {
            return Ok(None);
        };
        while let Some((name_table_index, hash)) = bucket_iter.next()? {
            if hash == self.hash {
                return Ok(Some(name_table_index));
            }
        }
        Ok(None)
    }
}

#[cfg(feature = "fallible-iterator")]
impl<R: Reader> fallible_iterator::FallibleIterator for NameHashIter<R> {
    type Item = NameTableIndex;
    type Error = Error;

    fn next(&mut self) -> ::core::result::Result<Option<Self::Item>, Self::Error> {
        NameHashIter::next(self)
    }
}

impl<R: Reader> Iterator for NameHashIter<R> {
    type Item = Result<NameTableIndex>;

    fn next(&mut self) -> Option<Self::Item> {
        NameHashIter::next(self).transpose()
    }
}

/// An iterator for a series of name entries in a name index entry pool.
///
/// Each name in a name index corresponds to a series of entries
/// with that name.
#[derive(Debug)]
pub struct NameEntryIter<'a, R: Reader> {
    entries: R,
    end_offset: R::Offset,
    abbreviations: &'a NameAbbreviations,
}

impl<'a, R: Reader> NameEntryIter<'a, R> {
    fn new(name_index: &'a NameIndex<R>, index: NameTableIndex) -> Result<Self> {
        let mut offsets = name_index.entry_offset_data.clone();
        offsets.skip(R::Offset::from_u32(
            index.0 * u32::from(name_index.format.word_size()),
        ))?;
        let offset = offsets
            .read_offset(name_index.format)
            .map(NameEntryOffset)?;

        let mut entries = name_index.entry_pool.clone();
        let end_offset = entries.len();
        entries.skip(offset.0)?;
        Ok(NameEntryIter {
            entries,
            end_offset,
            abbreviations: &name_index.abbreviations,
        })
    }

    /// Advance the iterator and return the next name entry.
    pub fn next(&mut self) -> Result<Option<NameEntry<R>>> {
        if self.entries.is_empty() {
            return Ok(None);
        }

        let offset = NameEntryOffset(self.end_offset - self.entries.len());
        match NameEntry::parse(&mut self.entries, offset, self.abbreviations) {
            Ok(Some(entry)) => Ok(Some(entry)),
            Ok(None) => {
                // Series end.
                self.entries.empty();
                Ok(None)
            }
            Err(e) => {
                // On error, prevent further iteration
                self.entries.empty();
                Err(e)
            }
        }
    }
}

#[cfg(feature = "fallible-iterator")]
impl<'a, R: Reader> fallible_iterator::FallibleIterator for NameEntryIter<'a, R> {
    type Item = NameEntry<R>;
    type Error = Error;

    fn next(&mut self) -> ::core::result::Result<Option<Self::Item>, Self::Error> {
        NameEntryIter::next(self)
    }
}

impl<'a, R: Reader> Iterator for NameEntryIter<'a, R> {
    type Item = Result<NameEntry<R>>;

    fn next(&mut self) -> Option<Self::Item> {
        NameEntryIter::next(self).transpose()
    }
}

/// An offset into the entry pool of a name index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct NameEntryOffset<T = usize>(pub T);

/// A parsed entry from the `.debug_names` section.
#[derive(Debug, Clone)]
pub struct NameEntry<R: Reader> {
    /// The offset of the entry in the entries pool.
    pub offset: NameEntryOffset<R::Offset>,

    /// The abbreviation code for this entry.
    pub abbrev_code: u64,

    /// The DIE tag for this entry.
    pub tag: constants::DwTag,

    /// The attributes for this entry.
    pub attrs: Vec<NameAttribute<R>>,
}

impl<R: Reader> NameEntry<R> {
    /// Get the value of the `DW_IDX_compile_unit` attribute, if any.
    ///
    /// Note that if neither `DW_IDX_compile_unit` nor `DW_IDX_type_unit` exist
    /// then you should use [`NameIndex::default_compile_unit`].
    pub fn compile_unit(&self, names: &NameIndex<R>) -> Result<Option<DebugInfoOffset<R::Offset>>> {
        for attr in &self.attrs {
            if attr.name == constants::DW_IDX_compile_unit {
                return attr.compile_unit(names).map(Some);
            }
        }
        Ok(None)
    }

    /// Get the value of the `DW_IDX_type_unit` attribute, if any.
    pub fn type_unit(&self, names: &NameIndex<R>) -> Result<Option<NameTypeUnit<R::Offset>>> {
        for attr in &self.attrs {
            if attr.name == constants::DW_IDX_type_unit {
                return attr.type_unit(names).map(Some);
            }
        }
        Ok(None)
    }

    /// Get the value of the `DW_IDX_die_offset` attribute, if any.
    pub fn die_offset(&self) -> Result<Option<UnitOffset<R::Offset>>> {
        for attr in &self.attrs {
            if attr.name == constants::DW_IDX_die_offset {
                return attr.die_offset().map(Some);
            }
        }
        Ok(None)
    }

    /// Get the value of the `DW_IDX_parent` attribute, if any.
    ///
    /// Returns `Ok(Some(Some(offset)))` if the DIE has a parent and it is indexed.
    /// Returns `Ok(Some(None))` if the DIE has a parent and it is not indexed.
    pub fn parent(&self) -> Result<Option<Option<NameTableIndex>>> {
        for attr in &self.attrs {
            if attr.name == constants::DW_IDX_parent {
                return attr.parent().map(Some);
            }
        }
        Ok(None)
    }

    /// Get the value of the `DW_IDX_type_hash` attribute, if any.
    pub fn type_hash(&self) -> Result<Option<u64>> {
        for attr in &self.attrs {
            if attr.name == constants::DW_IDX_type_hash {
                return attr.type_hash().map(Some);
            }
        }
        Ok(None)
    }

    /// Parse a single entry from the entry pool.
    fn parse(
        entry_reader: &mut R,
        offset: NameEntryOffset<R::Offset>,
        abbreviations: &NameAbbreviations,
    ) -> Result<Option<NameEntry<R>>> {
        let abbrev_code = entry_reader.read_uleb128()?;
        if abbrev_code == 0 {
            return Ok(None);
        }
        let Some(abbrev) = abbreviations.get(abbrev_code) else {
            return Err(Error::UnknownAbbreviation(abbrev_code));
        };
        let tag = abbrev.tag();
        let specs = abbrev.attributes();
        let mut attrs = Vec::with_capacity(specs.len());
        for spec in specs {
            let name = spec.name();
            let form = spec.form();
            let value = read_debug_names_form_value(entry_reader, form)?;
            attrs.push(NameAttribute { name, form, value });
        }

        Ok(Some(NameEntry {
            offset,
            abbrev_code,
            tag,
            attrs,
        }))
    }
}

/// A parsed attribute for a [`NameEntry`].
#[derive(Debug, Clone)]
pub struct NameAttribute<R: Reader> {
    name: constants::DwIdx,
    form: constants::DwForm,
    value: NameAttributeValue<R>,
}

impl<R: Reader> NameAttribute<R> {
    /// Get the attribute name.
    pub fn name(&self) -> constants::DwIdx {
        self.name
    }

    /// Get the attribute form.
    pub fn form(&self) -> constants::DwForm {
        self.form
    }

    /// Get the attribute value.
    ///
    /// Interpretation of this value depends on the name and form.
    pub fn value(&self) -> &NameAttributeValue<R> {
        &self.value
    }

    /// Get the value of a `DW_IDX_compile_unit` attribute.
    pub fn compile_unit(&self, names: &NameIndex<R>) -> Result<DebugInfoOffset<R::Offset>> {
        match self.value {
            NameAttributeValue::Unsigned(val) => {
                if let Ok(val) = u32::try_from(val) {
                    names.compile_unit_offset(val)
                } else {
                    Err(Error::InvalidNameAttributeIndex(val))
                }
            }
            _ => Err(Error::UnsupportedAttributeForm),
        }
    }

    /// Get the value of a `DW_IDX_type_unit` attribute.
    pub fn type_unit(&self, names: &NameIndex<R>) -> Result<NameTypeUnit<R::Offset>> {
        match self.value {
            NameAttributeValue::Unsigned(val) => {
                if let Ok(val) = u32::try_from(val) {
                    names.type_unit(val)
                } else {
                    Err(Error::InvalidNameAttributeIndex(val))
                }
            }
            _ => Err(Error::UnsupportedAttributeForm),
        }
    }

    /// Get the value of a `DW_IDX_die_offset` attribute.
    pub fn die_offset(&self) -> Result<UnitOffset<R::Offset>> {
        match self.value {
            NameAttributeValue::Offset(val) => Ok(UnitOffset(val)),
            _ => Err(Error::UnsupportedAttributeForm),
        }
    }

    /// Get the value of a `DW_IDX_parent` attribute.
    ///
    /// Returns `Ok(Some(offset))` if the DIE has a parent and it is indexed.
    /// Returns `Ok(None)` if the DIE has a parent and it is not indexed.
    pub fn parent(&self) -> Result<Option<NameTableIndex>> {
        match self.value {
            NameAttributeValue::Unsigned(val) => {
                if let Ok(val) = u32::try_from(val) {
                    Ok(Some(NameTableIndex(val)))
                } else {
                    Err(Error::InvalidNameAttributeIndex(val))
                }
            }
            NameAttributeValue::Flag(true) => Ok(None),
            _ => Err(Error::UnsupportedAttributeForm),
        }
    }

    /// Get the value of a `DW_IDX_type_hash` attribute.
    pub fn type_hash(&self) -> Result<u64> {
        match self.value {
            NameAttributeValue::Unsigned(val) => Ok(val),
            _ => Err(Error::UnsupportedAttributeForm),
        }
    }
}

/// A parsed attribute value for a [`NameEntry`].
#[derive(Debug, Clone)]
pub enum NameAttributeValue<R: Reader> {
    /// An unsigned integer.
    ///
    /// This can be from the following forms:
    /// `DW_FORM_data1`, `DW_FORM_data2`, `DW_FORM_data4`, `DW_FORM_data8`, `DW_FORM_udata`
    Unsigned(u64),
    /// An offset within a DWARF section or part thereof.
    ///
    /// This can be from the following forms:
    /// `DW_FORM_ref1`, `DW_FORM_ref2`, `DW_FORM_ref4`, `DW_FORM_ref8`, `DW_FORM_ref_udata`
    Offset(R::Offset),
    /// A boolean flag.
    ///
    /// This can be from the following forms:
    /// `DW_FORM_flag`, `DW_FORM_flag_present`
    Flag(bool),
}

/// Read an attribute value.
///
/// This handles the subset of DWARF forms used in `.debug_names` entry pools
/// (DW_IDX_* attributes).
fn read_debug_names_form_value<R: Reader>(
    input: &mut R,
    form: constants::DwForm,
) -> Result<NameAttributeValue<R>> {
    Ok(match form {
        constants::DW_FORM_flag => {
            let present = input.read_u8()?;
            NameAttributeValue::Flag(present != 0)
        }
        constants::DW_FORM_flag_present => NameAttributeValue::Flag(true),
        constants::DW_FORM_data1 => {
            let data = input.read_u8()?;
            NameAttributeValue::Unsigned(u64::from(data))
        }
        constants::DW_FORM_data2 => {
            let data = input.read_u16()?;
            NameAttributeValue::Unsigned(u64::from(data))
        }
        constants::DW_FORM_data4 => {
            let data = input.read_u32()?;
            NameAttributeValue::Unsigned(u64::from(data))
        }
        constants::DW_FORM_data8 => {
            let data = input.read_u64()?;
            NameAttributeValue::Unsigned(data)
        }
        constants::DW_FORM_udata => {
            let data = input.read_uleb128()?;
            NameAttributeValue::Unsigned(data)
        }
        constants::DW_FORM_ref1 => {
            let reference = input.read_u8().map(R::Offset::from_u8)?;
            NameAttributeValue::Offset(reference)
        }
        constants::DW_FORM_ref2 => {
            let reference = input.read_u16().map(R::Offset::from_u16)?;
            NameAttributeValue::Offset(reference)
        }
        constants::DW_FORM_ref4 => {
            let reference = input.read_u32().map(R::Offset::from_u32)?;
            NameAttributeValue::Offset(reference)
        }
        constants::DW_FORM_ref8 => {
            let reference = input.read_u64().and_then(R::Offset::from_u64)?;
            NameAttributeValue::Offset(reference)
        }
        constants::DW_FORM_ref_udata => {
            let reference = input.read_uleb128().and_then(R::Offset::from_u64)?;
            NameAttributeValue::Offset(reference)
        }
        form => return Err(Error::UnknownForm(form)),
    })
}

/// A table of name entry abbreviations.
#[derive(Debug, Default, Clone)]
pub struct NameAbbreviations {
    /// The abbreviations in this table.
    abbreviations: Vec<NameAbbreviation>,
}

impl NameAbbreviations {
    /// Create a new empty abbreviation table.
    pub fn new() -> Self {
        NameAbbreviations {
            abbreviations: Vec::new(),
        }
    }

    /// Get an abbreviation by its code.
    pub fn get(&self, code: u64) -> Option<&NameAbbreviation> {
        self.abbreviations.iter().find(|abbrev| abbrev.code == code)
    }

    /// Get all abbreviations.
    pub fn abbreviations(&self) -> &[NameAbbreviation] {
        &self.abbreviations
    }

    /// Parse the abbreviation table from a reader.
    fn parse<R: Reader>(mut reader: R) -> Result<NameAbbreviations> {
        let mut abbreviations = Vec::new();

        // Allow missing null terminator.
        while !reader.is_empty() {
            let code = reader.read_uleb128()?;
            if code == 0 {
                break; // End of abbreviation table
            }

            let tag = reader.read_uleb128_u16()?;
            if tag == 0 {
                return Err(Error::AbbreviationTagZero);
            }
            let tag = constants::DwTag(tag);

            let mut attributes = Vec::new();
            loop {
                let name = reader.read_uleb128_u16()?;
                let form = reader.read_uleb128_u16()?;
                match (name, form) {
                    (0, 0) => break,
                    (0, _) => return Err(Error::AttributeNameZero),
                    (_, 0) => return Err(Error::AttributeFormZero),
                    (_, _) => {}
                }
                attributes.push(NameAbbreviationAttribute {
                    name: constants::DwIdx(name),
                    form: constants::DwForm(form),
                });
            }

            abbreviations.push(NameAbbreviation {
                code,
                tag,
                attributes,
            });
        }

        Ok(NameAbbreviations { abbreviations })
    }
}

/// A name abbreviation entry defines how name entries are encoded.
#[derive(Debug, Clone)]
pub struct NameAbbreviation {
    /// The abbreviation code.
    code: u64,
    /// The DIE tag.
    tag: constants::DwTag,
    /// The list of attribute specifications.
    attributes: Vec<NameAbbreviationAttribute>,
}

impl NameAbbreviation {
    /// Get the abbreviation code.
    pub fn code(&self) -> u64 {
        self.code
    }

    /// Get the DIE tag.
    pub fn tag(&self) -> constants::DwTag {
        self.tag
    }

    /// Get the attribute specifications.
    pub fn attributes(&self) -> &[NameAbbreviationAttribute] {
        &self.attributes
    }
}

/// An attribute specification in a name abbreviation.
#[derive(Debug, Clone)]
pub struct NameAbbreviationAttribute {
    /// The attribute name (index type).
    name: constants::DwIdx,
    /// The attribute form.
    form: constants::DwForm,
}

impl NameAbbreviationAttribute {
    /// Get the attribute name (index type).
    pub fn name(&self) -> constants::DwIdx {
        self.name
    }

    /// Get the attribute form.
    pub fn form(&self) -> constants::DwForm {
        self.form
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants;
    use crate::endianity::LittleEndian;
    use crate::read::Section as _;
    use crate::test_util::GimliSectionMethods;
    use alloc::vec::Vec;
    use test_assembler::{Endian, Label, LabelMaker, Section};

    /// Debug names section builder methods for testing
    pub trait DebugNamesSectionMethods {
        fn debug_names_header(
            self,
            format: Format,
            length: &Label,
            start: &Label,
            version: u16,
            cu_count: u32,
            local_tu_count: u32,
            foreign_tu_count: u32,
            bucket_count: u32,
            name_count: u32,
            abbrev_table_size: u32,
            augmentation: &str,
        ) -> Self;
        fn debug_names_end(self, end: &Label) -> Self;
        fn debug_names_cu_offset(self, offset: u32) -> Self;
        fn debug_names_hash_bucket(self, value: u32) -> Self;
        fn debug_names_hash(self, hash: u32) -> Self;
        fn debug_names_string_offset(self, offset: u32) -> Self;
        fn debug_names_entry_offset(self, offset: u32) -> Self;
        fn debug_names_abbrev(
            self,
            code: u64,
            tag: constants::DwTag,
            idx_attrs: &[(constants::DwIdx, constants::DwForm)],
        ) -> Self;
        fn debug_names_abbrev_null(self) -> Self;
        fn debug_names_entry(self, abbrev_code: u64, data: &[u8]) -> Self;
    }

    impl DebugNamesSectionMethods for Section {
        fn debug_names_header(
            self,
            format: Format,
            length: &Label,
            start: &Label,
            version: u16,
            cu_count: u32,
            local_tu_count: u32,
            foreign_tu_count: u32,
            bucket_count: u32,
            name_count: u32,
            abbrev_table_size: u32,
            augmentation: &str,
        ) -> Self {
            // Write placeholder length and mark start position.
            // Caller should call debug_names_end() after all content and then
            // set length using: length.set_const((&end - &start) as u64);
            let section = match format {
                Format::Dwarf32 => self.D32(length).mark(start),
                Format::Dwarf64 => self.D32(0xffffffff).D64(length).mark(start),
            };
            section
                .D16(version)
                .D16(0) // Padding
                .D32(cu_count)
                .D32(local_tu_count)
                .D32(foreign_tu_count)
                .D32(bucket_count)
                .D32(name_count)
                .D32(abbrev_table_size)
                .D32(augmentation.len() as u32)
                .append_bytes(augmentation.as_bytes())
        }

        fn debug_names_end(self, end: &Label) -> Self {
            self.mark(end)
        }

        fn debug_names_cu_offset(self, offset: u32) -> Self {
            self.D32(offset)
        }

        fn debug_names_hash_bucket(self, value: u32) -> Self {
            self.D32(value)
        }

        fn debug_names_hash(self, hash: u32) -> Self {
            self.D32(hash)
        }

        fn debug_names_string_offset(self, offset: u32) -> Self {
            self.D32(offset)
        }

        fn debug_names_entry_offset(self, offset: u32) -> Self {
            self.D32(offset)
        }

        fn debug_names_abbrev(
            self,
            code: u64,
            tag: constants::DwTag,
            idx_attrs: &[(constants::DwIdx, constants::DwForm)],
        ) -> Self {
            let mut section = self.uleb(code).uleb(tag.0.into());
            for &(idx, form) in idx_attrs {
                section = section.uleb(idx.0.into()).uleb(form.0.into());
            }
            section.D8(0).D8(0) // Null terminator
        }

        fn debug_names_abbrev_null(self) -> Self {
            self.D8(0)
        }

        fn debug_names_entry(self, abbrev_code: u64, data: &[u8]) -> Self {
            self.uleb(abbrev_code).append_bytes(data)
        }
    }

    #[test]
    fn test_debug_names_empty_section() {
        let section = &[];
        let debug_names = DebugNames::new(section, LittleEndian);
        let mut headers = debug_names.headers();
        assert!(headers.next().unwrap().is_none());
    }

    #[test]
    fn test_debug_names_invalid_version() {
        // Create a minimal header with invalid version
        let mut section = Vec::new();
        // Length (4 bytes, little endian): minimal header size
        section.extend_from_slice(&[24u8, 0, 0, 0]);
        // Version (2 bytes): invalid version 4
        section.extend_from_slice(&[4u8, 0]);
        // Padding (2 bytes)
        section.extend_from_slice(&[0u8, 0]);
        // Remaining fields (all zeros for minimal test)
        section.extend_from_slice(&[0u8; 20]);

        let debug_names = DebugNames::new(&section, LittleEndian);
        let result = NameIndexHeader::parse(&mut debug_names.reader().clone(), DebugNamesOffset(0));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::UnknownVersion(4));
    }

    #[test]
    fn test_debug_names_valid_header() {
        // Create a minimal valid DWARF 5 header
        let mut section = Vec::new();
        // Length (4 bytes, little endian): full header size
        section.extend_from_slice(&[32u8, 0, 0, 0]);
        // Version (2 bytes): DWARF 5
        section.extend_from_slice(&[5u8, 0]);
        // Padding (2 bytes)
        section.extend_from_slice(&[0u8, 0]);
        // CU count (4 bytes)
        section.extend_from_slice(&[1u8, 0, 0, 0]);
        // Local TU count (4 bytes)
        section.extend_from_slice(&[0u8, 0, 0, 0]);
        // Foreign TU count (4 bytes)
        section.extend_from_slice(&[0u8, 0, 0, 0]);
        // Bucket count (4 bytes)
        section.extend_from_slice(&[1u8, 0, 0, 0]);
        // Name count (4 bytes)
        section.extend_from_slice(&[1u8, 0, 0, 0]);
        // Abbrev table size (4 bytes)
        section.extend_from_slice(&[0u8, 0, 0, 0]);
        // Augmentation string size (4 bytes)
        section.extend_from_slice(&[0u8, 0, 0, 0]);

        let debug_names = DebugNames::new(&section, LittleEndian);
        let result = NameIndexHeader::parse(&mut debug_names.reader().clone(), DebugNamesOffset(0));
        assert!(result.is_ok());

        let header = result.unwrap();
        assert_eq!(header.version(), 5);
        assert_eq!(header.compile_unit_count(), 1);
        assert_eq!(header.local_type_unit_count(), 0);
        assert_eq!(header.foreign_type_unit_count(), 0);
        assert_eq!(header.bucket_count(), 1);
        assert_eq!(header.name_count(), 1);
    }

    #[test]
    fn test_debug_names_unit_iterator() {
        // Create a minimal valid DWARF 5 header
        let mut section = Vec::new();
        // Length (4 bytes, little endian): header + minimal content
        section.extend_from_slice(&[40u8, 0, 0, 0]);
        // Version (2 bytes): DWARF 5
        section.extend_from_slice(&[5u8, 0]);
        // Padding (2 bytes)
        section.extend_from_slice(&[0u8, 0]);
        // CU count (4 bytes)
        section.extend_from_slice(&[0u8, 0, 0, 0]);
        // Local TU count (4 bytes)
        section.extend_from_slice(&[0u8, 0, 0, 0]);
        // Foreign TU count (4 bytes)
        section.extend_from_slice(&[0u8, 0, 0, 0]);
        // Bucket count (4 bytes)
        section.extend_from_slice(&[0u8, 0, 0, 0]);
        // Name count (4 bytes)
        section.extend_from_slice(&[0u8, 0, 0, 0]);
        // Abbrev table size (4 bytes)
        section.extend_from_slice(&[0u8, 0, 0, 0]);
        // Augmentation string size (4 bytes)
        section.extend_from_slice(&[0u8, 0, 0, 0]);
        // Minimal content (8 bytes to match the length calculation)
        section.extend_from_slice(&[0u8, 0, 0, 0, 0, 0, 0, 0]);

        let debug_names = DebugNames::new(&section, LittleEndian);
        let mut headers = debug_names.headers();

        // Should have one header
        let first_header = headers.next().unwrap();
        assert!(first_header.is_some());

        let header = first_header.unwrap();
        assert_eq!(header.version(), 5);

        // Should be no more headers
        let second_header = headers.next().unwrap();
        assert!(second_header.is_none());
    }

    #[test]
    fn test_debug_names_dwarf32_format() {
        // Test DWARF32 format parsing
        let augmentation = "LLVM0700";
        let mut buf = Vec::new();

        // Length (4 bytes): 32 (header excluding length field) + 8 (augmentation string) = 40
        buf.extend_from_slice(&[40u8, 0, 0, 0]);
        // Version (2 bytes): DWARF 5
        buf.extend_from_slice(&[5u8, 0]);
        // Padding (2 bytes)
        buf.extend_from_slice(&[0u8, 0]);
        // CU count (4 bytes)
        buf.extend_from_slice(&[0u8, 0, 0, 0]);
        // Local TU count (4 bytes)
        buf.extend_from_slice(&[0u8, 0, 0, 0]);
        // Foreign TU count (4 bytes)
        buf.extend_from_slice(&[0u8, 0, 0, 0]);
        // Bucket count (4 bytes)
        buf.extend_from_slice(&[0u8, 0, 0, 0]);
        // Name count (4 bytes)
        buf.extend_from_slice(&[0u8, 0, 0, 0]);
        // Abbrev table size (4 bytes)
        buf.extend_from_slice(&[0u8, 0, 0, 0]);
        // Augmentation string size (4 bytes)
        buf.extend_from_slice(&[augmentation.len() as u8, 0, 0, 0]);
        // Augmentation string
        buf.extend_from_slice(augmentation.as_bytes());

        let debug_names = DebugNames::new(&buf, LittleEndian);
        let mut headers = debug_names.headers();

        if let Ok(Some(header)) = headers.next() {
            assert_eq!(header.version(), 5);
            assert_eq!(header.format(), Format::Dwarf32);
            assert_eq!(header.compile_unit_count(), 0);
            assert_eq!(header.bucket_count(), 0);
            assert_eq!(header.name_count(), 0);
            assert_eq!(header.augmentation_string().unwrap().slice(), b"LLVM0700");
        } else {
            panic!("Expected valid debug_names header");
        }
    }

    #[test]
    fn test_debug_names_dwarf64_format() {
        // Test DWARF64 format parsing
        let augmentation = "";
        let mut buf = Vec::new();

        // DWARF64 initial length: 0xffffffff followed by 8-byte length
        buf.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]);
        // Length (8 bytes): header(32) + CU offsets(4) + hash buckets(8) + hash array(4) + string offsets(4) + entry offsets(4) + abbrev table(1) = 57
        buf.extend_from_slice(&[57u8, 0, 0, 0, 0, 0, 0, 0]);
        // Version (2 bytes): DWARF 5
        buf.extend_from_slice(&[5u8, 0]);
        // Padding (2 bytes)
        buf.extend_from_slice(&[0u8, 0]);
        // CU count (4 bytes)
        buf.extend_from_slice(&[1u8, 0, 0, 0]);
        // Local TU count (4 bytes)
        buf.extend_from_slice(&[0u8, 0, 0, 0]);
        // Foreign TU count (4 bytes)
        buf.extend_from_slice(&[0u8, 0, 0, 0]);
        // Bucket count (4 bytes)
        buf.extend_from_slice(&[2u8, 0, 0, 0]);
        // Name count (4 bytes)
        buf.extend_from_slice(&[1u8, 0, 0, 0]);
        // Abbrev table size (4 bytes)
        buf.extend_from_slice(&[1u8, 0, 0, 0]);
        // Augmentation string size (4 bytes)
        buf.extend_from_slice(&[augmentation.len() as u8, 0, 0, 0]);
        // Augmentation string (empty)

        // Data tables:
        // CU offsets (1 * 4 bytes)
        buf.extend_from_slice(&[0x00, 0x10, 0x00, 0x00]); // CU offset 0x1000
        // Hash buckets (2 * 4 bytes)
        buf.extend_from_slice(&[0u8, 0, 0, 0]); // Bucket 0: empty
        buf.extend_from_slice(&[1u8, 0, 0, 0]); // Bucket 1: points to name 1
        // Hash array (1 * 4 bytes)
        buf.extend_from_slice(&[0x78, 0x56, 0x34, 0x12]); // Hash value
        // String offsets (1 * 4 bytes)
        buf.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]); // String offset 0x100
        // Entry offsets (1 * 4 bytes)
        buf.extend_from_slice(&[0u8, 0, 0, 0]); // Entry offset 0
        // Abbreviation table (1 byte: null terminator)
        buf.extend_from_slice(&[0u8]);

        let debug_names = DebugNames::new(&buf, LittleEndian);
        let mut headers = debug_names.headers();

        if let Ok(Some(header)) = headers.next() {
            assert_eq!(header.version(), 5);
            assert_eq!(header.format(), Format::Dwarf64);
            assert_eq!(header.compile_unit_count(), 1);
            assert_eq!(header.bucket_count(), 2);
            assert_eq!(header.name_count(), 1);
        } else {
            panic!("Expected valid debug_names header");
        }
    }

    #[test]
    fn test_debug_names_error_truncated_header() {
        // Test parsing fails with truncated header
        let mut buf = Vec::new();
        // Length (4 bytes) - claims more data than available
        buf.extend_from_slice(&[100u8, 0, 0, 0]);
        // Version (2 bytes): DWARF 5
        buf.extend_from_slice(&[5u8, 0]);
        // Only provide partial header (missing most fields)
        buf.extend_from_slice(&[0u8, 0]);

        let debug_names = DebugNames::new(&buf, LittleEndian);
        let mut headers = debug_names.headers();

        assert!(headers.next().is_err());
    }

    #[test]
    fn test_debug_names_error_zero_length() {
        // Test parsing fails with zero length
        let mut buf = Vec::new();
        // Length (4 bytes) - zero length
        buf.extend_from_slice(&[0u8, 0, 0, 0]);

        let debug_names = DebugNames::new(&buf, LittleEndian);
        let mut headers = debug_names.headers();

        assert!(headers.next().is_err());
    }

    #[test]
    fn test_debug_names_error_invalid_dwarf64_marker() {
        // Test DWARF64 parsing fails with invalid initial marker
        let mut buf = Vec::new();
        // Invalid DWARF64 marker (should be 0xffffffff)
        buf.extend_from_slice(&[0xfe, 0xff, 0xff, 0xff]);
        // Length (8 bytes)
        buf.extend_from_slice(&[40u8, 0, 0, 0, 0, 0, 0, 0]);
        // Version (2 bytes): DWARF 5
        buf.extend_from_slice(&[5u8, 0]);
        // Rest of header
        buf.extend_from_slice(&[0u8; 30]);

        let debug_names = DebugNames::new(&buf, LittleEndian);
        let mut headers = debug_names.headers();

        // Should parse as DWARF32 with invalid length
        assert!(headers.next().is_err());
    }

    #[test]
    fn test_debug_names_error_length_overflow() {
        // Test parsing fails with length that would cause overflow
        let mut buf = Vec::new();
        // Length (4 bytes) - huge value that would overflow
        buf.extend_from_slice(&[0xff, 0xff, 0xff, 0x7f]);
        // Version (2 bytes): DWARF 5
        buf.extend_from_slice(&[5u8, 0]);
        // Rest of header
        buf.extend_from_slice(&[0u8; 30]);

        let debug_names = DebugNames::new(&buf, LittleEndian);
        let mut headers = debug_names.headers();

        assert!(headers.next().is_err());
    }

    #[test]
    fn test_debug_names_iterator_empty_hash_table() {
        // Test iterator with empty hash table (bucket_count = 0)
        let mut buf = Vec::new();
        // Length (4 bytes): 32 (header) + 4 (CU offsets) = 36
        buf.extend_from_slice(&[36u8, 0, 0, 0]);
        // Version (2 bytes): DWARF 5
        buf.extend_from_slice(&[5u8, 0]);
        // Padding (2 bytes)
        buf.extend_from_slice(&[0u8, 0]);
        // CU count (4 bytes)
        buf.extend_from_slice(&[1u8, 0, 0, 0]);
        // Local TU count (4 bytes)
        buf.extend_from_slice(&[0u8, 0, 0, 0]);
        // Foreign TU count (4 bytes)
        buf.extend_from_slice(&[0u8, 0, 0, 0]);
        // Bucket count (4 bytes) - empty hash table
        buf.extend_from_slice(&[0u8, 0, 0, 0]);
        // Name count (4 bytes)
        buf.extend_from_slice(&[0u8, 0, 0, 0]);
        // Abbrev table size (4 bytes)
        buf.extend_from_slice(&[0u8, 0, 0, 0]);
        // Augmentation string size (4 bytes)
        buf.extend_from_slice(&[0u8, 0, 0, 0]);

        // Data tables:
        // CU offsets (1 * 4 bytes)
        buf.extend_from_slice(&[0x00, 0x10, 0x00, 0x00]);

        let debug_names = DebugNames::new(&buf, LittleEndian);
        if let Ok(Some(header)) = debug_names.headers().next() {
            // Test that we can successfully parse the header with empty hash table
            assert_eq!(header.bucket_count(), 0);
            assert_eq!(header.name_count(), 0);
        } else {
            panic!("Expected valid debug_names header");
        }
    }

    #[test]
    fn test_debug_names_iterator_single_entry() {
        // Test iterator with exactly one entry
        let mut buf = Vec::new();
        // Length: header(32) + CU offsets(4) + hash buckets(4) + hash array(4) + string offsets(4) + entry offsets(4) + abbrev table(2) = 54
        buf.extend_from_slice(&[54u8, 0, 0, 0]);
        // Version (2 bytes): DWARF 5
        buf.extend_from_slice(&[5u8, 0]);
        // Padding (2 bytes)
        buf.extend_from_slice(&[0u8, 0]);
        // CU count (4 bytes)
        buf.extend_from_slice(&[1u8, 0, 0, 0]);
        // Local TU count (4 bytes)
        buf.extend_from_slice(&[0u8, 0, 0, 0]);
        // Foreign TU count (4 bytes)
        buf.extend_from_slice(&[0u8, 0, 0, 0]);
        // Bucket count (4 bytes)
        buf.extend_from_slice(&[1u8, 0, 0, 0]);
        // Name count (4 bytes)
        buf.extend_from_slice(&[1u8, 0, 0, 0]);
        // Abbrev table size (4 bytes)
        buf.extend_from_slice(&[2u8, 0, 0, 0]);
        // Augmentation string size (4 bytes)
        buf.extend_from_slice(&[0u8, 0, 0, 0]);

        // Data tables:
        // CU offsets (1 * 4 bytes)
        buf.extend_from_slice(&[0x00, 0x10, 0x00, 0x00]);
        // Hash buckets (1 * 4 bytes)
        buf.extend_from_slice(&[1u8, 0, 0, 0]); // Points to name 1
        // Hash array (1 * 4 bytes)
        buf.extend_from_slice(&[0x78, 0x56, 0x34, 0x12]);
        // String offsets (1 * 4 bytes)
        buf.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
        // Entry offsets (1 * 4 bytes)
        buf.extend_from_slice(&[0u8, 0, 0, 0]);
        // Abbreviation table (2 bytes: null terminator)
        buf.extend_from_slice(&[0u8, 0u8]);

        let debug_names = DebugNames::new(&buf, LittleEndian);
        if let Ok(Some(header)) = debug_names.headers().next() {
            // Test that we can successfully parse a header with single entry
            assert_eq!(header.bucket_count(), 1);
            assert_eq!(header.name_count(), 1);
            assert_eq!(header.compile_unit_count(), 1);
        } else {
            panic!("Expected valid debug_names header");
        }
    }

    #[test]
    fn test_debug_names_iterator_boundary_buckets() {
        // Test iterator with hash table having maximum valid bucket indices
        let mut buf = Vec::new();
        // Length: header(32) + CU offsets(4) + hash buckets(12) + hash array(12) + string offsets(12) + entry offsets(12) + abbrev table(1) = 85
        buf.extend_from_slice(&[85u8, 0, 0, 0]);
        // Version (2 bytes): DWARF 5
        buf.extend_from_slice(&[5u8, 0]);
        // Padding (2 bytes)
        buf.extend_from_slice(&[0u8, 0]);
        // CU count (4 bytes)
        buf.extend_from_slice(&[1u8, 0, 0, 0]);
        // Local TU count (4 bytes)
        buf.extend_from_slice(&[0u8, 0, 0, 0]);
        // Foreign TU count (4 bytes)
        buf.extend_from_slice(&[0u8, 0, 0, 0]);
        // Bucket count (4 bytes)
        buf.extend_from_slice(&[3u8, 0, 0, 0]);
        // Name count (4 bytes)
        buf.extend_from_slice(&[3u8, 0, 0, 0]);
        // Abbrev table size (4 bytes)
        buf.extend_from_slice(&[1u8, 0, 0, 0]);
        // Augmentation string size (4 bytes)
        buf.extend_from_slice(&[0u8, 0, 0, 0]);

        // Data tables:
        // CU offsets (1 * 4 bytes)
        buf.extend_from_slice(&[0x00, 0x10, 0x00, 0x00]);
        // Hash buckets (3 * 4 bytes) - boundary case: bucket points to last name
        buf.extend_from_slice(&[0u8, 0, 0, 0]); // Bucket 0: empty
        buf.extend_from_slice(&[0u8, 0, 0, 0]); // Bucket 1: empty
        buf.extend_from_slice(&[3u8, 0, 0, 0]); // Bucket 2: points to name 3 (last name)
        // Hash array (3 * 4 bytes)
        buf.extend_from_slice(&[0x11, 0x11, 0x11, 0x11]);
        buf.extend_from_slice(&[0x22, 0x22, 0x22, 0x22]);
        buf.extend_from_slice(&[0x33, 0x33, 0x33, 0x33]);
        // String offsets (3 * 4 bytes)
        buf.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
        buf.extend_from_slice(&[0x10, 0x01, 0x00, 0x00]);
        buf.extend_from_slice(&[0x20, 0x01, 0x00, 0x00]);
        // Entry offsets (3 * 4 bytes)
        buf.extend_from_slice(&[0u8, 0, 0, 0]);
        buf.extend_from_slice(&[0u8, 0, 0, 0]);
        buf.extend_from_slice(&[0u8, 0, 0, 0]);
        // Abbreviation table (1 byte: null terminator)
        buf.extend_from_slice(&[0u8]);

        let debug_names = DebugNames::new(&buf, LittleEndian);
        if let Ok(Some(header)) = debug_names.headers().next() {
            // Test boundary case where bucket points to last name
            assert_eq!(header.bucket_count(), 3);
            assert_eq!(header.name_count(), 3);
            assert_eq!(header.compile_unit_count(), 1);
        } else {
            panic!("Expected valid debug_names header");
        }
    }

    #[test]
    fn test_debug_names_abbrev_table_empty() {
        // Test with empty abbreviation table (abbrev_table_size = 0)
        let mut buf = Vec::new();
        // Length: header(32) + CU offsets(4) = 36
        buf.extend_from_slice(&[36u8, 0, 0, 0]);
        // Version (2 bytes): DWARF 5
        buf.extend_from_slice(&[5u8, 0]);
        // Padding (2 bytes)
        buf.extend_from_slice(&[0u8, 0]);
        // CU count (4 bytes)
        buf.extend_from_slice(&[1u8, 0, 0, 0]);
        // Local TU count (4 bytes)
        buf.extend_from_slice(&[0u8, 0, 0, 0]);
        // Foreign TU count (4 bytes)
        buf.extend_from_slice(&[0u8, 0, 0, 0]);
        // Bucket count (4 bytes)
        buf.extend_from_slice(&[0u8, 0, 0, 0]);
        // Name count (4 bytes)
        buf.extend_from_slice(&[0u8, 0, 0, 0]);
        // Abbrev table size (4 bytes) - empty table
        buf.extend_from_slice(&[0u8, 0, 0, 0]);
        // Augmentation string size (4 bytes)
        buf.extend_from_slice(&[0u8, 0, 0, 0]);

        // Data tables:
        // CU offsets (1 * 4 bytes)
        buf.extend_from_slice(&[0x00, 0x10, 0x00, 0x00]);

        let debug_names = DebugNames::new(&buf, LittleEndian);
        if let Ok(Some(header)) = debug_names.headers().next() {
            assert_eq!(header.abbrev_table_size(), 0);
            assert_eq!(header.bucket_count(), 0);
            assert_eq!(header.name_count(), 0);
        } else {
            panic!("Expected valid debug_names header");
        }
    }

    #[test]
    fn test_debug_names_abbrev_table_minimal() {
        // Test with minimal abbreviation table (just null terminator)
        let mut buf = Vec::new();
        // Length: header(32) + CU offsets(4) + abbrev table(1) = 37
        buf.extend_from_slice(&[37u8, 0, 0, 0]);
        // Version (2 bytes): DWARF 5
        buf.extend_from_slice(&[5u8, 0]);
        // Padding (2 bytes)
        buf.extend_from_slice(&[0u8, 0]);
        // CU count (4 bytes)
        buf.extend_from_slice(&[1u8, 0, 0, 0]);
        // Local TU count (4 bytes)
        buf.extend_from_slice(&[0u8, 0, 0, 0]);
        // Foreign TU count (4 bytes)
        buf.extend_from_slice(&[0u8, 0, 0, 0]);
        // Bucket count (4 bytes)
        buf.extend_from_slice(&[0u8, 0, 0, 0]);
        // Name count (4 bytes)
        buf.extend_from_slice(&[0u8, 0, 0, 0]);
        // Abbrev table size (4 bytes)
        buf.extend_from_slice(&[1u8, 0, 0, 0]);
        // Augmentation string size (4 bytes)
        buf.extend_from_slice(&[0u8, 0, 0, 0]);

        // Data tables:
        // CU offsets (1 * 4 bytes)
        buf.extend_from_slice(&[0x00, 0x10, 0x00, 0x00]);
        // Abbreviation table (1 byte: null terminator)
        buf.extend_from_slice(&[0u8]);

        let debug_names = DebugNames::new(&buf, LittleEndian);
        if let Ok(Some(header)) = debug_names.headers().next() {
            assert_eq!(header.abbrev_table_size(), 1);
        } else {
            panic!("Expected valid debug_names header");
        }
    }

    #[test]
    fn test_debug_names_abbrev_table_single_abbrev() {
        // Test with single abbreviation entry
        let mut buf = Vec::new();
        // Length: header(32) + CU offsets(4) + abbrev table(6) = 42
        buf.extend_from_slice(&[42u8, 0, 0, 0]);
        // Version (2 bytes): DWARF 5
        buf.extend_from_slice(&[5u8, 0]);
        // Padding (2 bytes)
        buf.extend_from_slice(&[0u8, 0]);
        // CU count (4 bytes)
        buf.extend_from_slice(&[1u8, 0, 0, 0]);
        // Local TU count (4 bytes)
        buf.extend_from_slice(&[0u8, 0, 0, 0]);
        // Foreign TU count (4 bytes)
        buf.extend_from_slice(&[0u8, 0, 0, 0]);
        // Bucket count (4 bytes)
        buf.extend_from_slice(&[0u8, 0, 0, 0]);
        // Name count (4 bytes)
        buf.extend_from_slice(&[0u8, 0, 0, 0]);
        // Abbrev table size (4 bytes)
        buf.extend_from_slice(&[6u8, 0, 0, 0]);
        // Augmentation string size (4 bytes)
        buf.extend_from_slice(&[0u8, 0, 0, 0]);

        // Data tables:
        // CU offsets (1 * 4 bytes)
        buf.extend_from_slice(&[0x00, 0x10, 0x00, 0x00]);
        // Abbreviation table (6 bytes):
        // Abbrev code 1 (ULEB128)
        buf.extend_from_slice(&[1u8]);
        // Tag: DW_TAG_base_type (ULEB128)
        buf.extend_from_slice(&[0x24u8]);
        // Index attributes:
        // DW_IDX_die_offset (ULEB128)
        buf.extend_from_slice(&[0x01u8]);
        // DW_FORM_ref4 (ULEB128)
        buf.extend_from_slice(&[0x06u8]);
        // End of attributes (0, 0)
        buf.extend_from_slice(&[0u8]);
        // End of abbreviations (0)
        buf.extend_from_slice(&[0u8]);

        let debug_names = DebugNames::new(&buf, LittleEndian);
        if let Ok(Some(header)) = debug_names.headers().next() {
            assert_eq!(header.abbrev_table_size(), 6);
        } else {
            panic!("Expected valid debug_names header");
        }
    }

    #[test]
    fn test_debug_names_real_data_integration() {
        // Test with real debug_names data structure matching actual compiler output
        // This simulates the structure from the gimli_debug_names_final.txt output
        let mut buf = Vec::new();

        // Create a more realistic debug_names section with multiple entries
        // Length: header(40) + CU offsets(4) + hash buckets(16) + hash array(16) + string offsets(16) + entry offsets(16) + abbrev table(17) + entries(12) = 137
        buf.extend_from_slice(&[137u8, 0, 0, 0]);
        // Version (2 bytes): DWARF 5
        buf.extend_from_slice(&[5u8, 0]);
        // Padding (2 bytes)
        buf.extend_from_slice(&[0u8, 0]);
        // CU count (4 bytes)
        buf.extend_from_slice(&[1u8, 0, 0, 0]);
        // Local TU count (4 bytes)
        buf.extend_from_slice(&[0u8, 0, 0, 0]);
        // Foreign TU count (4 bytes)
        buf.extend_from_slice(&[0u8, 0, 0, 0]);
        // Bucket count (4 bytes)
        buf.extend_from_slice(&[4u8, 0, 0, 0]);
        // Name count (4 bytes)
        buf.extend_from_slice(&[4u8, 0, 0, 0]);
        // Abbrev table size (4 bytes)
        buf.extend_from_slice(&[17u8, 0, 0, 0]);
        // Augmentation string size (4 bytes)
        buf.extend_from_slice(&[8u8, 0, 0, 0]);
        // Augmentation string: "LLVM0700"
        buf.extend_from_slice(b"LLVM0700");

        // Data tables:
        // CU offsets (1 * 4 bytes)
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        // Hash buckets (4 * 4 bytes) - simulating real distribution
        buf.extend_from_slice(&[1u8, 0, 0, 0]); // Bucket 0: points to name 1 ("int")
        buf.extend_from_slice(&[0u8, 0, 0, 0]); // Bucket 1: empty
        buf.extend_from_slice(&[2u8, 0, 0, 0]); // Bucket 2: points to name 2 ("main")
        buf.extend_from_slice(&[3u8, 0, 0, 0]); // Bucket 3: points to name 3 ("__ARRAY_SIZE_TYPE__")

        // Hash array (4 * 4 bytes) - using realistic hash values
        buf.extend_from_slice(&[0x30, 0x80, 0x88, 0x0B]); // Hash for "int"
        buf.extend_from_slice(&[0x6A, 0x7F, 0x9A, 0x7C]); // Hash for "main"
        buf.extend_from_slice(&[0xFB, 0x4C, 0xEF, 0x0C]); // Hash for "__ARRAY_SIZE_TYPE__"
        buf.extend_from_slice(&[0x63, 0x20, 0x95, 0x7C]); // Hash for "char"

        // String offsets (4 * 4 bytes)
        buf.extend_from_slice(&[0xF7, 0x00, 0x00, 0x00]); // String offset for "int"
        buf.extend_from_slice(&[0xF2, 0x00, 0x00, 0x00]); // String offset for "main"
        buf.extend_from_slice(&[0xDE, 0x00, 0x00, 0x00]); // String offset for "__ARRAY_SIZE_TYPE__"
        buf.extend_from_slice(&[0xD9, 0x00, 0x00, 0x00]); // String offset for "char"

        // Entry offsets (4 * 4 bytes)
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Entry at offset 0
        buf.extend_from_slice(&[0x06, 0x00, 0x00, 0x00]); // Entry at offset 6
        buf.extend_from_slice(&[0x0C, 0x00, 0x00, 0x00]); // Entry at offset 12
        buf.extend_from_slice(&[0x12, 0x00, 0x00, 0x00]); // Entry at offset 18

        // Abbreviation table (17 bytes total)
        // Abbreviation 0x1 (DW_TAG_base_type)
        buf.extend_from_slice(&[0x01]); // Code
        buf.extend_from_slice(&[0x24]); // DW_TAG_base_type
        buf.extend_from_slice(&[0x01]); // DW_IDX_die_offset
        buf.extend_from_slice(&[0x06]); // DW_FORM_ref4
        buf.extend_from_slice(&[0x02]); // DW_IDX_parent
        buf.extend_from_slice(&[0x19]); // DW_FORM_flag_present
        buf.extend_from_slice(&[0x00, 0x00]); // End of attributes

        // Abbreviation 0x2 (DW_TAG_subprogram)
        buf.extend_from_slice(&[0x02]); // Code
        buf.extend_from_slice(&[0x2E]); // DW_TAG_subprogram
        buf.extend_from_slice(&[0x01]); // DW_IDX_die_offset
        buf.extend_from_slice(&[0x06]); // DW_FORM_ref4
        buf.extend_from_slice(&[0x02]); // DW_IDX_parent
        buf.extend_from_slice(&[0x19]); // DW_FORM_flag_present
        buf.extend_from_slice(&[0x00, 0x00]); // End of attributes

        buf.extend_from_slice(&[0x00]); // End of abbreviations

        // Entry pool (12 bytes)
        // Entry 0: abbrev=1, die_offset=0x3c
        buf.extend_from_slice(&[0x01, 0x3C, 0x00, 0x00, 0x00, 0x01]);
        // Entry 1: abbrev=2, die_offset=0x2d
        buf.extend_from_slice(&[0x02, 0x2D, 0x00, 0x00, 0x00, 0x01]);

        let debug_names = DebugNames::new(&buf, LittleEndian);
        if let Ok(Some(header)) = debug_names.headers().next() {
            // Validate the parsed header matches real data structure
            assert_eq!(header.version(), 5);
            assert_eq!(header.format(), Format::Dwarf32);
            assert_eq!(header.compile_unit_count(), 1);
            assert_eq!(header.local_type_unit_count(), 0);
            assert_eq!(header.foreign_type_unit_count(), 0);
            assert_eq!(header.bucket_count(), 4);
            assert_eq!(header.name_count(), 4);
            assert_eq!(header.abbrev_table_size(), 17);
            assert_eq!(header.augmentation_string().unwrap().slice(), b"LLVM0700");
        } else {
            panic!("Expected valid debug_names header with real data");
        }
    }

    #[test]
    fn test_debug_names_with_entries() {
        // Test a complete debug_names section with entries
        let length = Label::new();
        let start = Label::new();
        let end = Label::new();

        let section = Section::with_endian(Endian::Little)
            .debug_names_header(
                Format::Dwarf32,
                &length,
                &start,
                5, // version
                1, // cu_count
                0, // local_tu_count
                0, // foreign_tu_count
                2, // bucket_count
                2, // name_count
                9, // abbrev_table_size
                "",
            )
            // CU offsets
            .debug_names_cu_offset(0)
            // Hash buckets
            .debug_names_hash_bucket(1) // Points to first name
            .debug_names_hash_bucket(0) // Empty
            // Hash array
            .debug_names_hash(0x12345678)
            .debug_names_hash(0x9abcdef0)
            // String offsets
            .debug_names_string_offset(0x100)
            .debug_names_string_offset(0x200)
            // Entry offsets
            .debug_names_entry_offset(0)
            .debug_names_entry_offset(6)
            // Abbreviation table
            .debug_names_abbrev(
                1,
                constants::DW_TAG_base_type,
                &[(constants::DW_IDX_die_offset, constants::DW_FORM_ref4)],
            )
            .debug_names_abbrev_null()
            // Entry pool
            .debug_names_entry(1, &[0x34, 0x12, 0x00, 0x00]) // First entry
            .debug_names_entry(1, &[0x78, 0x56, 0x00, 0x00]) // Second entry
            // Entry series terminator
            .D8(0)
            .debug_names_end(&end);

        length.set_const((&end - &start) as u64);
        let buf = section.get_contents().unwrap();

        let debug_names = DebugNames::new(&buf, LittleEndian);
        let mut headers = debug_names.headers();

        let header = headers.next().unwrap().unwrap();
        assert_eq!(header.name_count(), 2);

        let name_index = NameIndex::new(header).expect("Should create name index");

        // Test accessing data arrays
        assert_eq!(name_index.bucket_count(), 2);
        let mut bucket = name_index.find_by_bucket(0).unwrap().unwrap();
        assert_eq!(bucket.next(), Ok(Some((NameTableIndex(0), 0x12345678))));
        assert_eq!(bucket.next(), Ok(Some((NameTableIndex(1), 0x9abcdef0))));
        assert_eq!(bucket.next(), Ok(None));

        let bucket = name_index.find_by_bucket(1).unwrap();
        assert!(bucket.is_none());

        // Test entry iteration
        let _entries = name_index.name_entries(NameTableIndex(0)).unwrap();
        /*
        // TODO: fix test to have valid entry data, and check it
        entries.next().unwrap().unwrap();
        entries.next().unwrap().unwrap();
        assert!(entries.next().unwrap().is_some());
        */
    }

    #[test]
    fn test_debug_names_empty_iterator() {
        // Test iterator with zero entries
        let length = Label::new();
        let start = Label::new();
        let end = Label::new();

        let section = Section::with_endian(Endian::Little)
            .debug_names_header(Format::Dwarf32, &length, &start, 5, 0, 0, 0, 0, 1, 0, "")
            // String offsets
            .debug_names_string_offset(0x100)
            // Entry offsets
            .debug_names_entry_offset(0)
            // Entry series terminator
            .D8(0)
            .debug_names_end(&end);

        length.set_const((&end - &start) as u64);
        let buf = section.get_contents().unwrap();

        let debug_names = DebugNames::new(&buf, LittleEndian);
        let mut headers = debug_names.headers();

        if let Ok(Some(header)) = headers.next() {
            let name_index = NameIndex::new(header).expect("Should create name index");
            let mut entries = name_index.name_entries(NameTableIndex(0)).unwrap();
            // Should immediately return None for empty iterator
            assert!(entries.next().unwrap().is_none());
            // Multiple calls should continue to return None
            assert!(entries.next().unwrap().is_none());
        }
    }
}
