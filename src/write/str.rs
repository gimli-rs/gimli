use indexmap::IndexSet;
use std::ops::{Deref, DerefMut};
use vec::Vec;

use common::DebugStrOffset;
use write::{Result, Section, SectionId, Writer};

/// An identifier for a string in a `StringTable.`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StringId(usize);

/// A table of strings that will be stored in a `.debug_str` section.
// Requirements:
// - values are `[u8]`, null bytes are not allowed
// - insertion returns a fixed id
// - inserting a duplicate returns the id of the existing value
// - able to convert an id to a section offset
// Optional?
// - able to get an existing value given an id
//
// Limitations of current implementation (using IndexSet):
// - inserting requires either an allocation for duplicates,
//   or a double lookup for non-duplicates
// - doesn't preserve offsets when updating an existing `.debug_str` section
//
// Possible changes:
// - calculate offsets as we add values, and use that as the id.
//   This would avoid the need for DebugStrOffsets but would make it
//   hard to implement `get`.
#[derive(Debug, Default)]
pub struct StringTable {
    strings: IndexSet<Vec<u8>>,
}

impl StringTable {
    /// Add a string to the string table and return its id.
    ///
    /// # Panics
    ///
    /// Panics if `bytes` contains a null byte.
    pub fn add<T>(&mut self, bytes: T) -> StringId
    where
        T: Into<Vec<u8>>,
    {
        let bytes = bytes.into();
        assert!(!bytes.contains(&0));
        let (index, _) = self.strings.insert_full(bytes);
        StringId(index)
    }

    /// Return the number of strings in the table.
    #[inline]
    pub fn count(&self) -> usize {
        self.strings.len()
    }

    /// Get a reference to a string in the table.
    ///
    /// # Panics
    ///
    /// Panics if `id` is invalid.
    pub fn get(&self, id: StringId) -> &[u8] {
        self.strings.get_index(id.0).map(Vec::as_slice).unwrap()
    }

    /// Write the string table to the `.debug_str` section.
    ///
    /// Returns the offsets at which the strings are written.
    pub fn write<W: Writer>(&self, w: &mut DebugStr<W>) -> Result<DebugStrOffsets> {
        let mut offsets = Vec::new();
        for bytes in self.strings.iter() {
            offsets.push(w.offset());
            w.write(bytes)?;
            w.write_u8(0)?;
        }

        Ok(DebugStrOffsets { strings: offsets })
    }
}

/// A writable `.debug_str` section.
#[derive(Debug)]
pub struct DebugStr<W: Writer>(pub W);

impl<W: Writer> DebugStr<W> {
    /// Return the offset of the next write.
    pub fn offset(&self) -> DebugStrOffset {
        DebugStrOffset(self.len())
    }
}

impl<W: Writer> From<W> for DebugStr<W> {
    #[inline]
    fn from(w: W) -> Self {
        DebugStr(w)
    }
}

impl<W: Writer> Deref for DebugStr<W> {
    type Target = W;

    #[inline]
    fn deref(&self) -> &W {
        &self.0
    }
}

impl<W: Writer> DerefMut for DebugStr<W> {
    #[inline]
    fn deref_mut(&mut self) -> &mut W {
        &mut self.0
    }
}

impl<W: Writer> Section<W> for DebugStr<W> {
    #[inline]
    fn id() -> SectionId {
        SectionId::DebugStr
    }
}

/// The section offsets of all strings within a `.debug_str` section.
#[derive(Debug, Default)]
pub struct DebugStrOffsets {
    // We know ids start at 0.
    strings: Vec<DebugStrOffset>,
}

impl DebugStrOffsets {
    /// Get the `.debug_str` offset of a string.
    ///
    /// The given `id` must be valid.
    #[inline]
    pub fn get(&self, id: StringId) -> DebugStrOffset {
        self.strings[id.0]
    }

    /// Return the number of strings in the table.
    #[inline]
    pub fn count(&self) -> usize {
        self.strings.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use read;
    use write::EndianVec;
    use LittleEndian;

    #[test]
    fn test_string_table() {
        let mut strings = StringTable::default();
        assert_eq!(strings.count(), 0);
        let id1 = strings.add(&b"one"[..]);
        let id2 = strings.add(&b"two"[..]);
        assert_eq!(strings.add(&b"one"[..]), id1);
        assert_eq!(strings.add(&b"two"[..]), id2);
        assert_eq!(strings.get(id1), &b"one"[..]);
        assert_eq!(strings.get(id2), &b"two"[..]);
        assert_eq!(strings.count(), 2);

        let mut debug_str = DebugStr::from(EndianVec::new(LittleEndian));
        let offsets = strings.write(&mut debug_str).unwrap();
        assert_eq!(debug_str.slice(), b"one\0two\0");
        assert_eq!(offsets.get(id1), DebugStrOffset(0));
        assert_eq!(offsets.get(id2), DebugStrOffset(4));
        assert_eq!(offsets.count(), 2);
    }

    #[test]
    fn test_string_table_read() {
        let mut strings = StringTable::default();
        let id1 = strings.add(&b"one"[..]);
        let id2 = strings.add(&b"two"[..]);

        let mut debug_str = DebugStr::from(EndianVec::new(LittleEndian));
        let offsets = strings.write(&mut debug_str).unwrap();

        let read_debug_str = read::DebugStr::new(debug_str.slice(), LittleEndian);
        let str1 = read_debug_str.get_str(offsets.get(id1)).unwrap();
        let str2 = read_debug_str.get_str(offsets.get(id2)).unwrap();
        assert_eq!(str1.slice(), &b"one"[..]);
        assert_eq!(str2.slice(), &b"two"[..]);
    }
}
