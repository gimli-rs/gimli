use indexmap::IndexSet;
use std::ops::{Deref, DerefMut};
use vec::Vec;

use common::{Format, RangeListsOffset};
use write::{Address, Error, Result, Section, SectionId, Writer};

define_section!(
    DebugRanges,
    RangeListsOffset,
    "A writable `.debug_ranges` section."
);
define_section!(
    DebugRngLists,
    RangeListsOffset,
    "A writable `.debug_rnglists` section."
);

define_offsets!(
    DebugRangesOffsets: RangeListId => RangeListsOffset,
    "The section offsets of all ranges within a `.debug_ranges` section."
);

define_offsets!(
    DebugRngListsOffsets: RangeListId => RangeListsOffset,
    "The section offsets of all ranges within a `.debug_rnglists` section."
);

/// An identifier for a range list in a `RangeListTable`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RangeListId(pub usize);

/// A table of ranges that will be stored in a `.debug_ranges` or `.debug_rnglists` section.
#[derive(Debug, Default)]
pub struct RangeListTable {
    ranges: IndexSet<RangeList>,
}

/// Offsets into the `.debug_ranges` or `.debug_rnglists` section.
#[derive(Debug, Default)]
pub struct RangeListOffsets {
    /// Offsets into the `.debug_ranges` section.
    pub debug_ranges: DebugRangesOffsets,

    /// Offsets into the `.debug_rnglists` section.
    pub debug_rnglists: DebugRngListsOffsets,
}

impl RangeListTable {
    /// Add a range to the table.
    pub fn add(&mut self, range_list: RangeList) -> RangeListId {
        let (id, _) = self.ranges.insert_full(range_list);
        RangeListId(id)
    }

    /// Write the range table to the appropriate section for the given DWARF version.
    pub fn write<W: Writer>(
        &self,
        w_ranges: &mut DebugRanges<W>,
        w_rnglists: &mut DebugRngLists<W>,
        format: Format,
        version: u16,
        address_size: u8,
    ) -> Result<RangeListOffsets> {
        match version {
            2...4 => Ok(RangeListOffsets {
                debug_ranges: self.write_ranges(w_ranges, address_size)?,
                debug_rnglists: DebugRngListsOffsets::default(),
            }),
            5 => Ok(RangeListOffsets {
                debug_ranges: DebugRangesOffsets::default(),
                debug_rnglists: self.write_rnglists(w_rnglists, format, version, address_size)?,
            }),
            _ => Err(Error::UnsupportedVersion(version)),
        }
    }

    /// Write the range table to the `.debug_ranges` section.
    fn write_ranges<W: Writer>(
        &self,
        w: &mut DebugRanges<W>,
        address_size: u8,
    ) -> Result<DebugRangesOffsets> {
        let mut offsets = Vec::new();
        for range_list in self.ranges.iter() {
            offsets.push(w.offset());
            for range in &range_list.0 {
                w.write_address(range.begin, address_size)?;
                w.write_address(range.end, address_size)?;
            }
            w.write_word(0, address_size)?;
            w.write_word(0, address_size)?;
        }
        Ok(DebugRangesOffsets { offsets })
    }

    /// Write the range table to the `.debug_rnglists` section.
    fn write_rnglists<W: Writer>(
        &self,
        w: &mut DebugRngLists<W>,
        format: Format,
        version: u16,
        address_size: u8,
    ) -> Result<DebugRngListsOffsets> {
        let mut offsets = Vec::new();

        if version != 5 {
            return Err(Error::NeedVersion(5));
        }

        let length_offset = w.write_initial_length(format)?;
        let length_base = w.len();

        w.write_u16(version)?;
        w.write_u8(address_size)?;
        w.write_u8(0)?; // segment_selector_size
        w.write_u32(0)?; // offset_entry_count (when set to zero DW_FORM_rnglistx can't be used, see section 7.28)
                         // FIXME implement DW_FORM_rnglistx writing and implement the offset entry list

        for range_list in self.ranges.iter() {
            offsets.push(w.offset());
            for range in &range_list.0 {
                w.write_u8(::constants::DW_RLE_start_end.0)?;
                w.write_address(range.begin, address_size)?;
                w.write_address(range.end, address_size)?;
            }

            w.write_u8(::constants::DW_RLE_end_of_list.0)?;
        }

        let length = (w.len() - length_base) as u64;
        w.write_initial_length_at(length_offset, length, format)?;

        Ok(DebugRngListsOffsets { offsets })
    }
}

/// A range list that will be stored in the `.debug_ranges` section.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct RangeList(pub Vec<Range>);

/// A single range
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Range {
    /// The begin address of the range
    pub begin: Address,
    /// The end address of the range
    pub end: Address,
}

#[cfg(feature = "read")]
mod convert {
    use super::*;

    use read::{self, Reader};
    use write::{ConvertError, ConvertResult};
    impl RangeList {
        /// Create a range list by reading the data from the give range list iter.
        pub fn from<R: Reader<Offset = usize>>(
            mut from: read::RngListIter<R>,
            convert_address: &Fn(u64) -> Option<Address>,
        ) -> ConvertResult<Self> {
            let mut ranges = Vec::new();
            while let Some(range) = from.next()? {
                if let (Some(begin), Some(end)) =
                    (convert_address(range.begin), convert_address(range.end))
                {
                    ranges.push(Range { begin, end });
                } else {
                    return Err(ConvertError::InvalidAddress);
                }
            }
            Ok(RangeList(ranges))
        }
    }
}
