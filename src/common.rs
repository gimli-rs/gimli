/// Whether the format of a compilation unit is 32- or 64-bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Format {
    /// 64-bit DWARF
    Dwarf64,
    /// 32-bit DWARF
    Dwarf32,
}

impl Format {
    /// Return the serialized size of an initial length field for the format.
    #[inline]
    pub fn initial_length_size(self) -> u8 {
        match self {
            Format::Dwarf32 => 4,
            Format::Dwarf64 => 12,
        }
    }

    /// Return the natural word size for the format
    #[inline]
    pub fn word_size(self) -> u8 {
        match self {
            Format::Dwarf32 => 4,
            Format::Dwarf64 => 8,
        }
    }
}

/// A DWARF register number.
///
/// The meaning of this value is ABI dependent. This is generally encoded as
/// a ULEB128, but supported architectures need 16 bits at most.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Register(pub u16);

/// An offset into the `.debug_abbrev` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DebugAbbrevOffset<T = usize>(pub T);

/// An offset to a set of entries in the `.debug_addr` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugAddrBase<T = usize>(pub T);

/// An index into a set of addresses in the `.debug_addr` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugAddrIndex<T = usize>(pub T);

/// An offset into the `.debug_info` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct DebugInfoOffset<T = usize>(pub T);

/// An offset into the `.debug_line` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugLineOffset<T = usize>(pub T);

/// An offset into either the `.debug_loc` section or the `.debug_loclists` section,
/// depending on the version of the unit the offset was contained in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LocationListsOffset<T = usize>(pub T);

/// An offset to a set of location list offsets in the `.debug_loclists` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugLocListsBase<T = usize>(pub T);

/// An index into a set of location list offsets in the `.debug_loclists` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugLocListsIndex<T = usize>(pub T);

/// An offset into the `.debug_macinfo` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DebugMacinfoOffset<T = usize>(pub T);

/// An offset into either the `.debug_ranges` section or the `.debug_rnglists` section,
/// depending on the version of the unit the offset was contained in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RangeListsOffset<T = usize>(pub T);

/// An offset to a set of range list offsets in the `.debug_rnglists` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugRngListsBase<T = usize>(pub T);

/// An index into a set of range list offsets in the `.debug_rnglists` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugRngListsIndex<T = usize>(pub T);

/// An offset into the `.debug_str` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugStrOffset<T = usize>(pub T);

/// An offset to a set of entries in the `.debug_str_offsets` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugStrOffsetsBase<T = usize>(pub T);

/// An index into a set of entries in the `.debug_str_offsets` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugStrOffsetsIndex<T = usize>(pub T);

/// An offset into the `.debug_types` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DebugTypesOffset<T = usize>(pub T);

/// A type signature as used in the `.debug_types` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DebugTypeSignature(pub u64);

/// An offset into the `.debug_frame` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DebugFrameOffset<T = usize>(pub T);

impl<T> From<T> for DebugFrameOffset<T> {
    #[inline]
    fn from(o: T) -> Self {
        DebugFrameOffset(o)
    }
}

/// An offset into the `.eh_frame` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EhFrameOffset<T = usize>(pub T);

impl<T> From<T> for EhFrameOffset<T> {
    #[inline]
    fn from(o: T) -> Self {
        EhFrameOffset(o)
    }
}
