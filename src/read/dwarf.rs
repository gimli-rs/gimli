use read::{
    DebugAbbrev, DebugInfo, DebugLine, DebugStr, DebugTypes, LocationLists, RangeLists, Reader,
};

/// All of the commonly used DWARF sections, and other common information.
#[derive(Debug, Default)]
pub struct Dwarf<R: Reader> {
    /// The endianity of bytes that are read.
    pub endian: R::Endian,

    /// The `.debug_abbrev` section.
    pub debug_abbrev: DebugAbbrev<R>,

    /// The `.debug_info` section.
    pub debug_info: DebugInfo<R>,

    /// The `.debug_line` section.
    pub debug_line: DebugLine<R>,

    /// The `.debug_str` section.
    pub debug_str: DebugStr<R>,

    /// The `.debug_types` section.
    pub debug_types: DebugTypes<R>,

    /// The location lists in the `.debug_loc` and `.debug_loclists` sections.
    pub locations: LocationLists<R>,

    /// The range lists in the `.debug_ranges` and `.debug_rnglists` sections.
    pub ranges: RangeLists<R>,
}
