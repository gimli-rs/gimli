use crate::common::{
    DebugAddrBase, DebugAddrIndex, DebugInfoOffset, DebugLineStrOffset, DebugLocListsBase,
    DebugLocListsIndex, DebugRngListsBase, DebugRngListsIndex, DebugStrOffset, DebugStrOffsetsBase,
    DebugStrOffsetsIndex, DebugTypesOffset, Encoding, LocationListsOffset, RangeListsOffset,
    UnitSectionOffset,
};
use crate::constants;
use crate::read::{
    Abbreviations, AttributeValue, CompilationUnitHeader, CompilationUnitHeadersIter, DebugAbbrev,
    DebugAddr, DebugInfo, DebugLine, DebugLineStr, DebugStr, DebugStrOffsets, DebugTypes,
    EntriesCursor, EntriesTree, Error, IncompleteLineProgram, LocListIter, LocationLists,
    RangeLists, Reader, ReaderOffset, Result, RngListIter, TypeUnitHeader, TypeUnitHeadersIter,
    UnitHeader, UnitOffset,
};

/// All of the commonly used DWARF sections, and other common information.
#[derive(Debug, Default)]
pub struct Dwarf<R: Reader> {
    /// The `.debug_abbrev` section.
    pub debug_abbrev: DebugAbbrev<R>,

    /// The `.debug_addr` section.
    pub debug_addr: DebugAddr<R>,

    /// The `.debug_info` section.
    pub debug_info: DebugInfo<R>,

    /// The `.debug_line` section.
    pub debug_line: DebugLine<R>,

    /// The `.debug_line_str` section.
    pub debug_line_str: DebugLineStr<R>,

    /// The `.debug_str` section.
    pub debug_str: DebugStr<R>,

    /// The `.debug_str_offsets` section.
    pub debug_str_offsets: DebugStrOffsets<R>,

    /// The `.debug_str` section for a supplementary object file.
    pub debug_str_sup: DebugStr<R>,

    /// The `.debug_types` section.
    pub debug_types: DebugTypes<R>,

    /// The location lists in the `.debug_loc` and `.debug_loclists` sections.
    pub locations: LocationLists<R>,

    /// The range lists in the `.debug_ranges` and `.debug_rnglists` sections.
    pub ranges: RangeLists<R>,
}

impl<R: Reader> Dwarf<R> {
    /// Iterate the compilation- and partial-unit headers in the
    /// `.debug_info` section.
    ///
    /// Can be [used with
    /// `FallibleIterator`](./index.html#using-with-fallibleiterator).
    #[inline]
    pub fn units(&self) -> CompilationUnitHeadersIter<R> {
        self.debug_info.units()
    }

    /// Construct a new `Unit` from the given compilation unit header.
    #[inline]
    pub fn unit(&self, header: CompilationUnitHeader<R, R::Offset>) -> Result<Unit<R>> {
        Unit::new(self, header)
    }

    /// Iterate the type-unit headers in the `.debug_types` section.
    ///
    /// Can be [used with
    /// `FallibleIterator`](./index.html#using-with-fallibleiterator).
    #[inline]
    pub fn type_units(&self) -> TypeUnitHeadersIter<R> {
        self.debug_types.units()
    }

    /// Construct a new `Unit` from the given type unit header.
    #[inline]
    pub fn type_unit(&self, header: TypeUnitHeader<R, R::Offset>) -> Result<Unit<R>> {
        Unit::new_type_unit(self, header)
    }

    /// Parse the abbreviations for a compilation unit.
    // TODO: provide caching of abbreviations
    #[inline]
    pub fn abbreviations(
        &self,
        unit: &CompilationUnitHeader<R, R::Offset>,
    ) -> Result<Abbreviations> {
        unit.abbreviations(&self.debug_abbrev)
    }

    /// Parse the abbreviations for a type unit.
    // TODO: provide caching of abbreviations
    #[inline]
    pub fn type_abbreviations(&self, unit: &TypeUnitHeader<R, R::Offset>) -> Result<Abbreviations> {
        unit.abbreviations(&self.debug_abbrev)
    }

    /// Return the string offset at the given index.
    #[inline]
    pub fn string_offset(
        &self,
        unit: &Unit<R>,
        index: DebugStrOffsetsIndex<R::Offset>,
    ) -> Result<DebugStrOffset<R::Offset>> {
        self.debug_str_offsets
            .get_str_offset(unit.header.format(), unit.str_offsets_base, index)
    }

    /// Return the string at the given offset in `.debug_str`.
    #[inline]
    pub fn string(&self, offset: DebugStrOffset<R::Offset>) -> Result<R> {
        self.debug_str.get_str(offset)
    }

    /// Return the string at the given offset in `.debug_line_str`.
    #[inline]
    pub fn line_string(&self, offset: DebugLineStrOffset<R::Offset>) -> Result<R> {
        self.debug_line_str.get_str(offset)
    }

    /// Return an attribute value as a string slice.
    ///
    /// If the attribute value is one of:
    ///
    /// - an inline `DW_FORM_string` string
    /// - a `DW_FORM_strp` reference to an offset into the `.debug_str` section
    /// - a `DW_FORM_strp_sup` reference to an offset into a supplementary
    /// object file
    /// - a `DW_FORM_line_strp` reference to an offset into the `.debug_line_str`
    /// section
    /// - a `DW_FORM_strx` index into the `.debug_str_offsets` entries for the unit
    ///
    /// then return the attribute's string value. Returns an error if the attribute
    /// value does not have a string form, or if a string form has an invalid value.
    pub fn attr_string(&self, unit: &Unit<R>, attr: AttributeValue<R, R::Offset>) -> Result<R> {
        match attr {
            AttributeValue::String(string) => Ok(string),
            AttributeValue::DebugStrRef(offset) => self.debug_str.get_str(offset),
            AttributeValue::DebugStrRefSup(offset) => self.debug_str_sup.get_str(offset),
            AttributeValue::DebugLineStrRef(offset) => self.debug_line_str.get_str(offset),
            AttributeValue::DebugStrOffsetsIndex(index) => {
                let offset = self.debug_str_offsets.get_str_offset(
                    unit.header.format(),
                    unit.str_offsets_base,
                    index,
                )?;
                self.debug_str.get_str(offset)
            }
            _ => Err(Error::ExpectedStringAttributeValue),
        }
    }

    /// Return the address at the given index.
    pub fn address(&self, unit: &Unit<R>, index: DebugAddrIndex<R::Offset>) -> Result<u64> {
        self.debug_addr
            .get_address(unit.encoding().address_size, unit.addr_base, index)
    }

    /// Return the range list offset at the given index.
    pub fn ranges_offset(
        &self,
        unit: &Unit<R>,
        index: DebugRngListsIndex<R::Offset>,
    ) -> Result<RangeListsOffset<R::Offset>> {
        self.ranges
            .get_offset(unit.encoding(), unit.rnglists_base, index)
    }

    /// Iterate over the `RangeListEntry`s starting at the given offset.
    pub fn ranges(
        &self,
        unit: &Unit<R>,
        offset: RangeListsOffset<R::Offset>,
    ) -> Result<RngListIter<R>> {
        self.ranges.ranges(
            offset,
            unit.encoding(),
            unit.low_pc,
            &self.debug_addr,
            unit.addr_base,
        )
    }

    /// Try to return an attribute value as a range list offset.
    ///
    /// If the attribute value is one of:
    ///
    /// - a `DW_FORM_sec_offset` reference to the `.debug_ranges` or `.debug_rnglists` sections
    /// - a `DW_FORM_rnglistx` index into the `.debug_rnglists` entries for the unit
    ///
    /// then return the range list offset of the range list.
    /// Returns `None` for other forms.
    pub fn attr_ranges_offset(
        &self,
        unit: &Unit<R>,
        attr: AttributeValue<R, R::Offset>,
    ) -> Result<Option<RangeListsOffset<R::Offset>>> {
        match attr {
            AttributeValue::RangeListsRef(offset) => Ok(Some(offset)),
            AttributeValue::DebugRngListsIndex(index) => self.ranges_offset(unit, index).map(Some),
            _ => Ok(None),
        }
    }

    /// Try to return an attribute value as a range list entry iterator.
    ///
    /// If the attribute value is one of:
    ///
    /// - a `DW_FORM_sec_offset` reference to the `.debug_ranges` or `.debug_rnglists` sections
    /// - a `DW_FORM_rnglistx` index into the `.debug_rnglists` entries for the unit
    ///
    /// then return an iterator over the entries in the range list.
    /// Returns `None` for other forms.
    pub fn attr_ranges(
        &self,
        unit: &Unit<R>,
        attr: AttributeValue<R, R::Offset>,
    ) -> Result<Option<RngListIter<R>>> {
        match self.attr_ranges_offset(unit, attr)? {
            Some(offset) => Ok(Some(self.ranges(unit, offset)?)),
            None => Ok(None),
        }
    }

    /// Return the location list offset at the given index.
    pub fn locations_offset(
        &self,
        unit: &Unit<R>,
        index: DebugLocListsIndex<R::Offset>,
    ) -> Result<LocationListsOffset<R::Offset>> {
        self.locations
            .get_offset(unit.encoding(), unit.loclists_base, index)
    }

    /// Iterate over the `LocationListEntry`s starting at the given offset.
    pub fn locations(
        &self,
        unit: &Unit<R>,
        offset: LocationListsOffset<R::Offset>,
    ) -> Result<LocListIter<R>> {
        self.locations.locations(
            offset,
            unit.encoding(),
            unit.low_pc,
            &self.debug_addr,
            unit.addr_base,
        )
    }

    /// Try to return an attribute value as a location list offset.
    ///
    /// If the attribute value is one of:
    ///
    /// - a `DW_FORM_sec_offset` reference to the `.debug_loc` or `.debug_loclists` sections
    /// - a `DW_FORM_loclistx` index into the `.debug_loclists` entries for the unit
    ///
    /// then return the location list offset of the location list.
    /// Returns `None` for other forms.
    pub fn attr_locations_offset(
        &self,
        unit: &Unit<R>,
        attr: AttributeValue<R, R::Offset>,
    ) -> Result<Option<LocationListsOffset<R::Offset>>> {
        match attr {
            AttributeValue::LocationListsRef(offset) => Ok(Some(offset)),
            AttributeValue::DebugLocListsIndex(index) => {
                self.locations_offset(unit, index).map(Some)
            }
            _ => Ok(None),
        }
    }

    /// Try to return an attribute value as a location list entry iterator.
    ///
    /// If the attribute value is one of:
    ///
    /// - a `DW_FORM_sec_offset` reference to the `.debug_loc` or `.debug_loclists` sections
    /// - a `DW_FORM_loclistx` index into the `.debug_loclists` entries for the unit
    ///
    /// then return an iterator over the entries in the location list.
    /// Returns `None` for other forms.
    pub fn attr_locations(
        &self,
        unit: &Unit<R>,
        attr: AttributeValue<R, R::Offset>,
    ) -> Result<Option<LocListIter<R>>> {
        match self.attr_locations_offset(unit, attr)? {
            Some(offset) => Ok(Some(self.locations(unit, offset)?)),
            None => Ok(None),
        }
    }
}

/// All of the commonly used information for a unit in the `.debug_info` or `.debug_types`
/// sections.
#[derive(Debug)]
pub struct Unit<R: Reader> {
    /// The section offset of the unit.
    pub offset: UnitSectionOffset<R::Offset>,

    /// The header of the unit.
    pub header: UnitHeader<R, R::Offset>,

    /// The parsed abbreviations for the unit.
    pub abbreviations: Abbreviations,

    /// The `DW_AT_name` attribute of the unit.
    pub name: Option<R>,

    /// The `DW_AT_comp_dir` attribute of the unit.
    pub comp_dir: Option<R>,

    /// The `DW_AT_low_pc` attribute of the unit. Defaults to 0.
    pub low_pc: u64,

    /// The `DW_AT_str_offsets_base` attribute of the unit. Defaults to 0.
    pub str_offsets_base: DebugStrOffsetsBase<R::Offset>,

    /// The `DW_AT_addr_base` attribute of the unit. Defaults to 0.
    pub addr_base: DebugAddrBase<R::Offset>,

    /// The `DW_AT_loclists_base` attribute of the unit. Defaults to 0.
    pub loclists_base: DebugLocListsBase<R::Offset>,

    /// The `DW_AT_rnglists_base` attribute of the unit. Defaults to 0.
    pub rnglists_base: DebugRngListsBase<R::Offset>,

    /// The line number program of the unit.
    pub line_program: Option<IncompleteLineProgram<R, R::Offset>>,
}

impl<R: Reader> Unit<R> {
    /// Construct a new `Unit` from the given compilation unit header.
    #[inline]
    pub fn new(dwarf: &Dwarf<R>, header: CompilationUnitHeader<R, R::Offset>) -> Result<Self> {
        Self::new_internal(
            dwarf,
            UnitSectionOffset::DebugInfoOffset(header.offset()),
            header.header(),
        )
    }

    /// Construct a new `Unit` from the given type unit header.
    #[inline]
    pub fn new_type_unit(dwarf: &Dwarf<R>, header: TypeUnitHeader<R, R::Offset>) -> Result<Self> {
        Self::new_internal(
            dwarf,
            UnitSectionOffset::DebugTypesOffset(header.offset()),
            header.header(),
        )
    }

    fn new_internal(
        dwarf: &Dwarf<R>,
        offset: UnitSectionOffset<R::Offset>,
        header: UnitHeader<R, R::Offset>,
    ) -> Result<Self> {
        let abbreviations = header.abbreviations(&dwarf.debug_abbrev)?;
        let mut unit = Unit {
            offset,
            header,
            abbreviations,
            name: None,
            comp_dir: None,
            low_pc: 0,
            // Defaults to 0 for GNU extensions.
            str_offsets_base: DebugStrOffsetsBase(R::Offset::from_u8(0)),
            addr_base: DebugAddrBase(R::Offset::from_u8(0)),
            loclists_base: DebugLocListsBase(R::Offset::from_u8(0)),
            rnglists_base: DebugRngListsBase(R::Offset::from_u8(0)),
            line_program: None,
        };
        let mut name = None;
        let mut comp_dir = None;
        let mut line_program_offset = None;

        {
            let mut cursor = unit.header.entries(&unit.abbreviations);
            cursor.next_dfs()?;
            let root = cursor.current().ok_or(Error::MissingUnitDie)?;
            let mut attrs = root.attrs();
            while let Some(attr) = attrs.next()? {
                match attr.name() {
                    constants::DW_AT_name => {
                        name = Some(attr.value());
                    }
                    constants::DW_AT_comp_dir => {
                        comp_dir = Some(attr.value());
                    }
                    constants::DW_AT_low_pc => {
                        if let AttributeValue::Addr(address) = attr.value() {
                            unit.low_pc = address;
                        }
                    }
                    constants::DW_AT_stmt_list => {
                        if let AttributeValue::DebugLineRef(offset) = attr.value() {
                            line_program_offset = Some(offset);
                        }
                    }
                    constants::DW_AT_str_offsets_base => {
                        if let AttributeValue::DebugStrOffsetsBase(base) = attr.value() {
                            unit.str_offsets_base = base;
                        }
                    }
                    constants::DW_AT_addr_base => {
                        if let AttributeValue::DebugAddrBase(base) = attr.value() {
                            unit.addr_base = base;
                        }
                    }
                    constants::DW_AT_loclists_base => {
                        if let AttributeValue::DebugLocListsBase(base) = attr.value() {
                            unit.loclists_base = base;
                        }
                    }
                    constants::DW_AT_rnglists_base => {
                        if let AttributeValue::DebugRngListsBase(base) = attr.value() {
                            unit.rnglists_base = base;
                        }
                    }
                    _ => {}
                }
            }
        }

        unit.name = match name {
            Some(val) => Some(dwarf.attr_string(&unit, val)?),
            None => None,
        };
        unit.comp_dir = match comp_dir {
            Some(val) => Some(dwarf.attr_string(&unit, val)?),
            None => None,
        };
        unit.line_program = match line_program_offset {
            Some(offset) => Some(dwarf.debug_line.program(
                offset,
                unit.header.address_size(),
                unit.comp_dir.clone(),
                unit.name.clone(),
            )?),
            None => None,
        };
        Ok(unit)
    }

    /// Return the encoding parameters for this unit.
    #[inline]
    pub fn encoding(&self) -> Encoding {
        self.header.encoding()
    }

    /// Navigate this unit's `DebuggingInformationEntry`s.
    #[inline]
    pub fn entries(&self) -> EntriesCursor<R> {
        self.header.entries(&self.abbreviations)
    }

    /// Navigate this unit's `DebuggingInformationEntry`s
    /// starting at the given offset.
    #[inline]
    pub fn entries_at_offset(&self, offset: UnitOffset<R::Offset>) -> Result<EntriesCursor<R>> {
        self.header.entries_at_offset(&self.abbreviations, offset)
    }

    /// Navigate this unit's `DebuggingInformationEntry`s as a tree
    /// starting at the given offset.
    #[inline]
    pub fn entries_tree(&self, offset: Option<UnitOffset<R::Offset>>) -> Result<EntriesTree<R>> {
        self.header.entries_tree(&self.abbreviations, offset)
    }
}

impl<T: ReaderOffset> UnitSectionOffset<T> {
    /// Convert an offset to be relative to the start of the given unit,
    /// instead of relative to the start of the section.
    /// Returns `None` if the offset is not within the unit entries.
    pub fn to_unit_offset<R>(&self, unit: &Unit<R>) -> Option<UnitOffset<T>>
    where
        R: Reader<Offset = T>,
    {
        let (offset, unit_offset) = match (self, unit.offset) {
            (
                UnitSectionOffset::DebugInfoOffset(offset),
                UnitSectionOffset::DebugInfoOffset(unit_offset),
            ) => (offset.0, unit_offset.0),
            (
                UnitSectionOffset::DebugTypesOffset(offset),
                UnitSectionOffset::DebugTypesOffset(unit_offset),
            ) => (offset.0, unit_offset.0),
            _ => return None,
        };
        let offset = match offset.checked_sub(unit_offset) {
            Some(offset) => UnitOffset(offset),
            None => return None,
        };
        if !unit.header.is_valid_offset(offset) {
            return None;
        }
        Some(offset)
    }
}

impl<T: ReaderOffset> UnitOffset<T> {
    /// Convert an offset to be relative to the start of the .debug_info section,
    /// instead of relative to the start of the given compilation unit.
    pub fn to_unit_section_offset<R>(&self, unit: &Unit<R>) -> UnitSectionOffset<T>
    where
        R: Reader<Offset = T>,
    {
        match unit.offset {
            UnitSectionOffset::DebugInfoOffset(unit_offset) => {
                UnitSectionOffset::DebugInfoOffset(DebugInfoOffset(unit_offset.0 + self.0))
            }
            UnitSectionOffset::DebugTypesOffset(unit_offset) => {
                UnitSectionOffset::DebugTypesOffset(DebugTypesOffset(unit_offset.0 + self.0))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::read::EndianSlice;
    use crate::Endianity;

    /// Ensure that `Dwarf<R>` is covariant wrt R.
    #[test]
    fn test_dwarf_variance() {
        /// This only needs to compile.
        #[allow(dead_code)]
        fn f<'a: 'b, 'b, E: Endianity>(x: Dwarf<EndianSlice<'a, E>>) -> Dwarf<EndianSlice<'b, E>> {
            x
        }
    }
}
