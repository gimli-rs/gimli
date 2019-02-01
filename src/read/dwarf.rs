use common::{DebugAddrBase, DebugLocListsBase, DebugRngListsBase, DebugStrOffsetsBase, Encoding};
use constants;
use read::{
    Abbreviations, AttributeValue, CompilationUnitHeader, CompilationUnitHeadersIter, DebugAbbrev,
    DebugAddr, DebugInfo, DebugLine, DebugLineStr, DebugStr, DebugStrOffsets, DebugTypes,
    EntriesCursor, Error, IncompleteLineProgram, LocationLists, RangeLists, Reader, ReaderOffset,
    Result, TypeUnitHeader, TypeUnitHeadersIter, UnitHeader,
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
    /// Iterate the compilation- and partial-units in this
    /// `.debug_info` section.
    ///
    /// Can be [used with
    /// `FallibleIterator`](./index.html#using-with-fallibleiterator).
    #[inline]
    pub fn units(&self) -> CompilationUnitHeadersIter<R> {
        self.debug_info.units()
    }

    /// Iterate the type-units in this `.debug_types` section.
    ///
    /// Can be [used with
    /// `FallibleIterator`](./index.html#using-with-fallibleiterator).
    #[inline]
    pub fn type_units(&self) -> TypeUnitHeadersIter<R> {
        self.debug_types.units()
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

    /// Try to return an attribute value as a string slice.
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
    pub fn attr_string(
        &self,
        unit: &DwarfUnit<R>,
        attr: AttributeValue<R, R::Offset>,
    ) -> Result<R> {
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
}

/// All of the commonly used information for a DWARF compilation unit.
#[derive(Debug)]
pub struct DwarfUnit<R: Reader> {
    /// The header of the unit.
    pub header: UnitHeader<R, R::Offset>,

    /// The parsed abbreviations for the unit.
    pub abbreviations: Abbreviations,

    /// The `DW_AT_name` attribute of the unit.
    pub name: Option<AttributeValue<R, R::Offset>>,

    /// The `DW_AT_comp_dir` attribute of the unit.
    pub comp_dir: Option<AttributeValue<R, R::Offset>>,

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

impl<R: Reader> DwarfUnit<R> {
    /// Construct a new `DwarfUnit` from the given header.
    pub fn new(dwarf: &Dwarf<R>, header: UnitHeader<R, R::Offset>) -> Result<Self> {
        let abbreviations = header.abbreviations(&dwarf.debug_abbrev)?;
        let mut name = None;
        let mut comp_dir = None;
        let mut low_pc = 0;
        // Defaults to 0 for GNU extensions.
        let mut str_offsets_base = DebugStrOffsetsBase(R::Offset::from_u8(0));
        let mut addr_base = DebugAddrBase(R::Offset::from_u8(0));
        let mut loclists_base = DebugLocListsBase(R::Offset::from_u8(0));
        let mut rnglists_base = DebugRngListsBase(R::Offset::from_u8(0));
        let mut line_program_offset = None;

        {
            let mut cursor = header.entries(&abbreviations);
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
                            low_pc = address;
                        }
                    }
                    constants::DW_AT_stmt_list => {
                        if let AttributeValue::DebugLineRef(offset) = attr.value() {
                            line_program_offset = Some(offset);
                        }
                    }
                    constants::DW_AT_str_offsets_base => {
                        if let AttributeValue::DebugStrOffsetsBase(base) = attr.value() {
                            str_offsets_base = base;
                        }
                    }
                    constants::DW_AT_addr_base => {
                        if let AttributeValue::DebugAddrBase(base) = attr.value() {
                            addr_base = base;
                        }
                    }
                    constants::DW_AT_loclists_base => {
                        if let AttributeValue::DebugLocListsBase(base) = attr.value() {
                            loclists_base = base;
                        }
                    }
                    constants::DW_AT_rnglists_base => {
                        if let AttributeValue::DebugRngListsBase(base) = attr.value() {
                            rnglists_base = base;
                        }
                    }
                    _ => {}
                }
            }
        }

        let line_program = match line_program_offset {
            Some(offset) => Some(dwarf.debug_line.program(
                offset,
                header.address_size(),
                comp_dir.clone(),
                name.clone(),
            )?),
            None => None,
        };

        Ok(DwarfUnit {
            header,
            abbreviations,
            name,
            comp_dir,
            low_pc,
            str_offsets_base,
            addr_base,
            loclists_base,
            rnglists_base,
            line_program,
        })
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use read::EndianSlice;
    use Endianity;

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
