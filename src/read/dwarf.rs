use constants;
use read::{
    Abbreviations, AttributeValue, CompilationUnitHeader, CompilationUnitHeadersIter, DebugAbbrev,
    DebugAddr, DebugInfo, DebugLine, DebugLineStr, DebugStr, DebugStrOffsets, DebugTypes, Error,
    IncompleteLineProgram, LocationLists, RangeLists, Reader, Result, TypeUnitHeader,
    TypeUnitHeadersIter,
};
use Endianity;

/// All of the commonly used DWARF sections, and other common information.
// Endian is a type parameter so that we avoid invariance problems.
#[derive(Debug, Default)]
pub struct Dwarf<R, Endian>
where
    R: Reader<Endian = Endian>,
    Endian: Endianity,
{
    /// The endianity of bytes that are read.
    pub endian: Endian,

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

impl<R, Endian> Dwarf<R, Endian>
where
    R: Reader<Endian = Endian>,
    Endian: Endianity,
{
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

    /// Return the line number program for a unit.
    pub fn line_program(
        &self,
        unit: &CompilationUnitHeader<R, R::Offset>,
        abbrevs: &Abbreviations,
    ) -> Result<Option<IncompleteLineProgram<R, R::Offset>>> {
        let mut cursor = unit.entries(abbrevs);
        cursor.next_dfs()?;
        let root = cursor.current().ok_or(Error::MissingUnitDie)?;
        let offset = match root.attr_value(constants::DW_AT_stmt_list)? {
            Some(AttributeValue::DebugLineRef(offset)) => offset,
            Some(_) => return Err(Error::UnsupportedAttributeForm),
            None => return Ok(None),
        };
        let comp_dir = root.attr_value(constants::DW_AT_comp_dir)?;
        let comp_name = root.attr_value(constants::DW_AT_name)?;
        self.debug_line
            .program(offset, unit.address_size(), comp_dir, comp_name)
            .map(Option::Some)
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
    ///
    /// then return the attribute's string value. Returns an error if the attribute
    /// value does not have a string form, or if a string form has an invalid value.
    // TODO: handle `DW_FORM_strx`, but that requires knowing the DebugStrOffsetsBase
    pub fn attr_string(&self, attr: AttributeValue<R, R::Offset>) -> Result<R> {
        match attr {
            AttributeValue::String(string) => Ok(string),
            AttributeValue::DebugStrRef(offset) => self.debug_str.get_str(offset),
            AttributeValue::DebugStrRefSup(offset) => self.debug_str_sup.get_str(offset),
            AttributeValue::DebugLineStrRef(offset) => self.debug_line_str.get_str(offset),
            _ => Err(Error::ExpectedStringAttributeValue),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use read::EndianSlice;

    /// Ensure that `Dwarf<R, Endian>` is covariant wrt R.
    #[test]
    fn test_dwarf_variance() {
        /// This only needs to compile.
        #[allow(dead_code)]
        fn f<'a: 'b, 'b, E: Endianity>(
            x: Dwarf<EndianSlice<'a, E>, E>,
        ) -> Dwarf<EndianSlice<'b, E>, E> {
            x
        }
    }
}
