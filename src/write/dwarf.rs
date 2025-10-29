use alloc::vec::Vec;

use crate::common::Encoding;
use crate::write::{
    AbbreviationTable, LineProgram, LineString, LineStringTable, Result, Sections, StringTable,
    Unit, UnitTable, Writer,
};

/// Writable DWARF information for more than one unit.
#[derive(Debug, Default)]
pub struct Dwarf {
    /// A table of units. These are primarily stored in the `.debug_info` section,
    /// but they also contain information that is stored in other sections.
    pub units: UnitTable,

    /// Extra line number programs that are not associated with a unit.
    ///
    /// These should only be used when generating DWARF5 line-only debug
    /// information.
    pub line_programs: Vec<LineProgram>,

    /// A table of strings that will be stored in the `.debug_line_str` section.
    pub line_strings: LineStringTable,

    /// A table of strings that will be stored in the `.debug_str` section.
    pub strings: StringTable,
}

impl Dwarf {
    /// Create a new `Dwarf` instance.
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Write the DWARF information to the given sections.
    pub fn write<W: Writer>(&mut self, sections: &mut Sections<W>) -> Result<()> {
        let line_strings = self.line_strings.write(&mut sections.debug_line_str)?;
        let strings = self.strings.write(&mut sections.debug_str)?;
        self.units.write(sections, &line_strings, &strings)?;
        for line_program in &self.line_programs {
            line_program.write(
                &mut sections.debug_line,
                line_program.encoding(),
                &line_strings,
                &strings,
            )?;
        }
        Ok(())
    }

    /// Get a reference to the data for a line string.
    pub fn get_line_string<'a>(&'a self, string: &'a LineString) -> &'a [u8] {
        string.get(&self.strings, &self.line_strings)
    }
}

/// Writable DWARF information for a single unit.
#[derive(Debug)]
pub struct DwarfUnit {
    /// A unit. This is primarily stored in the `.debug_info` section,
    /// but also contains information that is stored in other sections.
    pub unit: Unit,

    /// A table of strings that will be stored in the `.debug_line_str` section.
    pub line_strings: LineStringTable,

    /// A table of strings that will be stored in the `.debug_str` section.
    pub strings: StringTable,
}

impl DwarfUnit {
    /// Create a new `DwarfUnit`.
    ///
    /// Note: you should set `self.unit.line_program` after creation.
    /// This cannot be done earlier because it may need to reference
    /// `self.line_strings`.
    pub fn new(encoding: Encoding) -> Self {
        let unit = Unit::new(encoding, LineProgram::none());
        DwarfUnit {
            unit,
            line_strings: LineStringTable::default(),
            strings: StringTable::default(),
        }
    }

    /// Write the DWARf information to the given sections.
    pub fn write<W: Writer>(&mut self, sections: &mut Sections<W>) -> Result<()> {
        let line_strings = self.line_strings.write(&mut sections.debug_line_str)?;
        let strings = self.strings.write(&mut sections.debug_str)?;

        let abbrev_offset = sections.debug_abbrev.offset();
        let mut abbrevs = AbbreviationTable::default();

        self.unit.write(
            sections,
            abbrev_offset,
            &mut abbrevs,
            &line_strings,
            &strings,
        )?;
        // None should exist because we didn't give out any UnitId.
        assert!(sections.debug_info_fixups.is_empty());
        assert!(sections.debug_loc_fixups.is_empty());
        assert!(sections.debug_loclists_fixups.is_empty());

        abbrevs.write(&mut sections.debug_abbrev)?;
        Ok(())
    }

    /// Get a reference to the data for a line string.
    pub fn get_line_string<'a>(&'a self, string: &'a LineString) -> &'a [u8] {
        string.get(&self.strings, &self.line_strings)
    }
}

#[cfg(feature = "read")]
pub(crate) mod convert {
    use super::*;
    use crate::common::LineEncoding;
    use crate::read::{self, Reader};
    use crate::write::{
        Address, ConvertLineProgram, ConvertResult, ConvertUnitSection, FilterUnitSection,
    };

    impl Dwarf {
        /// Create a `write::Dwarf` by converting a `read::Dwarf`.
        ///
        /// `convert_address` is a function to convert read addresses into the `Address`
        /// type. For non-relocatable addresses, this function may simply return
        /// `Address::Constant(address)`. For relocatable addresses, it is the caller's
        /// responsibility to determine the symbol and addend corresponding to the address
        /// and return `Address::Symbol { symbol, addend }`.
        ///
        /// `convert_address` should not be used for complex address transformations, as it
        /// will not be called for address offsets (such as in `DW_AT_high_pc`, line programs,
        /// location lists, or range lists).
        ///
        /// ## Example
        ///
        /// Convert a DWARF section using `Dwarf::from`.
        ///
        /// ```rust,no_run
        /// # fn example() -> Result<(), gimli::write::ConvertError> {
        /// # let loader = |name| -> Result<gimli::EndianSlice<gimli::RunTimeEndian>, gimli::Error> { unimplemented!() };
        /// let read_dwarf = gimli::read::Dwarf::load(loader)?;
        /// let write_dwarf = gimli::write::Dwarf::from(
        ///     &read_dwarf,
        ///     &|address| Some(gimli::write::Address::Constant(address)),
        /// )?;
        /// # unreachable!()
        /// # }
        /// ```
        pub fn from<R: Reader<Offset = usize>>(
            from_dwarf: &read::Dwarf<R>,
            convert_address: &dyn Fn(u64) -> Option<Address>,
        ) -> ConvertResult<Dwarf> {
            let mut dwarf = Dwarf::default();
            let mut convert = dwarf.convert(from_dwarf, None)?;
            while let Some((mut unit, root_entry)) = convert.read_unit()? {
                if let Some(convert_program) = unit.read_line_program(None, None)? {
                    let (program, files) = convert_program.convert_all(convert_address)?;
                    unit.set_line_program(program, files);
                }
                unit.convert_attributes(unit.unit.root(), &root_entry, convert_address)?;
                while let Some((id, entry)) = unit.read_entry()? {
                    if id.is_none() {
                        continue;
                    }
                    let id = unit.add_entry(id, &entry);
                    unit.convert_attributes(id, &entry, convert_address)?;
                }
            }
            // TODO: convert the line programs that were not referenced by a unit.
            Ok(dwarf)
        }

        /// Create a converter for all units in the `.debug_info` section of the given
        /// DWARF object.
        ///
        /// `encoding` applies to the converted units, and may be different from the
        /// source unit. If `None`, the encoding from the source unit is used.
        ///
        /// ## Example
        ///
        /// Convert a DWARF section using `convert`.
        /// See [`ConvertUnit`](crate::write::ConvertUnit) for an example of the unit
        /// conversion.
        ///
        /// ```rust,no_run
        /// # fn example() -> Result<(), gimli::write::ConvertError> {
        /// # let loader = |name| -> Result<gimli::EndianSlice<gimli::RunTimeEndian>, gimli::Error> { unimplemented!() };
        /// let read_dwarf = gimli::read::Dwarf::load(loader)?;
        /// let mut write_dwarf = gimli::write::Dwarf::new();
        /// let mut convert = write_dwarf.convert(&read_dwarf, None)?;
        /// while let Some((mut unit, root_entry)) = convert.read_unit()? {
        ///     // Now you can convert the root DIE attributes, and other DIEs.
        /// }
        /// # unreachable!()
        /// # }
        /// ```
        // TODO: specify `encoding` per unit instead?
        pub fn convert<'a, R: Reader<Offset = usize>>(
            &'a mut self,
            dwarf: &'a read::Dwarf<R>,
            encoding: Option<Encoding>,
        ) -> ConvertResult<ConvertUnitSection<'a, R>> {
            ConvertUnitSection::new(dwarf, self, encoding)
        }

        /// Create a converter for some of the DIEs in the `.debug_info` section of the
        /// given DWARF object.
        ///
        /// `filter` determines which DIEs are converted. This can be created using
        /// [`FilterUnitSection::new`].
        ///
        /// `encoding` applies to the converted units, and may be different from the
        /// source unit. If `None`, the encoding from the source unit is used.
        ///
        /// ## Example
        ///
        /// Convert a DWARF section using `convert_with_filter`.
        /// See [`ConvertUnit`](crate::write::ConvertUnit) for an example of the unit
        /// conversion.
        ///
        /// ```rust,no_run
        /// # fn example() -> Result<(), gimli::write::ConvertError> {
        /// # let loader = |name| -> Result<gimli::EndianSlice<gimli::RunTimeEndian>, gimli::Error> { unimplemented!() };
        /// # let need_entry = &|entry: &gimli::write::FilterUnitEntry<_>| -> Result<bool, gimli::write::ConvertError> { Ok(false) };
        /// let read_dwarf = gimli::read::Dwarf::load(loader)?;
        /// let mut filter = gimli::write::FilterUnitSection::new(&read_dwarf)?;
        /// while let Some(mut unit) = filter.read_unit()? {
        ///     while let Some(entry) = unit.read_entry()? {
        ///         if need_entry(&entry)? {
        ///             unit.require_entry(entry.offset);
        ///         }
        ///     }
        /// }
        /// let mut write_dwarf = gimli::write::Dwarf::new();
        /// let mut convert = write_dwarf.convert_with_filter(filter, None)?;
        /// while let Some((mut unit, root_entry)) = convert.read_unit()? {
        ///     // Now you can convert the root DIE attributes, and other DIEs.
        /// }
        /// # unreachable!()
        /// # }
        /// ```
        pub fn convert_with_filter<'a, R: Reader<Offset = usize>>(
            &'a mut self,
            filter: FilterUnitSection<'a, R>,
            encoding: Option<Encoding>,
        ) -> ConvertResult<ConvertUnitSection<'a, R>> {
            ConvertUnitSection::new_with_filter(self, filter, encoding)
        }

        /// Start a new conversion of a line number program.
        ///
        /// This is intended for line number programs that do not have an associated
        /// [`read::Unit`]. If the line number program has an associated [`read::Unit`]
        /// that you are converting, then you should use
        /// [`ConvertUnit::read_line_program`](crate::write::ConvertUnit::read_line_program)
        /// instead.
        ///
        /// `encoding` and `line_encoding` apply to the converted program, and
        /// may be different from the source program. If `None`, the encoding from
        /// the source program is used.
        ///
        /// See [`ConvertLineProgram`] for an example.
        pub fn read_line_program<'a, R: Reader<Offset = usize>>(
            &'a mut self,
            dwarf: &'a read::Dwarf<R>,
            program: read::IncompleteLineProgram<R>,
            encoding: Option<Encoding>,
            line_encoding: Option<LineEncoding>,
        ) -> ConvertResult<ConvertLineProgram<'a, R>> {
            ConvertLineProgram::new(
                dwarf,
                program,
                None,
                encoding,
                line_encoding,
                &mut self.line_strings,
                &mut self.strings,
            )
        }
    }
}
