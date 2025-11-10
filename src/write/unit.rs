use alloc::vec::Vec;
use std::ops::{Deref, DerefMut};
use std::slice;

use crate::common::{
    DebugAbbrevOffset, DebugInfoOffset, DebugLineOffset, DebugMacinfoOffset, DebugMacroOffset,
    DebugStrOffset, DebugTypeSignature, Encoding, Format, SectionId,
};
use crate::constants;
use crate::leb128::write::{sleb128_size, uleb128_size};
use crate::write::{
    Abbreviation, AbbreviationTable, Address, AttributeSpecification, BaseId, Error, Expression,
    FileId, LineProgram, LineStringId, LineStringTable, LocationListId, LocationListOffsets,
    LocationListTable, RangeListId, RangeListOffsets, RangeListTable, Result, Section, Sections,
    StringId, StringTable, Writer,
};

define_id!(UnitId, "An identifier for a unit in a `UnitTable`.");

define_id!(UnitEntryId, "An identifier for an entry in a `Unit`.");

/// A table of units that will be stored in the `.debug_info` section.
#[derive(Debug, Default)]
pub struct UnitTable {
    base_id: BaseId,
    units: Vec<Unit>,
}

impl UnitTable {
    /// Create a new unit and add it to the table.
    ///
    /// `address_size` must be in bytes.
    ///
    /// Returns the `UnitId` of the new unit.
    #[inline]
    pub fn add(&mut self, unit: Unit) -> UnitId {
        let id = UnitId::new(self.base_id, self.units.len());
        self.units.push(unit);
        id
    }

    /// Return the number of units.
    #[inline]
    pub fn count(&self) -> usize {
        self.units.len()
    }

    /// Return the id of a unit.
    ///
    /// # Panics
    ///
    /// Panics if `index >= self.count()`.
    #[inline]
    pub fn id(&self, index: usize) -> UnitId {
        assert!(index < self.count());
        UnitId::new(self.base_id, index)
    }

    /// Get a reference to a unit.
    ///
    /// # Panics
    ///
    /// Panics if `id` is invalid.
    #[inline]
    pub fn get(&self, id: UnitId) -> &Unit {
        debug_assert_eq!(self.base_id, id.base_id);
        &self.units[id.index]
    }

    /// Get a mutable reference to a unit.
    ///
    /// # Panics
    ///
    /// Panics if `id` is invalid.
    #[inline]
    pub fn get_mut(&mut self, id: UnitId) -> &mut Unit {
        debug_assert_eq!(self.base_id, id.base_id);
        &mut self.units[id.index]
    }

    /// Get an iterator for the units.
    pub fn iter(&self) -> impl Iterator<Item = (UnitId, &Unit)> {
        self.units
            .iter()
            .enumerate()
            .map(move |(index, unit)| (UnitId::new(self.base_id, index), unit))
    }

    /// Get a mutable iterator for the units.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (UnitId, &mut Unit)> {
        let base_id = self.base_id;
        self.units
            .iter_mut()
            .enumerate()
            .map(move |(index, unit)| (UnitId::new(base_id, index), unit))
    }

    /// Write the units to the given sections.
    pub fn write<W: Writer>(
        &mut self,
        sections: &mut Sections<W>,
        line_strings: &mut LineStringTable,
        strings: &mut StringTable,
    ) -> Result<()> {
        for unit in &mut self.units {
            if unit.written {
                continue;
            }

            // TODO: maybe share abbreviation tables
            let abbrev_offset = sections.debug_abbrev.offset();
            let mut abbrevs = AbbreviationTable::default();

            unit.write(sections, abbrev_offset, &mut abbrevs, line_strings, strings)?;

            abbrevs.write(&mut sections.debug_abbrev)?;
        }

        self.write_debug_info_fixups(&mut sections.debug_info_fixups, &mut sections.debug_info.0)?;
        self.write_debug_info_fixups(&mut sections.debug_loc_fixups, &mut sections.debug_loc.0)?;
        self.write_debug_info_fixups(
            &mut sections.debug_loclists_fixups,
            &mut sections.debug_loclists.0,
        )?;

        Ok(())
    }

    fn write_debug_info_fixups<W: Writer>(
        &self,
        fixups: &mut Vec<DebugInfoFixup>,
        w: &mut W,
    ) -> Result<()> {
        for fixup in fixups.drain(..) {
            debug_assert_eq!(self.base_id, fixup.unit.base_id);
            let entry_offset = self.units[fixup.unit.index]
                .offsets
                .debug_info_offset(fixup.entry)
                .ok_or(Error::InvalidReference)?
                .0;
            w.write_offset_at(fixup.offset, entry_offset, SectionId::DebugInfo, fixup.size)?;
        }
        Ok(())
    }
}

/// A unit's debugging information.
#[derive(Debug)]
pub struct Unit {
    base_id: BaseId,
    /// The encoding parameters for this unit.
    encoding: Encoding,
    /// The line number program for this unit.
    pub line_program: LineProgram,
    /// A table of range lists used by this unit.
    pub ranges: RangeListTable,
    /// A table of location lists used by this unit.
    pub locations: LocationListTable,
    /// All entries in this unit. The order is unrelated to the tree order.
    // Requirements:
    // - entries form a tree
    // - entries can be added in any order
    // - entries have a fixed id
    // - able to quickly lookup an entry from its id
    // Limitations of current implementation:
    // - mutable iteration of children is messy due to borrow checker
    entries: Vec<DebuggingInformationEntry>,
    /// The index of the root entry in entries.
    root: UnitEntryId,
    /// The unit has been written to the output sections.
    written: bool,
    /// The section offsets for the unit and DIEs after being written.
    offsets: UnitOffsets,
}

impl Unit {
    /// Create a new `Unit`.
    pub fn new(encoding: Encoding, line_program: LineProgram) -> Self {
        let base_id = BaseId::default();
        let ranges = RangeListTable::default();
        let locations = LocationListTable::default();
        let mut entries = Vec::new();
        let root = DebuggingInformationEntry::new(
            base_id,
            &mut entries,
            None,
            constants::DW_TAG_compile_unit,
        );
        let offsets = UnitOffsets {
            base_id,
            unit: DebugInfoOffset(!0),
            entries: Vec::new(),
        };
        Unit {
            base_id,
            encoding,
            line_program,
            ranges,
            locations,
            entries,
            root,
            written: false,
            offsets,
        }
    }

    /// Set the encoding parameters for this unit.
    #[inline]
    pub fn set_encoding(&mut self, encoding: Encoding) {
        self.encoding = encoding;
    }

    /// Return the encoding parameters for this unit.
    #[inline]
    pub fn encoding(&self) -> Encoding {
        self.encoding
    }

    /// Return the DWARF version for this unit.
    #[inline]
    pub fn version(&self) -> u16 {
        self.encoding.version
    }

    /// Return the address size in bytes for this unit.
    #[inline]
    pub fn address_size(&self) -> u8 {
        self.encoding.address_size
    }

    /// Return the DWARF format for this unit.
    #[inline]
    pub fn format(&self) -> Format {
        self.encoding.format
    }

    /// Return the number of `DebuggingInformationEntry`s created for this unit.
    ///
    /// This includes entries that no longer have a parent.
    #[inline]
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    /// Return the id of the root entry.
    #[inline]
    pub fn root(&self) -> UnitEntryId {
        self.root
    }

    /// Reserve a `DebuggingInformationEntry` in this unit and return its id.
    ///
    /// The id should be later passed to [`Self::add_reserved`].
    ///
    /// This method is useful when you need an id to use for a reference to the
    /// DIE prior to adding it.
    pub fn reserve(&mut self) -> UnitEntryId {
        DebuggingInformationEntry::new(
            self.base_id,
            &mut self.entries,
            None,
            constants::DW_TAG_null,
        )
    }

    /// Set the parent and tag of a previously reserved `DebuggingInformationEntry`.
    ///
    /// The `parent` must be within the same unit.
    ///
    /// # Panics
    ///
    /// Panics if `child` or `parent` is invalid, or if `child` is not a reserved entry.
    pub fn add_reserved(&mut self, child: UnitEntryId, parent: UnitEntryId, tag: constants::DwTag) {
        let entry = self.get_mut(child);
        debug_assert_eq!(entry.parent, None);
        debug_assert_eq!(entry.tag, constants::DW_TAG_null);
        entry.parent = Some(parent);
        entry.tag = tag;
        self.get_mut(parent).children.push(child);
    }

    /// Add a new `DebuggingInformationEntry` to this unit and return its id.
    ///
    /// The `parent` must be within the same unit.
    ///
    /// # Panics
    ///
    /// Panics if `parent` is invalid.
    #[inline]
    pub fn add(&mut self, parent: UnitEntryId, tag: constants::DwTag) -> UnitEntryId {
        debug_assert_eq!(self.base_id, parent.base_id);
        DebuggingInformationEntry::new(self.base_id, &mut self.entries, Some(parent), tag)
    }

    /// Get a reference to an entry.
    ///
    /// # Panics
    ///
    /// Panics if `id` is invalid.
    #[inline]
    pub fn get(&self, id: UnitEntryId) -> &DebuggingInformationEntry {
        debug_assert_eq!(self.base_id, id.base_id);
        &self.entries[id.index]
    }

    /// Get a mutable reference to an entry.
    ///
    /// # Panics
    ///
    /// Panics if `id` is invalid.
    #[inline]
    pub fn get_mut(&mut self, id: UnitEntryId) -> &mut DebuggingInformationEntry {
        debug_assert_eq!(self.base_id, id.base_id);
        &mut self.entries[id.index]
    }

    /// Return true if `self.line_program` is used by a DIE.
    fn line_program_in_use(&self) -> bool {
        if self.line_program.is_none() {
            return false;
        }
        if !self.line_program.is_empty() {
            return true;
        }

        for entry in &self.entries {
            for attr in &entry.attrs {
                if let AttributeValue::FileIndex(Some(_)) = attr.value {
                    return true;
                }
            }
        }

        false
    }

    /// Write the unit to the given sections.
    pub(crate) fn write<W: Writer>(
        &mut self,
        sections: &mut Sections<W>,
        abbrev_offset: DebugAbbrevOffset,
        abbrevs: &mut AbbreviationTable,
        line_strings: &mut LineStringTable,
        strings: &mut StringTable,
    ) -> Result<()> {
        debug_assert!(!self.written);

        let line_program = if self.line_program_in_use() {
            self.entries[self.root.index]
                .set(constants::DW_AT_stmt_list, AttributeValue::LineProgramRef);
            Some(self.line_program.write(
                &mut sections.debug_line,
                self.encoding,
                line_strings,
                strings,
            )?)
        } else {
            self.entries[self.root.index].delete(constants::DW_AT_stmt_list);
            None
        };

        // TODO: use .debug_types for type units in DWARF v4.
        let w = &mut sections.debug_info;

        let mut offsets = UnitOffsets {
            base_id: self.base_id,
            unit: w.offset(),
            // Entries can be written in any order, so create the complete vec now.
            entries: vec![DebugInfoOffset(0); self.entries.len()],
        };

        let length_offset = w.write_initial_length(self.format())?;
        let length_base = w.len();

        w.write_u16(self.version())?;
        if 2 <= self.version() && self.version() <= 4 {
            w.write_offset(
                abbrev_offset.0,
                SectionId::DebugAbbrev,
                self.format().word_size(),
            )?;
            w.write_u8(self.address_size())?;
        } else if self.version() == 5 {
            w.write_u8(constants::DW_UT_compile.0)?;
            w.write_u8(self.address_size())?;
            w.write_offset(
                abbrev_offset.0,
                SectionId::DebugAbbrev,
                self.format().word_size(),
            )?;
        } else {
            return Err(Error::UnsupportedVersion(self.version()));
        }

        // Calculate all DIE offsets, so that we are able to output references to them.
        // However, references to base types in expressions use ULEB128, so base types
        // must be moved to the front before we can calculate offsets.
        self.reorder_base_types();
        let mut codes = vec![0; self.entries.len()];
        let mut offset = w.len();
        self.entries[self.root.index].calculate_offsets(
            self,
            &mut offset,
            &mut offsets,
            abbrevs,
            &mut codes,
        )?;

        let range_lists = self.ranges.write(sections, self.encoding)?;
        // Location lists can't be written until we have DIE offsets.
        let loc_lists = self
            .locations
            .write(sections, self.encoding, Some(&offsets))?;

        let w = &mut sections.debug_info;
        let mut unit_refs = Vec::new();
        self.entries[self.root.index].write(
            w,
            &mut sections.debug_info_fixups,
            &mut unit_refs,
            self,
            &offsets,
            &codes,
            line_program,
            line_strings,
            strings,
            &range_lists,
            &loc_lists,
        )?;

        let length = (w.len() - length_base) as u64;
        w.write_initial_length_at(length_offset, length, self.format())?;

        for (offset, entry) in unit_refs {
            // This does not need relocation.
            w.write_udata_at(
                offset.0,
                offsets.unit_offset(entry).ok_or(Error::InvalidReference)?,
                self.format().word_size(),
            )?;
        }

        self.offsets = offsets;
        self.written = true;
        Ok(())
    }

    fn skip(&mut self) {
        self.written = true;
    }

    fn free(&mut self) {
        self.line_program = LineProgram::none();
        self.ranges = RangeListTable::default();
        self.locations = LocationListTable::default();
        self.entries = Vec::new();
    }

    /// Reorder base types to come first so that typed stack operations
    /// can get their offset.
    fn reorder_base_types(&mut self) {
        let root = &self.entries[self.root.index];
        let mut root_children = Vec::with_capacity(root.children.len());
        for entry in &root.children {
            if self.entries[entry.index].tag == constants::DW_TAG_base_type {
                root_children.push(*entry);
            }
        }
        for entry in &root.children {
            if self.entries[entry.index].tag != constants::DW_TAG_base_type {
                root_children.push(*entry);
            }
        }
        self.entries[self.root.index].children = root_children;
    }
}

/// A Debugging Information Entry (DIE).
///
/// DIEs have a set of attributes and optionally have children DIEs as well.
///
/// DIEs form a tree without any cycles. This is enforced by specifying the
/// parent when creating a DIE, and disallowing changes of parent.
#[derive(Debug)]
pub struct DebuggingInformationEntry {
    id: UnitEntryId,
    parent: Option<UnitEntryId>,
    tag: constants::DwTag,
    /// Whether to emit `DW_AT_sibling`.
    sibling: bool,
    attrs: Vec<Attribute>,
    children: Vec<UnitEntryId>,
}

impl DebuggingInformationEntry {
    /// Create a new `DebuggingInformationEntry`.
    ///
    /// # Panics
    ///
    /// Panics if `parent` is invalid.
    #[allow(clippy::new_ret_no_self)]
    fn new(
        base_id: BaseId,
        entries: &mut Vec<DebuggingInformationEntry>,
        parent: Option<UnitEntryId>,
        tag: constants::DwTag,
    ) -> UnitEntryId {
        let id = UnitEntryId::new(base_id, entries.len());
        entries.push(DebuggingInformationEntry {
            id,
            parent,
            tag,
            sibling: false,
            attrs: Vec::new(),
            children: Vec::new(),
        });
        if let Some(parent) = parent {
            debug_assert_eq!(base_id, parent.base_id);
            assert_ne!(parent, id);
            entries[parent.index].children.push(id);
        }
        id
    }

    /// Return the id of this entry.
    #[inline]
    pub fn id(&self) -> UnitEntryId {
        self.id
    }

    /// Return the parent of this entry.
    #[inline]
    pub fn parent(&self) -> Option<UnitEntryId> {
        self.parent
    }

    /// Return the tag of this entry.
    #[inline]
    pub fn tag(&self) -> constants::DwTag {
        self.tag
    }

    /// Return `true` if a `DW_AT_sibling` attribute will be emitted.
    #[inline]
    pub fn sibling(&self) -> bool {
        self.sibling
    }

    /// Set whether a `DW_AT_sibling` attribute will be emitted.
    ///
    /// The attribute will only be emitted if the DIE has children.
    #[inline]
    pub fn set_sibling(&mut self, sibling: bool) {
        self.sibling = sibling;
    }

    /// Iterate over the attributes of this entry.
    #[inline]
    pub fn attrs(&self) -> slice::Iter<'_, Attribute> {
        self.attrs.iter()
    }

    /// Iterate over the attributes of this entry for modification.
    #[inline]
    pub fn attrs_mut(&mut self) -> slice::IterMut<'_, Attribute> {
        self.attrs.iter_mut()
    }

    /// Get an attribute.
    pub fn get(&self, name: constants::DwAt) -> Option<&AttributeValue> {
        self.attrs
            .iter()
            .find(|attr| attr.name == name)
            .map(|attr| &attr.value)
    }

    /// Get an attribute for modification.
    pub fn get_mut(&mut self, name: constants::DwAt) -> Option<&mut AttributeValue> {
        self.attrs
            .iter_mut()
            .find(|attr| attr.name == name)
            .map(|attr| &mut attr.value)
    }

    /// Set an attribute.
    ///
    /// Replaces any existing attribute with the same name.
    ///
    /// # Panics
    ///
    /// Panics if `name` is `DW_AT_sibling`. Use `set_sibling` instead.
    pub fn set(&mut self, name: constants::DwAt, value: AttributeValue) {
        assert_ne!(name, constants::DW_AT_sibling);
        if let Some(attr) = self.attrs.iter_mut().find(|attr| attr.name == name) {
            attr.value = value;
            return;
        }
        self.attrs.push(Attribute { name, value });
    }

    /// Delete an attribute.
    ///
    /// Replaces any existing attribute with the same name.
    pub fn delete(&mut self, name: constants::DwAt) {
        self.attrs.retain(|x| x.name != name);
    }

    /// Iterate over the children of this entry.
    ///
    /// Note: use `Unit::add` to add a new child to this entry.
    #[inline]
    pub fn children(&self) -> slice::Iter<'_, UnitEntryId> {
        self.children.iter()
    }

    /// Delete a child entry and all of its children.
    pub fn delete_child(&mut self, id: UnitEntryId) {
        self.children.retain(|&child| child != id);
    }

    /// Return the type abbreviation for this DIE.
    fn abbreviation(&self, encoding: Encoding) -> Result<Abbreviation> {
        let mut attrs = Vec::new();

        if self.sibling && !self.children.is_empty() {
            let form = match encoding.format {
                Format::Dwarf32 => constants::DW_FORM_ref4,
                Format::Dwarf64 => constants::DW_FORM_ref8,
            };
            attrs.push(AttributeSpecification::new(constants::DW_AT_sibling, form));
        }

        for attr in &self.attrs {
            attrs.push(attr.specification(encoding)?);
        }

        Ok(Abbreviation::new(
            self.tag,
            !self.children.is_empty(),
            attrs,
        ))
    }

    fn calculate_offsets(
        &self,
        unit: &Unit,
        offset: &mut usize,
        offsets: &mut UnitOffsets,
        abbrevs: &mut AbbreviationTable,
        codes: &mut [u64],
    ) -> Result<()> {
        offsets.entries[self.id.index] = DebugInfoOffset(*offset);
        let code = abbrevs.add(self.abbreviation(unit.encoding())?);
        codes[self.id.index] = code;
        *offset += self.size(unit, offsets, code)?;
        if !self.children.is_empty() {
            for child in &self.children {
                unit.entries[child.index]
                    .calculate_offsets(unit, offset, offsets, abbrevs, codes)?;
            }
            // Null child
            *offset += 1;
        }
        Ok(())
    }

    fn size(&self, unit: &Unit, offsets: &UnitOffsets, code: u64) -> Result<usize> {
        let mut size = uleb128_size(code);
        if self.sibling && !self.children.is_empty() {
            size += unit.format().word_size() as usize;
        }
        for attr in &self.attrs {
            size += attr.value.size(unit, offsets)?;
        }
        Ok(size)
    }

    /// Write the entry to the given sections.
    fn write<W: Writer>(
        &self,
        w: &mut DebugInfo<W>,
        debug_info_refs: &mut Vec<DebugInfoFixup>,
        unit_refs: &mut Vec<(DebugInfoOffset, UnitEntryId)>,
        unit: &Unit,
        offsets: &UnitOffsets,
        codes: &[u64],
        line_program: Option<DebugLineOffset>,
        line_strings: &LineStringTable,
        strings: &StringTable,
        range_lists: &RangeListOffsets,
        loc_lists: &LocationListOffsets,
    ) -> Result<()> {
        debug_assert_eq!(offsets.debug_info_offset(self.id), Some(w.offset()));
        w.write_uleb128(codes[self.id.index])?;

        let sibling_offset = if self.sibling && !self.children.is_empty() {
            let offset = w.offset();
            w.write_udata(0, unit.format().word_size())?;
            Some(offset)
        } else {
            None
        };

        for attr in &self.attrs {
            attr.value.write(
                w,
                debug_info_refs,
                unit_refs,
                unit,
                offsets,
                line_program,
                line_strings,
                strings,
                range_lists,
                loc_lists,
            )?;
        }

        if !self.children.is_empty() {
            for child in &self.children {
                unit.entries[child.index].write(
                    w,
                    debug_info_refs,
                    unit_refs,
                    unit,
                    offsets,
                    codes,
                    line_program,
                    line_strings,
                    strings,
                    range_lists,
                    loc_lists,
                )?;
            }
            // Null child
            w.write_u8(0)?;
        }

        if let Some(offset) = sibling_offset {
            let next_offset = (w.offset().0 - offsets.unit.0) as u64;
            // This does not need relocation.
            w.write_udata_at(offset.0, next_offset, unit.format().word_size())?;
        }
        Ok(())
    }
}

/// An attribute in a `DebuggingInformationEntry`, consisting of a name and
/// associated value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    name: constants::DwAt,
    value: AttributeValue,
}

impl Attribute {
    /// Get the name of this attribute.
    #[inline]
    pub fn name(&self) -> constants::DwAt {
        self.name
    }

    /// Get the value of this attribute.
    #[inline]
    pub fn get(&self) -> &AttributeValue {
        &self.value
    }

    /// Set the value of this attribute.
    #[inline]
    pub fn set(&mut self, value: AttributeValue) {
        self.value = value;
    }

    /// Return the type specification for this attribute.
    fn specification(&self, encoding: Encoding) -> Result<AttributeSpecification> {
        Ok(AttributeSpecification::new(
            self.name,
            self.value.form(encoding)?,
        ))
    }
}

/// The value of an attribute in a `DebuggingInformationEntry`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttributeValue {
    /// "Refers to some location in the address space of the described program."
    Address(Address),

    /// A slice of an arbitrary number of bytes.
    Block(Vec<u8>),

    /// A one byte constant data value. How to interpret the byte depends on context.
    ///
    /// From section 7 of the standard: "Depending on context, it may be a
    /// signed integer, an unsigned integer, a floating-point constant, or
    /// anything else."
    Data1(u8),

    /// A two byte constant data value. How to interpret the bytes depends on context.
    ///
    /// This value will be converted to the target endian before writing.
    ///
    /// From section 7 of the standard: "Depending on context, it may be a
    /// signed integer, an unsigned integer, a floating-point constant, or
    /// anything else."
    Data2(u16),

    /// A four byte constant data value. How to interpret the bytes depends on context.
    ///
    /// This value will be converted to the target endian before writing.
    ///
    /// From section 7 of the standard: "Depending on context, it may be a
    /// signed integer, an unsigned integer, a floating-point constant, or
    /// anything else."
    Data4(u32),

    /// An eight byte constant data value. How to interpret the bytes depends on context.
    ///
    /// This value will be converted to the target endian before writing.
    ///
    /// From section 7 of the standard: "Depending on context, it may be a
    /// signed integer, an unsigned integer, a floating-point constant, or
    /// anything else."
    Data8(u64),

    /// An sixteen byte constant data value. How to interpret the bytes depends on context.
    ///
    /// This value will be converted to the target endian before writing.
    ///
    /// From section 7 of the standard: "Depending on context, it may be a
    /// signed integer, an unsigned integer, a floating-point constant, or
    /// anything else."
    Data16(u128),

    /// A signed integer constant.
    Sdata(i64),

    /// An unsigned integer constant.
    Udata(u64),

    /// "The information bytes contain a DWARF expression (see Section 2.5) or
    /// location description (see Section 2.6)."
    Exprloc(Expression),

    /// A boolean that indicates presence or absence of the attribute.
    Flag(bool),

    /// An attribute that is always present.
    FlagPresent,

    /// A reference to a `DebuggingInformationEntry` in this unit.
    UnitRef(UnitEntryId),

    /// A reference to a `DebuggingInformationEntry` in a potentially different unit.
    DebugInfoRef(DebugInfoRef),

    /// An offset into the `.debug_info` section of the supplementary object file.
    ///
    /// The API does not currently assist with generating this offset.
    /// This variant will be removed from the API once support for writing
    /// supplementary object files is implemented.
    DebugInfoRefSup(DebugInfoOffset),

    /// A reference to a line number program.
    LineProgramRef,

    /// A reference to a location list.
    LocationListRef(LocationListId),

    /// An offset into the `.debug_macinfo` section.
    ///
    /// The API does not currently assist with generating this offset.
    /// This variant will be removed from the API once support for writing
    /// `.debug_macinfo` sections is implemented.
    DebugMacinfoRef(DebugMacinfoOffset),

    /// An offset into the `.debug_macro` section.
    ///
    /// The API does not currently assist with generating this offset.
    /// This variant will be removed from the API once support for writing
    /// `.debug_macro` sections is implemented.
    DebugMacroRef(DebugMacroOffset),

    /// A reference to a range list.
    RangeListRef(RangeListId),

    /// A type signature.
    ///
    /// The API does not currently assist with generating this signature.
    /// This variant will be removed from the API once support for writing
    /// `.debug_types` sections is implemented.
    DebugTypesRef(DebugTypeSignature),

    /// A reference to a string in the `.debug_str` section.
    StringRef(StringId),

    /// An offset into the `.debug_str` section of the supplementary object file.
    ///
    /// The API does not currently assist with generating this offset.
    /// This variant will be removed from the API once support for writing
    /// supplementary object files is implemented.
    DebugStrRefSup(DebugStrOffset),

    /// A reference to a string in the `.debug_line_str` section.
    LineStringRef(LineStringId),

    /// A slice of bytes representing a string. Must not include null bytes.
    /// Not guaranteed to be UTF-8 or anything like that.
    String(Vec<u8>),

    /// The value of a `DW_AT_encoding` attribute.
    Encoding(constants::DwAte),

    /// The value of a `DW_AT_decimal_sign` attribute.
    DecimalSign(constants::DwDs),

    /// The value of a `DW_AT_endianity` attribute.
    Endianity(constants::DwEnd),

    /// The value of a `DW_AT_accessibility` attribute.
    Accessibility(constants::DwAccess),

    /// The value of a `DW_AT_visibility` attribute.
    Visibility(constants::DwVis),

    /// The value of a `DW_AT_virtuality` attribute.
    Virtuality(constants::DwVirtuality),

    /// The value of a `DW_AT_language` attribute.
    Language(constants::DwLang),

    /// The value of a `DW_AT_address_class` attribute.
    AddressClass(constants::DwAddr),

    /// The value of a `DW_AT_identifier_case` attribute.
    IdentifierCase(constants::DwId),

    /// The value of a `DW_AT_calling_convention` attribute.
    CallingConvention(constants::DwCc),

    /// The value of a `DW_AT_inline` attribute.
    Inline(constants::DwInl),

    /// The value of a `DW_AT_ordering` attribute.
    Ordering(constants::DwOrd),

    /// An index into the filename entries from the line number information
    /// table for the unit containing this value.
    FileIndex(Option<FileId>),
}

impl AttributeValue {
    /// Return the form that will be used to encode this value.
    pub fn form(&self, encoding: Encoding) -> Result<constants::DwForm> {
        // TODO: missing forms:
        // - DW_FORM_indirect
        // - DW_FORM_implicit_const
        // - FW_FORM_block1/block2/block4
        // - DW_FORM_str/strx1/strx2/strx3/strx4
        // - DW_FORM_addrx/addrx1/addrx2/addrx3/addrx4
        // - DW_FORM_data16
        // - DW_FORM_line_strp
        // - DW_FORM_loclistx
        // - DW_FORM_rnglistx
        let form = match *self {
            AttributeValue::Address(_) => constants::DW_FORM_addr,
            AttributeValue::Block(_) => constants::DW_FORM_block,
            AttributeValue::Data1(_) => constants::DW_FORM_data1,
            AttributeValue::Data2(_) => constants::DW_FORM_data2,
            AttributeValue::Data4(_) => constants::DW_FORM_data4,
            AttributeValue::Data8(_) => constants::DW_FORM_data8,
            AttributeValue::Data16(_) => constants::DW_FORM_data16,
            AttributeValue::Exprloc(_) => constants::DW_FORM_exprloc,
            AttributeValue::Flag(_) => constants::DW_FORM_flag,
            AttributeValue::FlagPresent => constants::DW_FORM_flag_present,
            AttributeValue::UnitRef(_) => {
                // Using a fixed size format lets us write a placeholder before we know
                // the value.
                match encoding.format {
                    Format::Dwarf32 => constants::DW_FORM_ref4,
                    Format::Dwarf64 => constants::DW_FORM_ref8,
                }
            }
            AttributeValue::DebugInfoRef(_) => constants::DW_FORM_ref_addr,
            AttributeValue::DebugInfoRefSup(_) => {
                // TODO: should this depend on the size of supplementary section?
                match encoding.format {
                    Format::Dwarf32 => constants::DW_FORM_ref_sup4,
                    Format::Dwarf64 => constants::DW_FORM_ref_sup8,
                }
            }
            AttributeValue::LineProgramRef
            | AttributeValue::LocationListRef(_)
            | AttributeValue::DebugMacinfoRef(_)
            | AttributeValue::DebugMacroRef(_)
            | AttributeValue::RangeListRef(_) => {
                if encoding.version == 2 || encoding.version == 3 {
                    match encoding.format {
                        Format::Dwarf32 => constants::DW_FORM_data4,
                        Format::Dwarf64 => constants::DW_FORM_data8,
                    }
                } else {
                    constants::DW_FORM_sec_offset
                }
            }
            AttributeValue::DebugTypesRef(_) => constants::DW_FORM_ref_sig8,
            AttributeValue::StringRef(_) => constants::DW_FORM_strp,
            AttributeValue::DebugStrRefSup(_) => constants::DW_FORM_strp_sup,
            AttributeValue::LineStringRef(_) => constants::DW_FORM_line_strp,
            AttributeValue::String(_) => constants::DW_FORM_string,
            AttributeValue::Encoding(_)
            | AttributeValue::DecimalSign(_)
            | AttributeValue::Endianity(_)
            | AttributeValue::Accessibility(_)
            | AttributeValue::Visibility(_)
            | AttributeValue::Virtuality(_)
            | AttributeValue::Language(_)
            | AttributeValue::AddressClass(_)
            | AttributeValue::IdentifierCase(_)
            | AttributeValue::CallingConvention(_)
            | AttributeValue::Inline(_)
            | AttributeValue::Ordering(_)
            | AttributeValue::FileIndex(_)
            | AttributeValue::Udata(_) => constants::DW_FORM_udata,
            AttributeValue::Sdata(_) => constants::DW_FORM_sdata,
        };
        Ok(form)
    }

    fn size(&self, unit: &Unit, offsets: &UnitOffsets) -> Result<usize> {
        macro_rules! debug_assert_form {
            ($form:expr) => {
                debug_assert_eq!(self.form(unit.encoding()).unwrap(), $form)
            };
        }
        Ok(match *self {
            AttributeValue::Address(_) => {
                debug_assert_form!(constants::DW_FORM_addr);
                unit.address_size() as usize
            }
            AttributeValue::Block(ref val) => {
                debug_assert_form!(constants::DW_FORM_block);
                uleb128_size(val.len() as u64) + val.len()
            }
            AttributeValue::Data1(_) => {
                debug_assert_form!(constants::DW_FORM_data1);
                1
            }
            AttributeValue::Data2(_) => {
                debug_assert_form!(constants::DW_FORM_data2);
                2
            }
            AttributeValue::Data4(_) => {
                debug_assert_form!(constants::DW_FORM_data4);
                4
            }
            AttributeValue::Data8(_) => {
                debug_assert_form!(constants::DW_FORM_data8);
                8
            }
            AttributeValue::Data16(_) => {
                debug_assert_form!(constants::DW_FORM_data16);
                16
            }
            AttributeValue::Sdata(val) => {
                debug_assert_form!(constants::DW_FORM_sdata);
                sleb128_size(val)
            }
            AttributeValue::Udata(val) => {
                debug_assert_form!(constants::DW_FORM_udata);
                uleb128_size(val)
            }
            AttributeValue::Exprloc(ref val) => {
                debug_assert_form!(constants::DW_FORM_exprloc);
                let size = val.size(unit.encoding(), Some(offsets))?;
                uleb128_size(size as u64) + size
            }
            AttributeValue::Flag(_) => {
                debug_assert_form!(constants::DW_FORM_flag);
                1
            }
            AttributeValue::FlagPresent => {
                debug_assert_form!(constants::DW_FORM_flag_present);
                0
            }
            AttributeValue::UnitRef(_) => {
                match unit.format() {
                    Format::Dwarf32 => debug_assert_form!(constants::DW_FORM_ref4),
                    Format::Dwarf64 => debug_assert_form!(constants::DW_FORM_ref8),
                }
                unit.format().word_size() as usize
            }
            AttributeValue::DebugInfoRef(_) => {
                debug_assert_form!(constants::DW_FORM_ref_addr);
                if unit.version() == 2 {
                    unit.address_size() as usize
                } else {
                    unit.format().word_size() as usize
                }
            }
            AttributeValue::DebugInfoRefSup(_) => {
                match unit.format() {
                    Format::Dwarf32 => debug_assert_form!(constants::DW_FORM_ref_sup4),
                    Format::Dwarf64 => debug_assert_form!(constants::DW_FORM_ref_sup8),
                }
                unit.format().word_size() as usize
            }
            AttributeValue::LineProgramRef => {
                if unit.version() >= 4 {
                    debug_assert_form!(constants::DW_FORM_sec_offset);
                }
                unit.format().word_size() as usize
            }
            AttributeValue::LocationListRef(_) => {
                if unit.version() >= 4 {
                    debug_assert_form!(constants::DW_FORM_sec_offset);
                }
                unit.format().word_size() as usize
            }
            AttributeValue::DebugMacinfoRef(_) => {
                if unit.version() >= 4 {
                    debug_assert_form!(constants::DW_FORM_sec_offset);
                }
                unit.format().word_size() as usize
            }
            AttributeValue::DebugMacroRef(_) => {
                if unit.version() >= 4 {
                    debug_assert_form!(constants::DW_FORM_sec_offset);
                }
                unit.format().word_size() as usize
            }
            AttributeValue::RangeListRef(_) => {
                if unit.version() >= 4 {
                    debug_assert_form!(constants::DW_FORM_sec_offset);
                }
                unit.format().word_size() as usize
            }
            AttributeValue::DebugTypesRef(_) => {
                debug_assert_form!(constants::DW_FORM_ref_sig8);
                8
            }
            AttributeValue::StringRef(_) => {
                debug_assert_form!(constants::DW_FORM_strp);
                unit.format().word_size() as usize
            }
            AttributeValue::DebugStrRefSup(_) => {
                debug_assert_form!(constants::DW_FORM_strp_sup);
                unit.format().word_size() as usize
            }
            AttributeValue::LineStringRef(_) => {
                debug_assert_form!(constants::DW_FORM_line_strp);
                unit.format().word_size() as usize
            }
            AttributeValue::String(ref val) => {
                debug_assert_form!(constants::DW_FORM_string);
                val.len() + 1
            }
            AttributeValue::Encoding(val) => {
                debug_assert_form!(constants::DW_FORM_udata);
                uleb128_size(val.0 as u64)
            }
            AttributeValue::DecimalSign(val) => {
                debug_assert_form!(constants::DW_FORM_udata);
                uleb128_size(val.0 as u64)
            }
            AttributeValue::Endianity(val) => {
                debug_assert_form!(constants::DW_FORM_udata);
                uleb128_size(val.0 as u64)
            }
            AttributeValue::Accessibility(val) => {
                debug_assert_form!(constants::DW_FORM_udata);
                uleb128_size(val.0 as u64)
            }
            AttributeValue::Visibility(val) => {
                debug_assert_form!(constants::DW_FORM_udata);
                uleb128_size(val.0 as u64)
            }
            AttributeValue::Virtuality(val) => {
                debug_assert_form!(constants::DW_FORM_udata);
                uleb128_size(val.0 as u64)
            }
            AttributeValue::Language(val) => {
                debug_assert_form!(constants::DW_FORM_udata);
                uleb128_size(val.0 as u64)
            }
            AttributeValue::AddressClass(val) => {
                debug_assert_form!(constants::DW_FORM_udata);
                uleb128_size(val.0)
            }
            AttributeValue::IdentifierCase(val) => {
                debug_assert_form!(constants::DW_FORM_udata);
                uleb128_size(val.0 as u64)
            }
            AttributeValue::CallingConvention(val) => {
                debug_assert_form!(constants::DW_FORM_udata);
                uleb128_size(val.0 as u64)
            }
            AttributeValue::Inline(val) => {
                debug_assert_form!(constants::DW_FORM_udata);
                uleb128_size(val.0 as u64)
            }
            AttributeValue::Ordering(val) => {
                debug_assert_form!(constants::DW_FORM_udata);
                uleb128_size(val.0 as u64)
            }
            AttributeValue::FileIndex(val) => {
                debug_assert_form!(constants::DW_FORM_udata);
                uleb128_size(val.map(|id| id.raw(unit.version())).unwrap_or(0))
            }
        })
    }

    /// Write the attribute value to the given sections.
    fn write<W: Writer>(
        &self,
        w: &mut DebugInfo<W>,
        debug_info_refs: &mut Vec<DebugInfoFixup>,
        unit_refs: &mut Vec<(DebugInfoOffset, UnitEntryId)>,
        unit: &Unit,
        offsets: &UnitOffsets,
        line_program: Option<DebugLineOffset>,
        line_strings: &LineStringTable,
        strings: &StringTable,
        range_lists: &RangeListOffsets,
        loc_lists: &LocationListOffsets,
    ) -> Result<()> {
        macro_rules! debug_assert_form {
            ($form:expr) => {
                debug_assert_eq!(self.form(unit.encoding()).unwrap(), $form)
            };
        }
        match *self {
            AttributeValue::Address(val) => {
                debug_assert_form!(constants::DW_FORM_addr);
                w.write_address(val, unit.address_size())?;
            }
            AttributeValue::Block(ref val) => {
                debug_assert_form!(constants::DW_FORM_block);
                w.write_uleb128(val.len() as u64)?;
                w.write(val)?;
            }
            AttributeValue::Data1(val) => {
                debug_assert_form!(constants::DW_FORM_data1);
                w.write_u8(val)?;
            }
            AttributeValue::Data2(val) => {
                debug_assert_form!(constants::DW_FORM_data2);
                w.write_u16(val)?;
            }
            AttributeValue::Data4(val) => {
                debug_assert_form!(constants::DW_FORM_data4);
                w.write_u32(val)?;
            }
            AttributeValue::Data8(val) => {
                debug_assert_form!(constants::DW_FORM_data8);
                w.write_u64(val)?;
            }
            AttributeValue::Data16(val) => {
                debug_assert_form!(constants::DW_FORM_data16);
                w.write_u128(val)?;
            }
            AttributeValue::Sdata(val) => {
                debug_assert_form!(constants::DW_FORM_sdata);
                w.write_sleb128(val)?;
            }
            AttributeValue::Udata(val) => {
                debug_assert_form!(constants::DW_FORM_udata);
                w.write_uleb128(val)?;
            }
            AttributeValue::Exprloc(ref val) => {
                debug_assert_form!(constants::DW_FORM_exprloc);
                w.write_uleb128(val.size(unit.encoding(), Some(offsets))? as u64)?;
                val.write(
                    &mut w.0,
                    Some(debug_info_refs),
                    unit.encoding(),
                    Some(offsets),
                )?;
            }
            AttributeValue::Flag(val) => {
                debug_assert_form!(constants::DW_FORM_flag);
                w.write_u8(val as u8)?;
            }
            AttributeValue::FlagPresent => {
                debug_assert_form!(constants::DW_FORM_flag_present);
            }
            AttributeValue::UnitRef(id) => {
                match unit.format() {
                    Format::Dwarf32 => debug_assert_form!(constants::DW_FORM_ref4),
                    Format::Dwarf64 => debug_assert_form!(constants::DW_FORM_ref8),
                }
                unit_refs.push((w.offset(), id));
                w.write_udata(0, unit.format().word_size())?;
            }
            AttributeValue::DebugInfoRef(reference) => {
                debug_assert_form!(constants::DW_FORM_ref_addr);
                let size = if unit.version() == 2 {
                    unit.address_size()
                } else {
                    unit.format().word_size()
                };
                match reference {
                    DebugInfoRef::Symbol(symbol) => w.write_reference(symbol, size)?,
                    DebugInfoRef::Entry(unit, entry) => {
                        debug_info_refs.push(DebugInfoFixup {
                            offset: w.len(),
                            unit,
                            entry,
                            size,
                        });
                        w.write_udata(0, size)?;
                    }
                }
            }
            AttributeValue::DebugInfoRefSup(val) => {
                match unit.format() {
                    Format::Dwarf32 => debug_assert_form!(constants::DW_FORM_ref_sup4),
                    Format::Dwarf64 => debug_assert_form!(constants::DW_FORM_ref_sup8),
                }
                w.write_udata(val.0 as u64, unit.format().word_size())?;
            }
            AttributeValue::LineProgramRef => {
                if unit.version() >= 4 {
                    debug_assert_form!(constants::DW_FORM_sec_offset);
                }
                match line_program {
                    Some(line_program) => {
                        w.write_offset(
                            line_program.0,
                            SectionId::DebugLine,
                            unit.format().word_size(),
                        )?;
                    }
                    None => return Err(Error::InvalidAttributeValue),
                }
            }
            AttributeValue::LocationListRef(val) => {
                if unit.version() >= 4 {
                    debug_assert_form!(constants::DW_FORM_sec_offset);
                }
                let section = if unit.version() <= 4 {
                    SectionId::DebugLoc
                } else {
                    SectionId::DebugLocLists
                };
                w.write_offset(loc_lists.get(val).0, section, unit.format().word_size())?;
            }
            AttributeValue::DebugMacinfoRef(val) => {
                if unit.version() >= 4 {
                    debug_assert_form!(constants::DW_FORM_sec_offset);
                }
                w.write_offset(val.0, SectionId::DebugMacinfo, unit.format().word_size())?;
            }
            AttributeValue::DebugMacroRef(val) => {
                if unit.version() >= 4 {
                    debug_assert_form!(constants::DW_FORM_sec_offset);
                }
                w.write_offset(val.0, SectionId::DebugMacro, unit.format().word_size())?;
            }
            AttributeValue::RangeListRef(val) => {
                if unit.version() >= 4 {
                    debug_assert_form!(constants::DW_FORM_sec_offset);
                }
                let section = if unit.version() <= 4 {
                    SectionId::DebugRanges
                } else {
                    SectionId::DebugRngLists
                };
                w.write_offset(range_lists.get(val).0, section, unit.format().word_size())?;
            }
            AttributeValue::DebugTypesRef(val) => {
                debug_assert_form!(constants::DW_FORM_ref_sig8);
                w.write_u64(val.0)?;
            }
            AttributeValue::StringRef(val) => {
                debug_assert_form!(constants::DW_FORM_strp);
                w.write_offset(
                    strings.offset(val).0,
                    SectionId::DebugStr,
                    unit.format().word_size(),
                )?;
            }
            AttributeValue::DebugStrRefSup(val) => {
                debug_assert_form!(constants::DW_FORM_strp_sup);
                w.write_udata(val.0 as u64, unit.format().word_size())?;
            }
            AttributeValue::LineStringRef(val) => {
                debug_assert_form!(constants::DW_FORM_line_strp);
                w.write_offset(
                    line_strings.offset(val).0,
                    SectionId::DebugLineStr,
                    unit.format().word_size(),
                )?;
            }
            AttributeValue::String(ref val) => {
                debug_assert_form!(constants::DW_FORM_string);
                w.write(val)?;
                w.write_u8(0)?;
            }
            AttributeValue::Encoding(val) => {
                debug_assert_form!(constants::DW_FORM_udata);
                w.write_uleb128(u64::from(val.0))?;
            }
            AttributeValue::DecimalSign(val) => {
                debug_assert_form!(constants::DW_FORM_udata);
                w.write_uleb128(u64::from(val.0))?;
            }
            AttributeValue::Endianity(val) => {
                debug_assert_form!(constants::DW_FORM_udata);
                w.write_uleb128(u64::from(val.0))?;
            }
            AttributeValue::Accessibility(val) => {
                debug_assert_form!(constants::DW_FORM_udata);
                w.write_uleb128(u64::from(val.0))?;
            }
            AttributeValue::Visibility(val) => {
                debug_assert_form!(constants::DW_FORM_udata);
                w.write_uleb128(u64::from(val.0))?;
            }
            AttributeValue::Virtuality(val) => {
                debug_assert_form!(constants::DW_FORM_udata);
                w.write_uleb128(u64::from(val.0))?;
            }
            AttributeValue::Language(val) => {
                debug_assert_form!(constants::DW_FORM_udata);
                w.write_uleb128(u64::from(val.0))?;
            }
            AttributeValue::AddressClass(val) => {
                debug_assert_form!(constants::DW_FORM_udata);
                w.write_uleb128(val.0)?;
            }
            AttributeValue::IdentifierCase(val) => {
                debug_assert_form!(constants::DW_FORM_udata);
                w.write_uleb128(u64::from(val.0))?;
            }
            AttributeValue::CallingConvention(val) => {
                debug_assert_form!(constants::DW_FORM_udata);
                w.write_uleb128(u64::from(val.0))?;
            }
            AttributeValue::Inline(val) => {
                debug_assert_form!(constants::DW_FORM_udata);
                w.write_uleb128(u64::from(val.0))?;
            }
            AttributeValue::Ordering(val) => {
                debug_assert_form!(constants::DW_FORM_udata);
                w.write_uleb128(u64::from(val.0))?;
            }
            AttributeValue::FileIndex(val) => {
                debug_assert_form!(constants::DW_FORM_udata);
                w.write_uleb128(val.map(|id| id.raw(unit.version())).unwrap_or(0))?;
            }
        }
        Ok(())
    }
}

define_section!(
    DebugInfo,
    DebugInfoOffset,
    "A writable `.debug_info` section."
);

/// The section offsets of all elements of a unit within a `.debug_info` section.
#[derive(Debug)]
pub(crate) struct UnitOffsets {
    base_id: BaseId,
    unit: DebugInfoOffset,
    entries: Vec<DebugInfoOffset>,
}

impl UnitOffsets {
    /// Get the `.debug_info` offset for the given entry.
    ///
    /// Returns `None` if the offset has not been calculated yet.
    #[inline]
    fn debug_info_offset(&self, entry: UnitEntryId) -> Option<DebugInfoOffset> {
        debug_assert_eq!(self.base_id, entry.base_id);
        let offset = self.entries[entry.index];
        if offset.0 == 0 { None } else { Some(offset) }
    }

    /// Get the unit offset for the given entry.
    ///
    /// Returns `None` if the offset has not been calculated yet.
    /// This may occur if the entry is orphaned or if a reference
    /// to the entry occurs before the entry itself is written.
    #[inline]
    pub(crate) fn unit_offset(&self, entry: UnitEntryId) -> Option<u64> {
        self.debug_info_offset(entry)
            .map(|offset| (offset.0 - self.unit.0) as u64)
    }
}

/// A reference to a `.debug_info` entry.
#[deprecated(note = "Renamed to DebugInfoRef")]
pub type Reference = DebugInfoRef;

/// A reference to a `.debug_info` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DebugInfoRef {
    /// An external symbol.
    ///
    /// The meaning of this value is decided by the writer, but
    /// will typically be an index into a symbol table.
    Symbol(usize),
    /// An entry in the same section.
    ///
    /// This only supports references in units that are emitted together.
    Entry(UnitId, UnitEntryId),
}

/// A reference to a `.debug_info` entry that has yet to be resolved.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DebugInfoFixup {
    /// The offset within the section where the reference should be written.
    pub offset: usize,
    /// The size of the reference.
    pub size: u8,
    /// The unit containing the entry.
    pub unit: UnitId,
    /// The entry being referenced.
    pub entry: UnitEntryId,
}

#[cfg(feature = "read")]
pub use convert::*;
#[cfg(feature = "read")]
pub(crate) mod convert {
    use super::*;
    use crate::common::{
        DwoId, LineEncoding, LocationListsOffset, RangeListsOffset, UnitSectionOffset,
    };
    use crate::read::{self, Reader};
    use crate::write::{
        self, ConvertError, ConvertLineProgram, ConvertResult, Dwarf, LocationList, RangeList,
    };
    use std::collections::{HashMap, HashSet};

    #[derive(Debug, Default)]
    struct FilterDependencies {
        edges: HashMap<UnitSectionOffset, HashSet<UnitSectionOffset>>,
        required: HashSet<UnitSectionOffset>,
    }

    impl FilterDependencies {
        /// Mark `entry` as a valid offset.
        ///
        /// This must be called before adding an edge from an entry.
        fn add_entry(&mut self, entry: UnitSectionOffset) {
            debug_assert!(!self.edges.contains_key(&entry));
            self.edges.insert(entry, HashSet::new());
        }

        /// If `from` is reachable then `to` is also reachable.
        ///
        /// Must have already called `add_entry(from)`.
        ///
        /// The edge will be ignored if `add_entry(to)` is never called
        /// (either before or after).
        fn add_edge(&mut self, from: UnitSectionOffset, to: UnitSectionOffset) {
            self.edges.get_mut(&from).unwrap().insert(to);
        }

        /// Mark `entry` as reachable.
        ///
        /// This doesn't depend on `add_entry` being called for the entry
        /// (but you probably should at some stage anyway).
        fn require_entry(&mut self, entry: UnitSectionOffset) {
            self.required.insert(entry);
        }

        /// Return a sorted list of all reachable entries.
        fn get_reachable(&self) -> Vec<UnitSectionOffset> {
            let mut reachable = self.required.clone();
            let mut queue = Vec::new();
            for i in self.required.iter() {
                queue.push(*i);
            }
            while let Some(i) = queue.pop() {
                if let Some(deps) = self.edges.get(&i) {
                    for j in deps {
                        if self.edges.contains_key(j) && reachable.insert(*j) {
                            queue.push(*j);
                        }
                    }
                }
            }
            let mut offsets: Vec<_> = reachable.into_iter().collect();
            offsets.sort_unstable();
            offsets
        }
    }

    /// The state for identifying which DIEs in a `.debug_info` section
    /// need to be converted.
    ///
    /// This is used to prune unneeded DIEs, and reserve IDs so that
    /// DIE references can be converted.
    ///
    /// The user should call [`FilterUnitSection::read_unit`] and
    /// [`FilterUnit::read_entry`] to traverse all DIEs in the section. Once there are
    /// no more units, this state can be passed to [`Dwarf::convert_with_filter`] or
    /// [`ConvertUnit::convert_split_with_filter`].
    ///
    /// ## Example
    ///
    /// Create a filter for the DIEs in a DWARF section.
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
    /// // `filter` can now be used to filter the DIEs during a conversion.
    /// # unreachable!()
    /// # }
    /// ```
    #[derive(Debug)]
    pub struct FilterUnitSection<'a, R: Reader<Offset = usize>> {
        dwarf: &'a read::Dwarf<R>,
        unit_headers: read::DebugInfoUnitHeadersIter<R>,
        skeleton_unit: Option<read::UnitRef<'a, R>>,
        units: Vec<read::Unit<R>>,
        deps: FilterDependencies,
    }

    impl<'a, R: Reader<Offset = usize>> FilterUnitSection<'a, R> {
        /// Start parsing a `.debug_info` section.
        ///
        /// ## Example
        ///
        /// ```rust,no_run
        /// # fn example() -> Result<(), gimli::write::ConvertError> {
        /// # let loader = |name| -> Result<gimli::EndianSlice<gimli::RunTimeEndian>, gimli::Error> { unimplemented!() };
        /// let read_dwarf = gimli::read::Dwarf::load(loader)?;
        /// let mut filter = gimli::write::FilterUnitSection::new(&read_dwarf)?;
        /// # unreachable!()
        /// # }
        /// ```
        pub fn new(dwarf: &'a read::Dwarf<R>) -> ConvertResult<Self> {
            Ok(FilterUnitSection {
                dwarf,
                unit_headers: dwarf.units(),
                skeleton_unit: None,
                units: Vec::new(),
                deps: FilterDependencies::default(),
            })
        }

        /// Start parsing the `.debug_info` section for a split DWARF unit.
        ///
        /// ## Example
        ///
        /// ```rust,no_run
        /// # fn example() -> Result<(), gimli::write::ConvertError> {
        /// # let loader = |name| -> Result<gimli::EndianSlice<gimli::RunTimeEndian>, gimli::Error> { unimplemented!() };
        /// # let skeleton_unit: gimli::UnitRef<'static, gimli::EndianSlice<gimli::RunTimeEndian>> = unimplemented!();
        /// let dwp = gimli::read::DwarfPackage::load(loader, Default::default())?;
        /// let dwo_id = skeleton_unit.dwo_id.unwrap();
        /// let split_dwarf = dwp.find_cu(dwo_id, skeleton_unit.dwarf)?.unwrap();
        /// let mut filter = gimli::write::FilterUnitSection::new_split(&split_dwarf, skeleton_unit)?;
        /// # unreachable!()
        /// # }
        /// ```
        pub fn new_split(
            dwarf: &'a read::Dwarf<R>,
            skeleton_unit: read::UnitRef<'a, R>,
        ) -> ConvertResult<Self> {
            Ok(FilterUnitSection {
                dwarf,
                unit_headers: dwarf.units(),
                skeleton_unit: Some(skeleton_unit),
                units: Vec::new(),
                deps: FilterDependencies::default(),
            })
        }

        /// Read the next unit header and prepare to parse its DIEs.
        pub fn read_unit(&'_ mut self) -> ConvertResult<Option<FilterUnit<'_, R>>> {
            let Some(header) = self.unit_headers.next()? else {
                return Ok(None);
            };
            let mut unit = self.dwarf.unit(header)?;
            if let Some(skeleton_unit) = self.skeleton_unit {
                unit.copy_relocated_attributes(&skeleton_unit);
            }
            self.units.push(unit);
            let unit = self.units.last().unwrap().unit_ref(self.dwarf);

            FilterUnit::new(unit, self.skeleton_unit, &mut self.deps).map(Some)
        }
    }

    /// The state for identifying which DIEs in a `.debug_info` unit
    /// need to be converted.
    ///
    /// This is created by [`FilterUnitSection::read_unit`].
    ///
    /// See [`FilterUnitSection`] for an example.
    #[derive(Debug)]
    pub struct FilterUnit<'a, R: Reader<Offset = usize>> {
        /// The unit being read.
        pub unit: read::UnitRef<'a, R>,
        /// The skeleton unit being read if `unit` is a split unit.
        pub skeleton_unit: Option<read::UnitRef<'a, R>>,
        entries: read::EntriesRaw<'a, 'a, R>,
        parents: Vec<FilterParent>,
        deps: &'a mut FilterDependencies,
    }

    #[derive(Debug, Clone, Copy)]
    struct FilterParent {
        depth: isize,
        offset: read::UnitOffset,
        tag: constants::DwTag,
    }

    impl<'a, R: Reader<Offset = usize>> FilterUnit<'a, R> {
        fn new(
            unit: read::UnitRef<'a, R>,
            skeleton_unit: Option<read::UnitRef<'a, R>>,
            deps: &'a mut FilterDependencies,
        ) -> ConvertResult<Self> {
            let mut entries = unit.entries_raw(None)?;
            let abbrev = entries
                .read_abbreviation()?
                .ok_or(read::Error::MissingUnitDie)?;
            entries.skip_attributes(abbrev.attributes())?;
            Ok(FilterUnit {
                unit,
                skeleton_unit,
                entries,
                parents: Vec::new(),
                deps,
            })
        }

        /// Read the next DIE.
        ///
        /// Returns `None` if the unit has no more DIEs.
        ///
        /// This also records dependencies for the DIE:
        /// - the DIE always depends on its parent
        /// - the parent may depend on the DIE
        /// - the DIE depends on any DIEs that are referenced by its attributes
        ///
        /// The only task the user needs to perform is to call
        /// [`FilterUnit::require_entry`] if the DIE is always required to be
        /// converted. Typically, a DIE will be required if it has a valid address range.
        pub fn read_entry(&mut self) -> ConvertResult<Option<FilterUnitEntry<'a, R>>> {
            loop {
                if self.entries.is_empty() {
                    return Ok(None);
                }

                // Calculate offset and depth before reading the abbreviation code.
                let offset = self.entries.next_offset();
                let depth = self.entries.next_depth();

                let Some(abbrev) = self.entries.read_abbreviation()? else {
                    // Null entry.
                    continue;
                };

                while let Some(parent) = self.parents.last() {
                    if parent.depth < depth {
                        break;
                    }
                    self.parents.pop();
                }
                let parent = self.parents.last().copied();

                if abbrev.has_children() {
                    self.parents.push(FilterParent {
                        depth,
                        offset,
                        tag: abbrev.tag(),
                    });
                }

                let entry_offset = offset.to_unit_section_offset(&self.unit);
                self.deps.add_entry(entry_offset);

                let mut entry = FilterUnitEntry {
                    unit: self.unit,
                    offset,
                    depth,
                    tag: abbrev.tag(),
                    attrs: Vec::new(),
                    parent: parent.map(|p| p.offset),
                    parent_tag: parent.map(|p| p.tag),
                };
                Self::read_attributes(&mut entry, &mut self.entries, abbrev.attributes())?;
                for attr in &entry.attrs {
                    self.add_attribute_refs(entry_offset, attr.value())?;
                }
                if let Some(parent) = parent {
                    let parent_offset = parent.offset.to_unit_section_offset(&self.unit);
                    self.deps.add_edge(entry_offset, parent_offset);
                    if parent.tag != constants::DW_TAG_namespace && entry.has_die_back_edge() {
                        self.deps.add_edge(parent_offset, entry_offset);
                    }
                }

                return Ok(Some(entry));
            }
        }

        fn read_attributes(
            entry: &mut FilterUnitEntry<'a, R>,
            entries: &mut read::EntriesRaw<'_, '_, R>,
            specs: &[read::AttributeSpecification],
        ) -> ConvertResult<()> {
            for spec in specs {
                let attr = entries.read_attribute(*spec)?;
                match attr.name() {
                    // Skip DWARF metadata attributes.
                    // TODO: should DWO attributes be conditionally kept?
                    constants::DW_AT_sibling
                    | constants::DW_AT_str_offsets_base
                    | constants::DW_AT_addr_base
                    | constants::DW_AT_rnglists_base
                    | constants::DW_AT_loclists_base
                    | constants::DW_AT_dwo_name
                    | constants::DW_AT_GNU_addr_base
                    | constants::DW_AT_GNU_ranges_base
                    | constants::DW_AT_GNU_dwo_name
                    | constants::DW_AT_GNU_dwo_id => {}
                    _ => entry.attrs.push(attr),
                }
            }
            Ok(())
        }

        fn add_attribute_refs(
            &mut self,
            entry_offset: UnitSectionOffset,
            value: read::AttributeValue<R>,
        ) -> ConvertResult<()> {
            match value {
                read::AttributeValue::UnitRef(val) => {
                    // This checks that the offset is within bounds, but not that it refers to a valid DIE.
                    if val.is_in_bounds(&self.unit) {
                        self.deps
                            .add_edge(entry_offset, val.to_unit_section_offset(&self.unit));
                    }
                }
                read::AttributeValue::DebugInfoRef(val) => {
                    self.deps
                        .add_edge(entry_offset, UnitSectionOffset::DebugInfoOffset(val));
                }
                read::AttributeValue::Exprloc(expression) => {
                    self.add_expression_refs(entry_offset, expression.clone());
                }
                read::AttributeValue::LocationListsRef(val) => {
                    self.add_location_refs(entry_offset, val)?;
                }
                read::AttributeValue::DebugLocListsIndex(index) => {
                    self.add_location_refs(entry_offset, self.unit.locations_offset(index)?)?;
                }
                _ => (),
            }
            Ok(())
        }

        fn add_location_refs(
            &mut self,
            entry_offset: UnitSectionOffset,
            offset: LocationListsOffset,
        ) -> ConvertResult<()> {
            let mut locations = self.unit.locations(offset)?;
            while let Some(location) = locations.next()? {
                self.add_expression_refs(entry_offset, location.data);
            }
            Ok(())
        }

        fn add_expression_refs(
            &mut self,
            entry_offset: UnitSectionOffset,
            expression: read::Expression<R>,
        ) {
            let mut ops = expression.operations(self.unit.encoding());
            // Ignore parsing errors. They can be handled in the conversion step.
            while let Ok(Some(op)) = ops.next() {
                match op {
                    read::Operation::Deref {
                        base_type: offset, ..
                    }
                    | read::Operation::RegisterOffset {
                        base_type: offset, ..
                    }
                    | read::Operation::TypedLiteral {
                        base_type: offset, ..
                    }
                    | read::Operation::Convert {
                        base_type: offset, ..
                    }
                    | read::Operation::Reinterpret {
                        base_type: offset, ..
                    }
                    | read::Operation::ParameterRef { offset, .. }
                    | read::Operation::Call {
                        offset: read::DieReference::UnitRef(offset),
                        ..
                    } => {
                        if offset.is_in_bounds(&self.unit) {
                            self.deps
                                .add_edge(entry_offset, offset.to_unit_section_offset(&self.unit));
                        }
                    }
                    read::Operation::Call {
                        offset: read::DieReference::DebugInfoRef(ref_offset),
                        ..
                    } => {
                        self.deps.add_edge(entry_offset, ref_offset.into());
                    }
                    _ => {}
                }
            }
        }

        /// Indicate that the DIE with the given offset is always required to be converted.
        ///
        /// Typically, this will be called if the DIE has a valid address range.
        ///
        /// This can only be called for offsets within the current unit.
        pub fn require_entry(&mut self, offset: read::UnitOffset) {
            debug_assert!(offset.is_in_bounds(&self.unit));
            self.deps
                .require_entry(offset.to_unit_section_offset(&self.unit));
        }
    }

    /// A DIE read by [`FilterUnit::read_entry`].
    ///
    /// See [`FilterUnitSection`] for an example.
    #[derive(Debug)]
    #[non_exhaustive]
    pub struct FilterUnitEntry<'a, R: Reader<Offset = usize>> {
        /// The unit that this DIE was read from.
        ///
        /// This may be a skeleton unit.
        pub unit: read::UnitRef<'a, R>,
        /// The offset of this DIE within the unit.
        pub offset: read::UnitOffset,
        /// The depth of this DIE in the tree.
        ///
        /// This may be useful for maintaining a stack of state corresponding to the
        /// parent entries.
        pub depth: isize,
        /// The tag that was read for this DIE.
        pub tag: constants::DwTag,
        /// The attributes that were read for this DIE.
        ///
        /// This excludes attributes for DWARF metadata.
        pub attrs: Vec<read::Attribute<R>>,
        /// The offset of this DIE's parent, if any.
        ///
        /// This is set to `None` if the parent is the root of the unit.
        pub parent: Option<read::UnitOffset>,
        /// The tag of this DIE's parent, if any.
        ///
        /// This is set to `None` if the parent is the root of the unit.
        pub parent_tag: Option<constants::DwTag>,
    }

    impl<'a, R: Reader<Offset = usize>> FilterUnitEntry<'a, R> {
        /// Return `true` if this entry has an attribute with the given name.
        pub fn has_attr(&self, name: constants::DwAt) -> bool {
            self.attrs.iter().any(|attr| attr.name() == name)
        }

        /// Find the value of the first attribute with the given name.
        pub fn attr_value(&self, name: constants::DwAt) -> Option<read::AttributeValue<R>> {
            self.attrs
                .iter()
                .find(|attr| attr.name() == name)
                .map(|attr| attr.value())
        }

        /// Return `true` if this DIE has a back-edge to its parent.
        // DIEs can be broadly divided into three categories:
        // 1. Extensions of their parents; effectively attributes: DW_TAG_variable, DW_TAG_member, etc.
        // 2. Standalone entities referred to by other DIEs via 'reference' class attributes: types.
        // 3. Structural entities that organize how the above relate to each other: namespaces.
        // Here, we must make sure to return 'true' for DIEs in the first category since stripping them,
        // provided their parent is alive, is always wrong. To be conservatively correct in the face
        // of new/vendor tags, we maintain a "(mostly) known good" list of tags of the latter categories.
        fn has_die_back_edge(&self) -> bool {
            match self.tag {
                constants::DW_TAG_array_type
                | constants::DW_TAG_atomic_type
                | constants::DW_TAG_base_type
                | constants::DW_TAG_class_type
                | constants::DW_TAG_const_type
                | constants::DW_TAG_dwarf_procedure
                | constants::DW_TAG_entry_point
                | constants::DW_TAG_enumeration_type
                | constants::DW_TAG_pointer_type
                | constants::DW_TAG_ptr_to_member_type
                | constants::DW_TAG_reference_type
                | constants::DW_TAG_restrict_type
                | constants::DW_TAG_rvalue_reference_type
                | constants::DW_TAG_string_type
                | constants::DW_TAG_structure_type
                | constants::DW_TAG_typedef
                | constants::DW_TAG_union_type
                | constants::DW_TAG_unspecified_type
                | constants::DW_TAG_volatile_type
                | constants::DW_TAG_coarray_type
                | constants::DW_TAG_common_block
                | constants::DW_TAG_dynamic_type
                | constants::DW_TAG_file_type
                | constants::DW_TAG_immutable_type
                | constants::DW_TAG_interface_type
                | constants::DW_TAG_set_type
                | constants::DW_TAG_shared_type
                | constants::DW_TAG_subroutine_type
                | constants::DW_TAG_packed_type
                | constants::DW_TAG_template_alias
                | constants::DW_TAG_namelist
                | constants::DW_TAG_namespace
                | constants::DW_TAG_imported_unit
                | constants::DW_TAG_imported_declaration
                | constants::DW_TAG_imported_module
                | constants::DW_TAG_module => false,
                constants::DW_TAG_subprogram => self.has_attr(constants::DW_AT_declaration),
                _ => true,
            }
        }
    }

    /// The state for the conversion of a `.debug_info` section.
    ///
    /// Created by [`Dwarf::convert`] or [`Dwarf::convert_with_filter`].
    #[derive(Debug)]
    pub struct ConvertUnitSection<'a, R: Reader<Offset = usize>> {
        from_dwarf: &'a read::Dwarf<R>,
        from_units: Vec<(read::Unit<R>, UnitId)>,
        /// The next unit in `from_units` to return from `read_unit`.
        from_unit_index: usize,
        /// The associated skeleton unit if this is a split DWARF section.
        ///
        /// If this is set then `from_units` will contain exactly one unit.
        from_skeleton_unit: Option<read::UnitRef<'a, R>>,
        entry_ids: HashMap<UnitSectionOffset, (UnitId, UnitEntryId)>,
        dwarf: &'a mut Dwarf,
    }

    impl<'a, R: Reader<Offset = usize>> ConvertUnitSection<'a, R> {
        /// Create a converter for the `.debug_info` section of the given DWARF object.
        pub(crate) fn new(
            from_dwarf: &'a read::Dwarf<R>,
            dwarf: &'a mut Dwarf,
        ) -> ConvertResult<Self> {
            let mut convert = ConvertUnitSection {
                from_dwarf,
                from_units: Vec::new(),
                from_unit_index: 0,
                from_skeleton_unit: None,
                entry_ids: HashMap::new(),
                dwarf,
            };

            // Assigns ids to all units and entries, so that we can convert
            // references in attributes.
            let mut offsets = Vec::new();
            let mut from_units = from_dwarf.units();
            while let Some(from_unit) = from_units.next()? {
                let from_unit = from_dwarf.unit(from_unit)?;
                read_entry_offsets(&from_unit, &mut offsets)?;
                convert.reserve_unit(from_unit, &offsets);
            }

            Ok(convert)
        }

        /// Create a converter for the `.debug_info` section of the given DWARF object.
        ///
        /// Only reachable entries identified by `filter` will be reserved.
        ///
        /// Units with no reachable entries will be skipped.
        pub(crate) fn new_with_filter(
            dwarf: &'a mut Dwarf,
            filter: FilterUnitSection<'a, R>,
        ) -> ConvertResult<Self> {
            let mut convert = ConvertUnitSection {
                from_dwarf: filter.dwarf,
                from_units: Vec::new(),
                from_unit_index: 0,
                from_skeleton_unit: filter.skeleton_unit,
                entry_ids: HashMap::new(),
                dwarf,
            };

            let offsets = filter.deps.get_reachable();

            // Reserve all filtered entries.
            let mut start;
            let mut end = 0;
            for from_unit in filter.units {
                start = end;
                while let Some(offset) = offsets.get(end) {
                    if offset.to_unit_offset(&from_unit).is_none() {
                        break;
                    }
                    end += 1;
                }
                convert.reserve_unit(from_unit, &offsets[start..end]);
            }
            debug_assert_eq!(end, offsets.len());

            Ok(convert)
        }

        /// Create a placeholder for each entry in a unit.
        ///
        /// This allows us to assign IDs to entries before they are created.
        fn reserve_unit(&mut self, from_unit: read::Unit<R>, offsets: &[UnitSectionOffset]) {
            let root_offset = from_unit
                .header
                .root_offset()
                .to_unit_section_offset(&from_unit);

            let unit_id = self
                .dwarf
                .units
                .add(Unit::new(from_unit.encoding(), LineProgram::none()));
            self.from_units.push((from_unit, unit_id));
            let unit = self.dwarf.units.get_mut(unit_id);

            self.entry_ids.insert(root_offset, (unit_id, unit.root()));
            for offset in offsets {
                self.entry_ids.insert(*offset, (unit_id, unit.reserve()));
            }
        }

        /// Read the next unit header and prepare to convert it.
        ///
        /// Returns a `ConvertUnit` for the unit, and a `ConvertUnitEntry` for the root
        /// DIE.
        ///
        /// See [`ConvertUnit`] for an example of the unit conversion.
        pub fn read_unit(
            &mut self,
        ) -> ConvertResult<Option<(ConvertUnit<'_, R>, ConvertUnitEntry<'_, R>)>> {
            let Some((from_unit, unit_id)) = self.from_units.get(self.from_unit_index) else {
                return Ok(None);
            };
            self.from_unit_index += 1;

            let from_unit = from_unit.unit_ref(self.from_dwarf);

            let mut unit = ConvertUnit {
                from_unit,
                from_skeleton_unit: self.from_skeleton_unit,
                unit_id: *unit_id,
                unit: self.dwarf.units.get_mut(*unit_id),
                entry_ids: &self.entry_ids,
                line_strings: &mut self.dwarf.line_strings,
                strings: &mut self.dwarf.strings,
                line_program_files: Vec::new(),
                from_entries: from_unit.entries_raw(None)?,
                parents: Vec::new(),
            };
            let (_id, entry) = unit.read_entry()?.ok_or(read::Error::MissingUnitDie)?;
            Ok(Some((unit, entry)))
        }
    }

    /// The state for the conversion of a split `.debug_info` section.
    ///
    /// Created by [`ConvertUnit::convert_split`] or
    /// [`ConvertUnit::convert_split_with_filter`].
    #[derive(Debug)]
    pub struct ConvertSplitUnitSection<'a, R: Reader<Offset = usize>> {
        from_dwarf: &'a read::Dwarf<R>,
        from_unit: read::Unit<R>,
        from_skeleton_unit: read::UnitRef<'a, R>,
        entry_ids: HashMap<UnitSectionOffset, (UnitId, UnitEntryId)>,
        unit_id: UnitId,
        unit: &'a mut write::Unit,
        line_strings: &'a mut write::LineStringTable,
        strings: &'a mut write::StringTable,
    }

    impl<'a, R: Reader<Offset = usize>> ConvertSplitUnitSection<'a, R> {
        fn new(
            skeleton: &'a mut ConvertUnit<'a, R>,
            split_dwarf: &'a read::Dwarf<R>,
        ) -> ConvertResult<Self> {
            debug_assert!(skeleton.from_skeleton_unit.is_none());

            let split_unit_header = split_dwarf
                .units()
                .next()?
                .ok_or(read::Error::MissingSplitUnit)?;
            let mut split_unit = split_dwarf.unit(split_unit_header)?;
            split_unit.copy_relocated_attributes(&skeleton.from_unit);

            let mut offsets = Vec::new();
            read_entry_offsets(&split_unit, &mut offsets)?;

            Self::new_with_offsets(skeleton, split_dwarf, split_unit, offsets)
        }

        fn new_with_filter(
            skeleton: &'a mut ConvertUnit<'a, R>,
            filter: FilterUnitSection<'a, R>,
        ) -> ConvertResult<Self> {
            debug_assert!(skeleton.from_skeleton_unit.is_none());

            let split_unit = filter
                .units
                .into_iter()
                .next()
                .ok_or(read::Error::MissingSplitUnit)?;

            let offsets = filter.deps.get_reachable();

            Self::new_with_offsets(skeleton, filter.dwarf, split_unit, offsets)
        }

        fn new_with_offsets(
            skeleton: &'a mut ConvertUnit<'a, R>,
            split_dwarf: &'a read::Dwarf<R>,
            split_unit: read::Unit<R>,
            offsets: Vec<UnitSectionOffset>,
        ) -> ConvertResult<Self> {
            let root_offset = split_unit
                .header
                .root_offset()
                .to_unit_section_offset(&split_unit);

            // Replace the unit that was reserved for the skeleton unit.
            let unit_id = skeleton.unit_id;
            let unit = &mut *skeleton.unit;

            let mut entry_ids = HashMap::new();
            entry_ids.insert(root_offset, (unit_id, unit.root()));
            for offset in offsets {
                entry_ids.insert(offset, (unit_id, unit.reserve()));
            }

            Ok(ConvertSplitUnitSection {
                from_dwarf: split_dwarf,
                from_unit: split_unit,
                from_skeleton_unit: skeleton.from_unit,
                entry_ids,
                unit_id,
                unit,
                line_strings: skeleton.line_strings,
                strings: skeleton.strings,
            })
        }

        /// Read the split unit header and prepare to convert it.
        ///
        /// Returns a `ConvertUnit` for the unit, and a `ConvertUnitEntry` for the root
        /// DIE.
        ///
        /// See [`ConvertUnit`] for an example of the unit conversion.
        pub fn read_unit(
            &'_ mut self,
        ) -> ConvertResult<(ConvertUnit<'_, R>, ConvertUnitEntry<'_, R>)> {
            let from_unit = self.from_unit.unit_ref(self.from_dwarf);

            let mut unit = ConvertUnit {
                from_unit,
                from_skeleton_unit: Some(self.from_skeleton_unit),
                unit_id: self.unit_id,
                unit: self.unit,
                entry_ids: &self.entry_ids,
                line_strings: self.line_strings,
                strings: self.strings,
                line_program_files: Vec::new(),
                from_entries: from_unit.entries_raw(None)?,
                parents: Vec::new(),
            };
            let (_id, entry) = unit.read_entry()?.ok_or(read::Error::MissingUnitDie)?;
            Ok((unit, entry))
        }
    }

    /// Read entry offsets for a unit.
    ///
    /// `offsets` is cleared first, allowing reuse of the allocation.
    ///
    /// Does not include the root entry.
    fn read_entry_offsets<R: Reader<Offset = usize>>(
        unit: &read::Unit<R>,
        offsets: &mut Vec<UnitSectionOffset>,
    ) -> ConvertResult<()> {
        let mut from_entries = unit.entries_raw(None)?;

        // The root entry is skipped because write::Unit always creates a root entry.
        let abbrev = from_entries
            .read_abbreviation()?
            .ok_or(read::Error::MissingUnitDie)?;
        from_entries.skip_attributes(abbrev.attributes())?;

        offsets.clear();
        while !from_entries.is_empty() {
            let offset = from_entries.next_offset();
            let Some(abbrev) = from_entries.read_abbreviation()? else {
                continue;
            };
            from_entries.skip_attributes(abbrev.attributes())?;
            offsets.push(offset.to_unit_section_offset(unit));
        }

        Ok(())
    }

    /// The state for the conversion of a `.debug_info` unit.
    ///
    /// This is created by [`ConvertUnitSection::read_unit`] or
    /// [`ConvertSplitUnitSection::read_unit`].
    ///
    /// ## Example
    ///
    /// Convert a unit.
    ///
    /// ```rust,no_run
    /// # fn example() -> Result<(), gimli::write::ConvertError> {
    /// # let loader = |name| -> Result<gimli::EndianSlice<gimli::RunTimeEndian>, gimli::Error> { unimplemented!() };
    /// let read_dwarf = gimli::read::Dwarf::load(loader)?;
    /// let mut write_dwarf = gimli::write::Dwarf::new();
    /// let mut convert = write_dwarf.convert(&read_dwarf)?;
    /// while let Some((mut unit, root_entry)) = convert.read_unit()? {
    ///     if let Some(convert_program) = unit.read_line_program(None, None)? {
    ///         let (program, files) = convert_program.convert_all(
    ///             &|address| Some(gimli::write::Address::Constant(address)),
    ///         )?;
    ///         unit.set_line_program(program, files);
    ///     }
    ///     let root_id = unit.unit.root();
    ///     convert_attributes(&mut unit, root_id, &root_entry)?;
    ///     while let Some((id, entry)) = unit.read_entry()? {
    ///         // `id` is `None` for DIEs that weren't reserved and thus don't need converting.
    ///         // This only happens when `FilterUnitSection` is used.
    ///         if id.is_none() {
    ///             continue;
    ///         }
    ///         let id = unit.add_entry(id, &entry);
    ///         convert_attributes(&mut unit, id, &entry)?;
    ///     }
    /// }
    ///
    /// fn convert_attributes<R: gimli::Reader<Offset = usize>>(
    ///     unit: &mut gimli::write::ConvertUnit<'_, R>,
    ///     id: gimli::write::UnitEntryId,
    ///     entry: &gimli::write::ConvertUnitEntry<'_, R>,
    /// ) -> gimli::write::ConvertResult<()> {
    ///     for attr in &entry.attrs {
    ///         let value = unit.convert_attribute_value(
    ///             entry.from_unit,
    ///             attr.name(),
    ///             attr.value(),
    ///             &|address| Some(gimli::write::Address::Constant(address)),
    ///         )?;
    ///         unit.unit.get_mut(id).set(attr.name(), value);
    ///     }
    ///     Ok(())
    /// }
    /// # unreachable!()
    /// # }
    /// ```
    #[derive(Debug)]
    pub struct ConvertUnit<'a, R: Reader<Offset = usize>> {
        /// The unit being read from.
        pub from_unit: read::UnitRef<'a, R>,
        /// The skeleton unit being read from if `from_unit` is a split unit.
        pub from_skeleton_unit: Option<read::UnitRef<'a, R>>,
        unit_id: UnitId,
        /// The unit being written to.
        pub unit: &'a mut write::Unit,
        /// The table containing converted line strings.
        pub line_strings: &'a mut write::LineStringTable,
        /// The table containing converted strings.
        pub strings: &'a mut write::StringTable,
        line_program_files: Vec<FileId>,
        entry_ids: &'a HashMap<UnitSectionOffset, (UnitId, UnitEntryId)>,
        from_entries: read::EntriesRaw<'a, 'a, R>,
        parents: Vec<(isize, UnitEntryId)>,
    }

    impl<'a, R: Reader<Offset = usize>> ConvertUnit<'a, R> {
        /// Create a converter for all DIEs in a split DWARF unit and its skeleton unit.
        ///
        /// `split_dwarf` is the unit's contribution to the DWARF sections
        /// in a `DwarfPackage`, or the DWARF sections in a DWO file.
        ///
        /// ## Example
        ///
        /// Convert a split DWARF unit using `convert_split`.
        ///
        /// ```rust,no_run
        /// # fn example() -> Result<(), gimli::write::ConvertError> {
        /// # let loader = |name| -> Result<gimli::EndianSlice<gimli::RunTimeEndian>, gimli::Error> { unimplemented!() };
        /// # let skeleton_unit: gimli::UnitRef<'static, gimli::EndianSlice<gimli::RunTimeEndian>> = unimplemented!();
        /// let dwp = gimli::read::DwarfPackage::load(loader, Default::default())?;
        /// let mut convert: gimli::write::ConvertUnitSection<_> = unimplemented!();
        /// while let Some((mut unit, root_entry)) = convert.read_unit()? {
        ///     let Some(dwo_id) = unit.from_unit.dwo_id else {
        ///         // Not a split unit. Handling omitted for this example.
        ///         continue;
        ///     };
        ///     let split_dwarf = dwp.find_cu(dwo_id, skeleton_unit.dwarf)?.unwrap();
        ///     let mut convert_split = unit.convert_split(&split_dwarf)?;
        ///     let (split_unit, split_root_entry) = convert_split.read_unit()?;
        ///     // Now you can convert the root entry attributes, and other entries.
        /// }
        /// # unreachable!()
        /// # }
        /// ```
        pub fn convert_split(
            &'a mut self,
            split_dwarf: &'a read::Dwarf<R>,
        ) -> ConvertResult<ConvertSplitUnitSection<'a, R>> {
            ConvertSplitUnitSection::new(self, split_dwarf)
        }

        /// Create a converter for some of the  DIEs in a split DWARF unit and its skeleton unit.
        ///
        /// `filter` determines which DIEs are converted. This can be created using
        /// [`FilterUnitSection::new_split`].
        ///
        /// ## Example
        ///
        /// Convert a split DWARF unit using `convert_split_with_filter`.
        ///
        /// ```rust,no_run
        /// # fn example() -> Result<(), gimli::write::ConvertError> {
        /// # let loader = |name| -> Result<gimli::EndianSlice<gimli::RunTimeEndian>, gimli::Error> { unimplemented!() };
        /// # let need_entry = &|entry: &gimli::write::FilterUnitEntry<_>| -> Result<bool, gimli::write::ConvertError> { Ok(false) };
        /// # let skeleton_unit: gimli::UnitRef<'static, gimli::EndianSlice<gimli::RunTimeEndian>> = unimplemented!();
        /// let dwp = gimli::read::DwarfPackage::load(loader, Default::default())?;
        /// let mut convert: gimli::write::ConvertUnitSection<_> = unimplemented!();
        /// while let Some((mut unit, root_entry)) = convert.read_unit()? {
        ///     let Some(dwo_id) = unit.from_unit.dwo_id else {
        ///         // Not a split unit. Handling omitted for this example.
        ///         continue;
        ///     };
        ///     let split_dwarf = dwp.find_cu(dwo_id, skeleton_unit.dwarf)?.unwrap();
        ///     let mut filter = gimli::write::FilterUnitSection::new_split(&split_dwarf, unit.from_unit)?;
        ///     while let Some(mut unit) = filter.read_unit()? {
        ///         while let Some(entry) = unit.read_entry()? {
        ///             if need_entry(&entry)? {
        ///                 unit.require_entry(entry.offset);
        ///             }
        ///         }
        ///     }
        ///     let mut convert_split = unit.convert_split_with_filter(filter)?;
        ///     let (split_unit, split_root_entry) = convert_split.read_unit()?;
        ///     // Now you can convert the root entry attributes, and other entries.
        /// }
        /// # unreachable!()
        /// # }
        /// ```
        pub fn convert_split_with_filter(
            &'a mut self,
            filter: FilterUnitSection<'a, R>,
        ) -> ConvertResult<ConvertSplitUnitSection<'a, R>> {
            ConvertSplitUnitSection::new_with_filter(self, filter)
        }

        /// Start converting the line number program for this unit.
        ///
        /// `encoding` and `line_encoding` apply to the converted program, and
        /// may be different from the source program. If `None`, the encoding from
        /// the source program is used.
        ///
        /// Returns `Ok(None)` if there is no line number program for this unit.
        ///
        /// See [`ConvertLineProgram`] for an example of converting the program.
        pub fn read_line_program(
            &'_ mut self,
            encoding: Option<Encoding>,
            line_encoding: Option<LineEncoding>,
        ) -> ConvertResult<Option<ConvertLineProgram<'_, R>>> {
            let from_unit = self.from_skeleton_unit.unwrap_or(self.from_unit);
            let Some(from_program) = &from_unit.line_program else {
                return Ok(None);
            };
            ConvertLineProgram::new(
                from_unit.dwarf,
                from_program.clone(),
                // If the program is in a skeleton unit, then pass the name from the split unit.
                self.from_skeleton_unit
                    .and_then(|_| self.from_unit.name.clone()),
                encoding,
                line_encoding,
                self.line_strings,
                self.strings,
            )
            .map(Some)
        }

        /// Sets the converted line program for the unit, and the mapping for converting
        /// file index attributes.
        ///
        /// The parameters are from the result of [`ConvertLineProgram::program`].
        pub fn set_line_program(
            &mut self,
            line_program: LineProgram,
            line_program_files: Vec<FileId>,
        ) {
            self.unit.line_program = line_program;
            self.line_program_files = line_program_files;
        }

        /// Read the next DIE from the input.
        ///
        /// Returns the `UnitEntryId` that was reserved for the entry, if any. If you wish
        /// to use this ID, you must call [`Unit::add_reserved`] or [`ConvertUnit::add_entry`].
        ///
        /// Returns a [`ConvertUnitEntry`] containing information about the DIE and its
        /// attributes.
        ///
        /// Returns `Ok(None)` if there are no more entries.
        // TODO: allow reuse of `ConvertUnitEntry` to avoid allocations?
        pub fn read_entry(
            &mut self,
        ) -> ConvertResult<Option<(Option<UnitEntryId>, ConvertUnitEntry<'a, R>)>> {
            loop {
                if self.from_entries.is_empty() {
                    return Ok(None);
                }

                // Calculate offset and depth before reading the abbreviation code.
                let offset = self.from_entries.next_offset();
                let depth = self.from_entries.next_depth();

                let Some(abbrev) = self.from_entries.read_abbreviation()? else {
                    // Null entry.
                    continue;
                };

                let section_offset = offset.to_unit_section_offset(&self.from_unit);
                let id = self.entry_ids.get(&section_offset).map(|entry| entry.1);

                let mut parent = None;
                while let Some((parent_depth, parent_id)) = self.parents.last().copied() {
                    if parent_depth < depth {
                        parent = Some(parent_id);
                        break;
                    }
                    self.parents.pop();
                }

                if let Some(id) = id {
                    if abbrev.has_children() {
                        self.parents.push((depth, id));
                    }
                }

                let mut entry = ConvertUnitEntry {
                    from_unit: self.from_unit,
                    offset,
                    depth,
                    tag: abbrev.tag(),
                    attrs: Vec::new(),
                    sibling: false,
                    parent,
                };
                entry.read_attributes(&mut self.from_entries, abbrev.attributes())?;
                return Ok(Some((id, entry)));
            }
        }

        /// Add an entry to the converted unit.
        ///
        /// The tag, parent, and `DW_AT_sibling` attribute are set using the
        /// fields of `entry`. No other attributes are copied.
        ///
        /// `id` is the entry ID that was reserved, if any. This is usually the ID that
        /// was returned by [`ConvertUnit::read_entry`]. [`Unit::add_reserved`] will
        /// automatically be called for this ID. If not specified then a new ID is
        /// created.
        ///
        /// Returns the ID of the entry (either reserved or newly created).
        pub fn add_entry(
            &mut self,
            id: Option<UnitEntryId>,
            entry: &ConvertUnitEntry<'_, R>,
        ) -> UnitEntryId {
            let parent = entry.parent.unwrap_or(self.unit.root());
            match id {
                Some(id) => {
                    self.unit.add_reserved(id, parent, entry.tag);
                    self.unit.get_mut(id).set_sibling(entry.sibling);
                    id
                }
                None => {
                    let id = self.unit.add(parent, entry.tag);
                    self.unit.get_mut(id).set_sibling(entry.sibling);
                    id
                }
            }
        }

        /// Write the unit to the given sections.
        ///
        /// This unit will be written immediately, instead of when [`Dwarf::write`] is called.
        /// Note that [`Dwarf::write`] must still be called after all units have been
        /// converted.
        ///
        /// This also frees memory associated with DIEs for this, which is useful for
        /// reducing total memory usage.
        pub fn write<W: Writer>(&mut self, sections: &mut Sections<W>) -> Result<()> {
            let abbrev_offset = sections.debug_abbrev.offset();
            let mut abbrevs = AbbreviationTable::default();
            self.unit.write(
                sections,
                abbrev_offset,
                &mut abbrevs,
                self.line_strings,
                self.strings,
            )?;
            abbrevs.write(&mut sections.debug_abbrev)?;
            self.unit.free();
            Ok(())
        }

        /// Mark this unit as unneeded.
        ///
        /// This unit will not be written, even when [`Dwarf::write`] is called.
        ///
        /// This also frees memory associated with DIEs for this unit, which is useful for
        /// reducing total memory usage.
        pub fn skip(&mut self) {
            self.unit.skip();
            self.unit.free();
        }

        pub(crate) fn convert_attributes(
            &mut self,
            id: UnitEntryId,
            entry: &ConvertUnitEntry<'_, R>,
            convert_address: &dyn Fn(u64) -> Option<Address>,
        ) -> ConvertResult<()> {
            for attr in &entry.attrs {
                if attr.name() == constants::DW_AT_GNU_locviews {
                    // This is a GNU extension that is not supported, and is safe to ignore.
                    // TODO: remove this when we support it.
                } else {
                    let value = self.convert_attribute_value(
                        entry.from_unit,
                        attr.name(),
                        attr.value(),
                        convert_address,
                    )?;
                    self.unit.get_mut(id).set(attr.name(), value);
                }
            }
            Ok(())
        }

        /// Convert an attribute value.
        ///
        /// [`Self::set_line_program`] must be called before converting
        /// file index attributes.
        ///
        /// See [`Dwarf::from`](crate::write::Dwarf::from) for the meaning of `convert_address`.
        pub fn convert_attribute_value(
            &mut self,
            from_unit: read::UnitRef<'_, R>,
            name: constants::DwAt,
            value: read::AttributeValue<R>,
            convert_address: &dyn Fn(u64) -> Option<Address>,
        ) -> ConvertResult<AttributeValue> {
            Ok(match value {
                read::AttributeValue::Addr(val) => match (convert_address)(val) {
                    Some(val) => AttributeValue::Address(val),
                    None => return Err(ConvertError::InvalidAddress),
                },
                read::AttributeValue::Block(r) => AttributeValue::Block(r.to_slice()?.into()),
                read::AttributeValue::Data1(val) => AttributeValue::Data1(val),
                read::AttributeValue::Data2(val) => AttributeValue::Data2(val),
                read::AttributeValue::Data4(val) => AttributeValue::Data4(val),
                read::AttributeValue::Data8(val) => AttributeValue::Data8(val),
                read::AttributeValue::Data16(val) => AttributeValue::Data16(val),
                read::AttributeValue::Sdata(val) => AttributeValue::Sdata(val),
                read::AttributeValue::Udata(val) => AttributeValue::Udata(val),
                read::AttributeValue::Exprloc(expression) => {
                    if name == constants::DW_AT_vtable_elem_location {
                        let bytecode = expression.0.to_slice()?;
                        if bytecode.first().copied() == Some(constants::DW_OP_constu.0) {
                            // This is a vtable index. We must preserve the DW_OP_constu
                            // operation because gdb checks for it.
                            // `convert_expression` is unsuitable because it may convert
                            // to something like DW_OP_lit0.
                            return Ok(AttributeValue::Exprloc(Expression::raw(bytecode.to_vec())));
                        }
                    }
                    let expression =
                        self.convert_expression(from_unit, expression, convert_address)?;
                    AttributeValue::Exprloc(expression)
                }
                // TODO: it would be nice to preserve the flag form.
                read::AttributeValue::Flag(val) => AttributeValue::Flag(val),
                read::AttributeValue::DebugAddrIndex(index) => {
                    let val = from_unit.address(index)?;
                    match convert_address(val) {
                        Some(val) => AttributeValue::Address(val),
                        None => return Err(ConvertError::InvalidAddress),
                    }
                }
                read::AttributeValue::UnitRef(val) => {
                    // TODO: must not be in the skeleton unit
                    AttributeValue::UnitRef(self.convert_unit_ref(val)?)
                }
                read::AttributeValue::DebugInfoRef(val) => {
                    // TODO: must not be in the skeleton unit
                    AttributeValue::DebugInfoRef(self.convert_debug_info_ref(val)?)
                }
                read::AttributeValue::DebugInfoRefSup(val) => AttributeValue::DebugInfoRefSup(val),
                read::AttributeValue::DebugLineRef(val) => {
                    // There should only be a ref to the line program in the CU DIE.
                    if Some(val)
                        != from_unit
                            .line_program
                            .as_ref()
                            .map(|program| program.header().offset())
                    {
                        return Err(ConvertError::InvalidLineRef);
                    };
                    AttributeValue::LineProgramRef
                }
                read::AttributeValue::DebugMacinfoRef(val) => AttributeValue::DebugMacinfoRef(val),
                read::AttributeValue::DebugMacroRef(val) => AttributeValue::DebugMacroRef(val),
                read::AttributeValue::LocationListsRef(val) => {
                    let loc_list = self.convert_location_list(from_unit, val, convert_address)?;
                    let loc_id = self.unit.locations.add(loc_list);
                    AttributeValue::LocationListRef(loc_id)
                }
                read::AttributeValue::DebugLocListsIndex(index) => {
                    let offset = from_unit.locations_offset(index)?;
                    let loc_list =
                        self.convert_location_list(from_unit, offset, convert_address)?;
                    let loc_id = self.unit.locations.add(loc_list);
                    AttributeValue::LocationListRef(loc_id)
                }
                read::AttributeValue::RangeListsRef(offset) => {
                    let offset = from_unit.ranges_offset_from_raw(offset);
                    let range_list = self.convert_range_list(from_unit, offset, convert_address)?;
                    let range_id = self.unit.ranges.add(range_list);
                    AttributeValue::RangeListRef(range_id)
                }
                read::AttributeValue::DebugRngListsIndex(index) => {
                    let offset = from_unit.ranges_offset(index)?;
                    let range_list = self.convert_range_list(from_unit, offset, convert_address)?;
                    let range_id = self.unit.ranges.add(range_list);
                    AttributeValue::RangeListRef(range_id)
                }
                read::AttributeValue::DebugTypesRef(val) => AttributeValue::DebugTypesRef(val),
                read::AttributeValue::DebugStrRef(offset) => {
                    let r = from_unit.string(offset)?;
                    let id = self.strings.add(r.to_slice()?);
                    AttributeValue::StringRef(id)
                }
                read::AttributeValue::DebugStrRefSup(val) => AttributeValue::DebugStrRefSup(val),
                read::AttributeValue::DebugStrOffsetsIndex(index) => {
                    let offset = from_unit.string_offset(index)?;
                    let r = from_unit.string(offset)?;
                    let id = self.strings.add(r.to_slice()?);
                    AttributeValue::StringRef(id)
                }
                read::AttributeValue::DebugLineStrRef(offset) => {
                    let r = from_unit.line_string(offset)?;
                    let id = self.line_strings.add(r.to_slice()?);
                    AttributeValue::LineStringRef(id)
                }
                read::AttributeValue::String(r) => AttributeValue::String(r.to_slice()?.into()),
                read::AttributeValue::Encoding(val) => AttributeValue::Encoding(val),
                read::AttributeValue::DecimalSign(val) => AttributeValue::DecimalSign(val),
                read::AttributeValue::Endianity(val) => AttributeValue::Endianity(val),
                read::AttributeValue::Accessibility(val) => AttributeValue::Accessibility(val),
                read::AttributeValue::Visibility(val) => AttributeValue::Visibility(val),
                read::AttributeValue::Virtuality(val) => AttributeValue::Virtuality(val),
                read::AttributeValue::Language(val) => AttributeValue::Language(val),
                read::AttributeValue::AddressClass(val) => AttributeValue::AddressClass(val),
                read::AttributeValue::IdentifierCase(val) => AttributeValue::IdentifierCase(val),
                read::AttributeValue::CallingConvention(val) => {
                    AttributeValue::CallingConvention(val)
                }
                read::AttributeValue::Inline(val) => AttributeValue::Inline(val),
                read::AttributeValue::Ordering(val) => AttributeValue::Ordering(val),
                read::AttributeValue::FileIndex(val) => {
                    AttributeValue::FileIndex(self.convert_file_index(from_unit, val)?)
                }
                read::AttributeValue::DwoId(DwoId(val)) => AttributeValue::Udata(val),
                // Should always be a more specific section reference.
                read::AttributeValue::SecOffset(_) => {
                    return Err(ConvertError::InvalidAttributeValue);
                }
                // These are only used for metadata attributes, and should have
                // been skipped already.
                read::AttributeValue::DebugAddrBase(_)
                | read::AttributeValue::DebugLocListsBase(_)
                | read::AttributeValue::DebugRngListsBase(_)
                | read::AttributeValue::DebugStrOffsetsBase(_) => {
                    return Err(ConvertError::InvalidAttributeValue);
                }
            })
        }

        /// Convert an expression.
        ///
        /// See [`Dwarf::from`](crate::write::Dwarf::from) for the meaning of `convert_address`.
        pub fn convert_expression(
            &self,
            from_unit: read::UnitRef<'_, R>,
            expression: read::Expression<R>,
            convert_address: &dyn Fn(u64) -> Option<Address>,
        ) -> ConvertResult<Expression> {
            Expression::from(
                expression,
                from_unit.encoding(),
                Some(from_unit),
                convert_address,
                self,
            )
        }

        /// Convert a file index from a `DW_AT_decl_file` or similar attribute.
        ///
        /// [`Self::set_line_program`] must be called before converting
        /// file index attributes.
        pub fn convert_file_index(
            &self,
            from_unit: read::UnitRef<'_, R>,
            index: u64,
        ) -> ConvertResult<Option<FileId>> {
            if index == 0 && from_unit.encoding().version <= 4 {
                return Ok(None);
            }
            match self.line_program_files.get(index as usize) {
                Some(id) => Ok(Some(*id)),
                None => Err(ConvertError::InvalidFileIndex),
            }
        }

        /// Convert a location list.
        ///
        /// See [`Dwarf::from`](crate::write::Dwarf::from) for the meaning of `convert_address`.
        pub fn convert_location_list(
            &self,
            from_unit: read::UnitRef<'_, R>,
            offset: LocationListsOffset,
            convert_address: &dyn Fn(u64) -> Option<Address>,
        ) -> ConvertResult<LocationList> {
            let iter = from_unit.raw_locations(offset)?;
            LocationList::from(iter, from_unit, convert_address, self)
        }

        /// Convert a range list.
        ///
        /// See [`Dwarf::from`](crate::write::Dwarf::from) for the meaning of `convert_address`.
        pub fn convert_range_list(
            &self,
            from_unit: read::UnitRef<'_, R>,
            offset: RangeListsOffset,
            convert_address: &dyn Fn(u64) -> Option<Address>,
        ) -> ConvertResult<RangeList> {
            let iter = from_unit.raw_ranges(offset)?;
            RangeList::from(iter, from_unit, convert_address)
        }

        /// Convert a reference to an entry in the same unit.
        ///
        /// This conversion doesn't work for references from a skeleton unit,
        /// but those shouldn't occur in practice.
        pub fn convert_unit_ref(&self, entry: read::UnitOffset) -> ConvertResult<UnitEntryId> {
            if !entry.is_in_bounds(&self.from_unit) {
                return Err(ConvertError::InvalidUnitRef);
            }
            let id = self
                .entry_ids
                .get(&entry.to_unit_section_offset(&self.from_unit))
                .ok_or(ConvertError::InvalidUnitRef)?;
            Ok(id.1)
        }

        /// Convert a `.debug_info` reference.
        ///
        /// This conversion doesn't work for references from a skeleton unit,
        /// but those shouldn't occur in practice.
        pub fn convert_debug_info_ref(
            &self,
            entry: DebugInfoOffset,
        ) -> ConvertResult<DebugInfoRef> {
            // TODO: support relocation of this value
            let id = self
                .entry_ids
                .get(&UnitSectionOffset::DebugInfoOffset(entry))
                .ok_or(ConvertError::InvalidDebugInfoRef)?;
            Ok(DebugInfoRef::Entry(id.0, id.1))
        }
    }

    /// A DIE read by [`ConvertUnit::read_entry`].
    #[derive(Debug)]
    #[non_exhaustive]
    pub struct ConvertUnitEntry<'a, R: Reader<Offset = usize>> {
        /// The unit that this DIE was read from.
        ///
        /// This may be a skeleton unit.
        pub from_unit: read::UnitRef<'a, R>,
        /// The offset of this DIE within the unit.
        pub offset: read::UnitOffset,
        /// The depth of this DIE in the tree.
        ///
        /// This may be useful for maintaining a stack of state corresponding to the
        /// parent entries.
        pub depth: isize,
        /// The tag that was read for this DIE.
        pub tag: constants::DwTag,
        /// The attributes that were read for this DIE.
        ///
        /// This excludes attributes for DWARF metadata.
        pub attrs: Vec<read::Attribute<R>>,
        /// True if the `DW_AT_sibling` attribute was present.
        pub sibling: bool,
        /// The id of the entry that was reserved for this DIE's parent, if any.
        ///
        /// You may ignore this value if you wish to use a different parent.
        /// This is set to `None` if the parent is unknown or is the root DIE.
        pub parent: Option<UnitEntryId>,
    }

    impl<'a, R: Reader<Offset = usize>> ConvertUnitEntry<'a, R> {
        /// Read the DIE at the given offset.
        ///
        /// This does not affect the state of the reader.
        /// The returned entry will not have a valid `depth` or `parent`.
        /// This may be used for entries that were not filtered or reserved.
        ///
        /// Returns an error if there is no entry at the given offset.
        pub fn read(
            from_unit: read::UnitRef<'a, R>,
            offset: read::UnitOffset,
        ) -> ConvertResult<ConvertUnitEntry<'a, R>> {
            let mut from_entries = from_unit.entries_raw(Some(offset))?;
            let Some(abbrev) = from_entries.read_abbreviation()? else {
                // Null entry.
                return Err(read::Error::NoEntryAtGivenOffset.into());
            };

            let mut entry = ConvertUnitEntry {
                from_unit,
                offset,
                depth: 0,
                tag: abbrev.tag(),
                attrs: Vec::new(),
                sibling: false,
                parent: None,
            };
            entry.read_attributes(&mut from_entries, abbrev.attributes())?;
            Ok(entry)
        }

        fn read_attributes(
            &mut self,
            from_entries: &mut read::EntriesRaw<'_, '_, R>,
            specs: &[read::AttributeSpecification],
        ) -> ConvertResult<()> {
            for spec in specs {
                let attr = from_entries.read_attribute(*spec)?;
                match attr.name() {
                    // This may point to a null entry, so we have to treat it differently.
                    constants::DW_AT_sibling => self.sibling = true,
                    // Skip DWARF metadata attributes.
                    // TODO: should DWO attributes be conditionally kept?
                    constants::DW_AT_str_offsets_base
                    | constants::DW_AT_addr_base
                    | constants::DW_AT_rnglists_base
                    | constants::DW_AT_loclists_base
                    | constants::DW_AT_dwo_name
                    | constants::DW_AT_GNU_addr_base
                    | constants::DW_AT_GNU_ranges_base
                    | constants::DW_AT_GNU_dwo_name
                    | constants::DW_AT_GNU_dwo_id => {}
                    _ => self.attrs.push(attr),
                }
            }
            Ok(())
        }

        /// Return `true` if this entry has an attribute with the given name.
        pub fn has_attr(&self, name: constants::DwAt) -> bool {
            self.attrs.iter().any(|attr| attr.name() == name)
        }

        /// Find the value of the first attribute with the given name.
        pub fn attr_value(&self, name: constants::DwAt) -> Option<read::AttributeValue<R>> {
            self.attrs
                .iter()
                .find(|attr| attr.name() == name)
                .map(|attr| attr.value())
        }
    }

    pub(crate) trait ConvertDebugInfoRef {
        fn convert_unit_ref(&self, entry: read::UnitOffset) -> ConvertResult<UnitEntryId>;
        fn convert_debug_info_ref(&self, entry: DebugInfoOffset) -> ConvertResult<DebugInfoRef>;
    }

    impl<'a, R: Reader<Offset = usize>> ConvertDebugInfoRef for ConvertUnit<'a, R> {
        fn convert_unit_ref(&self, entry: read::UnitOffset) -> ConvertResult<UnitEntryId> {
            ConvertUnit::convert_unit_ref(self, entry)
        }

        fn convert_debug_info_ref(&self, entry: DebugInfoOffset) -> ConvertResult<DebugInfoRef> {
            ConvertUnit::convert_debug_info_ref(self, entry)
        }
    }

    pub(crate) struct NoConvertDebugInfoRef;

    impl ConvertDebugInfoRef for NoConvertDebugInfoRef {
        fn convert_unit_ref(&self, _entry: read::UnitOffset) -> ConvertResult<UnitEntryId> {
            Err(ConvertError::InvalidUnitRef)
        }

        fn convert_debug_info_ref(&self, _entry: DebugInfoOffset) -> ConvertResult<DebugInfoRef> {
            Err(ConvertError::InvalidDebugInfoRef)
        }
    }
}

#[cfg(test)]
#[cfg(feature = "read")]
mod tests {
    use super::*;
    use crate::LittleEndian;
    use crate::common::LineEncoding;
    use crate::constants;
    use crate::read;
    use crate::write::{
        Dwarf, DwarfUnit, EndianVec, LineString, Location, LocationList, Range, RangeList,
    };
    use std::mem;

    #[test]
    fn test_unit_table() {
        let mut dwarf = Dwarf::new();
        let unit_id1 = dwarf.units.add(Unit::new(
            Encoding {
                version: 4,
                address_size: 8,
                format: Format::Dwarf32,
            },
            LineProgram::none(),
        ));
        let unit2 = dwarf.units.add(Unit::new(
            Encoding {
                version: 2,
                address_size: 4,
                format: Format::Dwarf64,
            },
            LineProgram::none(),
        ));
        let unit3 = dwarf.units.add(Unit::new(
            Encoding {
                version: 5,
                address_size: 4,
                format: Format::Dwarf32,
            },
            LineProgram::none(),
        ));
        assert_eq!(dwarf.units.count(), 3);
        {
            let unit1 = dwarf.units.get_mut(unit_id1);
            assert_eq!(unit1.version(), 4);
            assert_eq!(unit1.address_size(), 8);
            assert_eq!(unit1.format(), Format::Dwarf32);
            assert_eq!(unit1.count(), 1);

            let root_id = unit1.root();
            assert_eq!(root_id, UnitEntryId::new(unit1.base_id, 0));
            {
                let root = unit1.get_mut(root_id);
                assert_eq!(root.id(), root_id);
                assert!(root.parent().is_none());
                assert_eq!(root.tag(), constants::DW_TAG_compile_unit);

                // Test get/get_mut
                assert!(root.get(constants::DW_AT_producer).is_none());
                assert!(root.get_mut(constants::DW_AT_producer).is_none());
                let mut producer = AttributeValue::String(b"root"[..].into());
                root.set(constants::DW_AT_producer, producer.clone());
                assert_eq!(root.get(constants::DW_AT_producer), Some(&producer));
                assert_eq!(root.get_mut(constants::DW_AT_producer), Some(&mut producer));

                // Test attrs
                let mut attrs = root.attrs();
                let attr = attrs.next().unwrap();
                assert_eq!(attr.name(), constants::DW_AT_producer);
                assert_eq!(attr.get(), &producer);
                assert!(attrs.next().is_none());
            }

            let child1 = unit1.add(root_id, constants::DW_TAG_subprogram);
            assert_eq!(child1, UnitEntryId::new(unit1.base_id, 1));
            {
                let child1 = unit1.get_mut(child1);
                assert_eq!(child1.parent(), Some(root_id));

                let tmp = AttributeValue::String(b"tmp"[..].into());
                child1.set(constants::DW_AT_name, tmp.clone());
                assert_eq!(child1.get(constants::DW_AT_name), Some(&tmp));

                // Test attrs_mut
                let name = AttributeValue::StringRef(dwarf.strings.add(&b"child1"[..]));
                {
                    let attr = child1.attrs_mut().next().unwrap();
                    assert_eq!(attr.name(), constants::DW_AT_name);
                    attr.set(name.clone());
                }
                assert_eq!(child1.get(constants::DW_AT_name), Some(&name));
            }

            let child2 = unit1.add(root_id, constants::DW_TAG_subprogram);
            assert_eq!(child2, UnitEntryId::new(unit1.base_id, 2));
            {
                let child2 = unit1.get_mut(child2);
                assert_eq!(child2.parent(), Some(root_id));

                let tmp = AttributeValue::String(b"tmp"[..].into());
                child2.set(constants::DW_AT_name, tmp.clone());
                assert_eq!(child2.get(constants::DW_AT_name), Some(&tmp));

                // Test replace
                let name = AttributeValue::StringRef(dwarf.strings.add(&b"child2"[..]));
                child2.set(constants::DW_AT_name, name.clone());
                assert_eq!(child2.get(constants::DW_AT_name), Some(&name));
            }

            {
                let root = unit1.get(root_id);
                assert_eq!(
                    root.children().cloned().collect::<Vec<_>>(),
                    vec![child1, child2]
                );
            }
        }
        {
            let unit2 = dwarf.units.get(unit2);
            assert_eq!(unit2.version(), 2);
            assert_eq!(unit2.address_size(), 4);
            assert_eq!(unit2.format(), Format::Dwarf64);
            assert_eq!(unit2.count(), 1);

            let root = unit2.root();
            assert_eq!(root, UnitEntryId::new(unit2.base_id, 0));
            let root = unit2.get(root);
            assert_eq!(root.id(), UnitEntryId::new(unit2.base_id, 0));
            assert!(root.parent().is_none());
            assert_eq!(root.tag(), constants::DW_TAG_compile_unit);
        }

        let mut sections = Sections::new(EndianVec::new(LittleEndian));
        dwarf.write(&mut sections).unwrap();

        println!("{:?}", sections.debug_str);
        println!("{:?}", sections.debug_info);
        println!("{:?}", sections.debug_abbrev);

        let read_dwarf = sections.read(LittleEndian);
        let mut read_units = read_dwarf.units();

        {
            let read_unit1 = read_units.next().unwrap().unwrap();
            let unit1 = dwarf.units.get(unit_id1);
            assert_eq!(unit1.version(), read_unit1.version());
            assert_eq!(unit1.address_size(), read_unit1.address_size());
            assert_eq!(unit1.format(), read_unit1.format());

            let read_unit1 = read_dwarf.unit(read_unit1).unwrap();
            let mut read_entries = read_unit1.entries();

            let root = unit1.get(unit1.root());
            {
                let (depth, read_root) = read_entries.next_dfs().unwrap().unwrap();
                assert_eq!(depth, 0);
                assert_eq!(root.tag(), read_root.tag());
                assert!(read_root.has_children());

                let producer = match root.get(constants::DW_AT_producer).unwrap() {
                    AttributeValue::String(producer) => &**producer,
                    otherwise => panic!("unexpected {:?}", otherwise),
                };
                assert_eq!(producer, b"root");
                let read_producer = read_root
                    .attr_value(constants::DW_AT_producer)
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    read_dwarf
                        .attr_string(&read_unit1, read_producer)
                        .unwrap()
                        .slice(),
                    producer
                );
            }

            let mut children = root.children().cloned();

            {
                let child = children.next().unwrap();
                assert_eq!(child, UnitEntryId::new(unit1.base_id, 1));
                let child = unit1.get(child);
                let (depth, read_child) = read_entries.next_dfs().unwrap().unwrap();
                assert_eq!(depth, 1);
                assert_eq!(child.tag(), read_child.tag());
                assert!(!read_child.has_children());

                let name = match child.get(constants::DW_AT_name).unwrap() {
                    AttributeValue::StringRef(name) => *name,
                    otherwise => panic!("unexpected {:?}", otherwise),
                };
                let name = dwarf.strings.get(name);
                assert_eq!(name, b"child1");
                let read_name = read_child
                    .attr_value(constants::DW_AT_name)
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    read_dwarf
                        .attr_string(&read_unit1, read_name)
                        .unwrap()
                        .slice(),
                    name
                );
            }

            {
                let child = children.next().unwrap();
                assert_eq!(child, UnitEntryId::new(unit1.base_id, 2));
                let child = unit1.get(child);
                let (depth, read_child) = read_entries.next_dfs().unwrap().unwrap();
                assert_eq!(depth, 0);
                assert_eq!(child.tag(), read_child.tag());
                assert!(!read_child.has_children());

                let name = match child.get(constants::DW_AT_name).unwrap() {
                    AttributeValue::StringRef(name) => *name,
                    otherwise => panic!("unexpected {:?}", otherwise),
                };
                let name = dwarf.strings.get(name);
                assert_eq!(name, b"child2");
                let read_name = read_child
                    .attr_value(constants::DW_AT_name)
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    read_dwarf
                        .attr_string(&read_unit1, read_name)
                        .unwrap()
                        .slice(),
                    name
                );
            }

            assert!(read_entries.next_dfs().unwrap().is_none());
        }

        {
            let read_unit2 = read_units.next().unwrap().unwrap();
            let unit2 = dwarf.units.get(unit2);
            assert_eq!(unit2.version(), read_unit2.version());
            assert_eq!(unit2.address_size(), read_unit2.address_size());
            assert_eq!(unit2.format(), read_unit2.format());

            let abbrevs = read_dwarf.abbreviations(&read_unit2).unwrap();
            let mut read_entries = read_unit2.entries(&abbrevs);

            {
                let root = unit2.get(unit2.root());
                let (depth, read_root) = read_entries.next_dfs().unwrap().unwrap();
                assert_eq!(depth, 0);
                assert_eq!(root.tag(), read_root.tag());
                assert!(!read_root.has_children());
            }

            assert!(read_entries.next_dfs().unwrap().is_none());
        }

        {
            let read_unit3 = read_units.next().unwrap().unwrap();
            let unit3 = dwarf.units.get(unit3);
            assert_eq!(unit3.version(), read_unit3.version());
            assert_eq!(unit3.address_size(), read_unit3.address_size());
            assert_eq!(unit3.format(), read_unit3.format());

            let abbrevs = read_dwarf.abbreviations(&read_unit3).unwrap();
            let mut read_entries = read_unit3.entries(&abbrevs);

            {
                let root = unit3.get(unit3.root());
                let (depth, read_root) = read_entries.next_dfs().unwrap().unwrap();
                assert_eq!(depth, 0);
                assert_eq!(root.tag(), read_root.tag());
                assert!(!read_root.has_children());
            }

            assert!(read_entries.next_dfs().unwrap().is_none());
        }

        assert!(read_units.next().unwrap().is_none());

        let convert_dwarf =
            Dwarf::from(&read_dwarf, &|address| Some(Address::Constant(address))).unwrap();
        assert_eq!(convert_dwarf.units.count(), dwarf.units.count());

        for i in 0..convert_dwarf.units.count() {
            let unit_id = dwarf.units.id(i);
            let unit = dwarf.units.get(unit_id);
            let convert_unit_id = convert_dwarf.units.id(i);
            let convert_unit = convert_dwarf.units.get(convert_unit_id);
            assert_eq!(convert_unit.version(), unit.version());
            assert_eq!(convert_unit.address_size(), unit.address_size());
            assert_eq!(convert_unit.format(), unit.format());
            assert_eq!(convert_unit.count(), unit.count());

            let root = unit.get(unit.root());
            let convert_root = convert_unit.get(convert_unit.root());
            assert_eq!(convert_root.tag(), root.tag());
            for (convert_attr, attr) in convert_root.attrs().zip(root.attrs()) {
                assert_eq!(convert_attr, attr);
            }
        }
    }

    #[test]
    fn test_attribute_value() {
        let string_data = "string data";
        let line_string_data = "line string data";

        let data = vec![1, 2, 3, 4];
        let read_data = read::EndianSlice::new(&[1, 2, 3, 4], LittleEndian);

        let mut expression = Expression::new();
        expression.op_constu(57);
        let read_expression = read::Expression(read::EndianSlice::new(
            &[constants::DW_OP_constu.0, 57],
            LittleEndian,
        ));

        let range = RangeList(vec![Range::StartEnd {
            begin: Address::Constant(0x1234),
            end: Address::Constant(0x2345),
        }]);

        let location = LocationList(vec![Location::StartEnd {
            begin: Address::Constant(0x1234),
            end: Address::Constant(0x2345),
            data: expression.clone(),
        }]);

        for &version in &[2, 3, 4, 5] {
            for &address_size in &[4, 8] {
                for &format in &[Format::Dwarf32, Format::Dwarf64] {
                    let encoding = Encoding {
                        format,
                        version,
                        address_size,
                    };

                    let mut dwarf = Dwarf::new();
                    let unit = dwarf.units.add(Unit::new(encoding, LineProgram::none()));
                    let unit = dwarf.units.get_mut(unit);
                    let loc_id = unit.locations.add(location.clone());
                    let range_id = unit.ranges.add(range.clone());
                    // Create a string with a non-zero id/offset.
                    dwarf.strings.add("dummy string");
                    let string_id = dwarf.strings.add(string_data);
                    dwarf.line_strings.add("dummy line string");
                    let line_string_id = dwarf.line_strings.add(line_string_data);

                    let attributes = &[
                        (
                            constants::DW_AT_name,
                            AttributeValue::Address(Address::Constant(0x1234)),
                            read::AttributeValue::Addr(0x1234),
                        ),
                        (
                            constants::DW_AT_name,
                            AttributeValue::Block(data.clone()),
                            read::AttributeValue::Block(read_data),
                        ),
                        (
                            constants::DW_AT_name,
                            AttributeValue::Data1(0x12),
                            read::AttributeValue::Data1(0x12),
                        ),
                        (
                            constants::DW_AT_name,
                            AttributeValue::Data2(0x1234),
                            read::AttributeValue::Data2(0x1234),
                        ),
                        (
                            constants::DW_AT_name,
                            AttributeValue::Data4(0x1234),
                            read::AttributeValue::Data4(0x1234),
                        ),
                        (
                            constants::DW_AT_name,
                            AttributeValue::Data8(0x1234),
                            read::AttributeValue::Data8(0x1234),
                        ),
                        (
                            constants::DW_AT_name,
                            AttributeValue::Data16(0x1234),
                            read::AttributeValue::Data16(0x1234),
                        ),
                        (
                            constants::DW_AT_name,
                            AttributeValue::Sdata(0x1234),
                            read::AttributeValue::Sdata(0x1234),
                        ),
                        (
                            constants::DW_AT_name,
                            AttributeValue::Udata(0x1234),
                            read::AttributeValue::Udata(0x1234),
                        ),
                        (
                            constants::DW_AT_name,
                            AttributeValue::Exprloc(expression.clone()),
                            read::AttributeValue::Exprloc(read_expression),
                        ),
                        (
                            constants::DW_AT_name,
                            AttributeValue::Flag(false),
                            read::AttributeValue::Flag(false),
                        ),
                        /*
                        (
                            constants::DW_AT_name,
                            AttributeValue::FlagPresent,
                            read::AttributeValue::Flag(true),
                        ),
                        */
                        (
                            constants::DW_AT_name,
                            AttributeValue::DebugInfoRefSup(DebugInfoOffset(0x1234)),
                            read::AttributeValue::DebugInfoRefSup(DebugInfoOffset(0x1234)),
                        ),
                        (
                            constants::DW_AT_macro_info,
                            AttributeValue::DebugMacinfoRef(DebugMacinfoOffset(0x1234)),
                            read::AttributeValue::SecOffset(0x1234),
                        ),
                        (
                            constants::DW_AT_macros,
                            AttributeValue::DebugMacroRef(DebugMacroOffset(0x1234)),
                            read::AttributeValue::SecOffset(0x1234),
                        ),
                        (
                            constants::DW_AT_name,
                            AttributeValue::DebugTypesRef(DebugTypeSignature(0x1234)),
                            read::AttributeValue::DebugTypesRef(DebugTypeSignature(0x1234)),
                        ),
                        (
                            constants::DW_AT_name,
                            AttributeValue::DebugStrRefSup(DebugStrOffset(0x1234)),
                            read::AttributeValue::DebugStrRefSup(DebugStrOffset(0x1234)),
                        ),
                        (
                            constants::DW_AT_name,
                            AttributeValue::String(data.clone()),
                            read::AttributeValue::String(read_data),
                        ),
                        (
                            constants::DW_AT_encoding,
                            AttributeValue::Encoding(constants::DwAte(0x12)),
                            read::AttributeValue::Udata(0x12),
                        ),
                        (
                            constants::DW_AT_decimal_sign,
                            AttributeValue::DecimalSign(constants::DwDs(0x12)),
                            read::AttributeValue::Udata(0x12),
                        ),
                        (
                            constants::DW_AT_endianity,
                            AttributeValue::Endianity(constants::DwEnd(0x12)),
                            read::AttributeValue::Udata(0x12),
                        ),
                        (
                            constants::DW_AT_accessibility,
                            AttributeValue::Accessibility(constants::DwAccess(0x12)),
                            read::AttributeValue::Udata(0x12),
                        ),
                        (
                            constants::DW_AT_visibility,
                            AttributeValue::Visibility(constants::DwVis(0x12)),
                            read::AttributeValue::Udata(0x12),
                        ),
                        (
                            constants::DW_AT_virtuality,
                            AttributeValue::Virtuality(constants::DwVirtuality(0x12)),
                            read::AttributeValue::Udata(0x12),
                        ),
                        (
                            constants::DW_AT_language,
                            AttributeValue::Language(constants::DwLang(0x12)),
                            read::AttributeValue::Udata(0x12),
                        ),
                        (
                            constants::DW_AT_address_class,
                            AttributeValue::AddressClass(constants::DwAddr(0x12)),
                            read::AttributeValue::Udata(0x12),
                        ),
                        (
                            constants::DW_AT_identifier_case,
                            AttributeValue::IdentifierCase(constants::DwId(0x12)),
                            read::AttributeValue::Udata(0x12),
                        ),
                        (
                            constants::DW_AT_calling_convention,
                            AttributeValue::CallingConvention(constants::DwCc(0x12)),
                            read::AttributeValue::Udata(0x12),
                        ),
                        (
                            constants::DW_AT_ordering,
                            AttributeValue::Ordering(constants::DwOrd(0x12)),
                            read::AttributeValue::Udata(0x12),
                        ),
                        (
                            constants::DW_AT_inline,
                            AttributeValue::Inline(constants::DwInl(0x12)),
                            read::AttributeValue::Udata(0x12),
                        ),
                    ];

                    let mut add_attribute = |name, value| {
                        let entry_id = unit.add(unit.root(), constants::DW_TAG_subprogram);
                        let entry = unit.get_mut(entry_id);
                        entry.set(name, value);
                    };
                    for (name, value, _) in attributes {
                        add_attribute(*name, value.clone());
                    }
                    add_attribute(
                        constants::DW_AT_location,
                        AttributeValue::LocationListRef(loc_id),
                    );
                    add_attribute(
                        constants::DW_AT_ranges,
                        AttributeValue::RangeListRef(range_id),
                    );
                    add_attribute(constants::DW_AT_name, AttributeValue::StringRef(string_id));
                    add_attribute(
                        constants::DW_AT_name,
                        AttributeValue::LineStringRef(line_string_id),
                    );

                    let mut sections = Sections::new(EndianVec::new(LittleEndian));
                    dwarf.write(&mut sections).unwrap();

                    let read_dwarf = sections.read(LittleEndian);
                    let mut read_units = read_dwarf.units();
                    let read_unit = read_units.next().unwrap().unwrap();
                    let read_unit = read_dwarf.unit(read_unit).unwrap();
                    let read_unit = read_unit.unit_ref(&read_dwarf);
                    let mut read_entries = read_unit.entries();
                    let (_, _root) = read_entries.next_dfs().unwrap().unwrap();

                    let mut get_attribute = |name| {
                        let (_, entry) = read_entries.next_dfs().unwrap().unwrap();
                        entry.attr(name).unwrap().unwrap()
                    };
                    for (name, _, expect_value) in attributes {
                        let read_value = &get_attribute(*name).raw_value();
                        // read::AttributeValue is invariant in the lifetime of R.
                        // The lifetimes here are all okay, so transmute it.
                        let read_value = unsafe {
                            mem::transmute::<
                                &read::AttributeValue<read::EndianSlice<'_, LittleEndian>>,
                                &read::AttributeValue<read::EndianSlice<'_, LittleEndian>>,
                            >(read_value)
                        };
                        assert_eq!(read_value, expect_value);
                    }

                    let read_attr = get_attribute(constants::DW_AT_location).value();
                    let read::AttributeValue::LocationListsRef(read_loc_offset) = read_attr else {
                        panic!("unexpected {:?}", read_attr);
                    };
                    let mut read_locations = read_unit.locations(read_loc_offset).unwrap();
                    let read_location = read_locations.next().unwrap().unwrap();
                    assert_eq!(read_location.range.begin, 0x1234);
                    assert_eq!(read_location.range.end, 0x2345);
                    assert_eq!(read_location.data, read_expression);

                    let read_attr = get_attribute(constants::DW_AT_ranges).value();
                    let read::AttributeValue::RangeListsRef(read_range_offset) = read_attr else {
                        panic!("unexpected {:?}", read_attr);
                    };
                    let read_range_offset = read_unit.ranges_offset_from_raw(read_range_offset);
                    let mut read_ranges = read_unit.ranges(read_range_offset).unwrap();
                    let read_range = read_ranges.next().unwrap().unwrap();
                    assert_eq!(read_range.begin, 0x1234);
                    assert_eq!(read_range.end, 0x2345);

                    let read_string = get_attribute(constants::DW_AT_name).raw_value();
                    let read::AttributeValue::DebugStrRef(read_string_offset) = read_string else {
                        panic!("unexpected {:?}", read_string);
                    };
                    assert_eq!(
                        read_dwarf.string(read_string_offset).unwrap().slice(),
                        string_data.as_bytes()
                    );

                    let read_line_string = get_attribute(constants::DW_AT_name).raw_value();
                    let read::AttributeValue::DebugLineStrRef(read_line_string_offset) =
                        read_line_string
                    else {
                        panic!("unexpected {:?}", read_line_string);
                    };
                    assert_eq!(
                        read_dwarf
                            .line_string(read_line_string_offset)
                            .unwrap()
                            .slice(),
                        line_string_data.as_bytes()
                    );

                    let convert_dwarf =
                        Dwarf::from(&read_dwarf, &|address| Some(Address::Constant(address)))
                            .unwrap();
                    let convert_unit = convert_dwarf.units.get(convert_dwarf.units.id(0));
                    let convert_root = convert_unit.get(convert_unit.root());
                    let mut convert_entries = convert_root.children();

                    let mut get_convert_attr = |name| {
                        let convert_entry = convert_unit.get(*convert_entries.next().unwrap());
                        convert_entry.get(name).unwrap()
                    };
                    for (name, attr, _) in attributes {
                        let convert_attr = get_convert_attr(*name);
                        assert_eq!(convert_attr, attr);
                    }

                    let convert_attr = get_convert_attr(constants::DW_AT_location);
                    let AttributeValue::LocationListRef(convert_loc_id) = convert_attr else {
                        panic!("unexpected {:?}", convert_attr);
                    };
                    let convert_location = convert_unit.locations.get(*convert_loc_id);
                    assert_eq!(*convert_location, location);

                    let convert_attr = get_convert_attr(constants::DW_AT_ranges);
                    let AttributeValue::RangeListRef(convert_range_id) = convert_attr else {
                        panic!("unexpected {:?}", convert_attr);
                    };
                    let convert_range = convert_unit.ranges.get(*convert_range_id);
                    assert_eq!(*convert_range, range);

                    let convert_attr = get_convert_attr(constants::DW_AT_name);
                    let AttributeValue::StringRef(convert_string_id) = convert_attr else {
                        panic!("unexpected {:?}", convert_attr);
                    };
                    let convert_string = convert_dwarf.strings.get(*convert_string_id);
                    assert_eq!(convert_string, string_data.as_bytes());

                    let convert_attr = get_convert_attr(constants::DW_AT_name);
                    let AttributeValue::LineStringRef(convert_line_string_id) = convert_attr else {
                        panic!("unexpected {:?}", convert_attr);
                    };
                    let convert_line_string =
                        convert_dwarf.line_strings.get(*convert_line_string_id);
                    assert_eq!(convert_line_string, line_string_data.as_bytes());
                }
            }
        }
    }

    #[test]
    fn test_unit_ref() {
        let mut dwarf = Dwarf::new();
        let unit_id1 = dwarf.units.add(Unit::new(
            Encoding {
                version: 4,
                address_size: 8,
                format: Format::Dwarf32,
            },
            LineProgram::none(),
        ));
        assert_eq!(unit_id1, dwarf.units.id(0));
        let unit_id2 = dwarf.units.add(Unit::new(
            Encoding {
                version: 2,
                address_size: 4,
                format: Format::Dwarf64,
            },
            LineProgram::none(),
        ));
        assert_eq!(unit_id2, dwarf.units.id(1));
        let unit1_child1 = UnitEntryId::new(dwarf.units.get(unit_id1).base_id, 1);
        let unit1_child2 = UnitEntryId::new(dwarf.units.get(unit_id1).base_id, 2);
        let unit2_child1 = UnitEntryId::new(dwarf.units.get(unit_id2).base_id, 1);
        let unit2_child2 = UnitEntryId::new(dwarf.units.get(unit_id2).base_id, 2);
        {
            let unit1 = dwarf.units.get_mut(unit_id1);
            let root = unit1.root();
            let child_id1 = unit1.add(root, constants::DW_TAG_subprogram);
            assert_eq!(child_id1, unit1_child1);
            let child_id2 = unit1.add(root, constants::DW_TAG_subprogram);
            assert_eq!(child_id2, unit1_child2);
            {
                let child1 = unit1.get_mut(child_id1);
                child1.set(constants::DW_AT_type, AttributeValue::UnitRef(child_id2));
            }
            {
                let child2 = unit1.get_mut(child_id2);
                child2.set(
                    constants::DW_AT_type,
                    AttributeValue::DebugInfoRef(DebugInfoRef::Entry(unit_id2, unit2_child1)),
                );
            }
        }
        {
            let unit2 = dwarf.units.get_mut(unit_id2);
            let root = unit2.root();
            let child_id1 = unit2.add(root, constants::DW_TAG_subprogram);
            assert_eq!(child_id1, unit2_child1);
            let child_id2 = unit2.add(root, constants::DW_TAG_subprogram);
            assert_eq!(child_id2, unit2_child2);
            {
                let child1 = unit2.get_mut(child_id1);
                child1.set(constants::DW_AT_type, AttributeValue::UnitRef(child_id2));
            }
            {
                let child2 = unit2.get_mut(child_id2);
                child2.set(
                    constants::DW_AT_type,
                    AttributeValue::DebugInfoRef(DebugInfoRef::Entry(unit_id1, unit1_child1)),
                );
            }
        }

        let mut sections = Sections::new(EndianVec::new(LittleEndian));
        dwarf.write(&mut sections).unwrap();

        println!("{:?}", sections.debug_info);
        println!("{:?}", sections.debug_abbrev);

        let read_dwarf = sections.read(LittleEndian);
        let mut read_units = read_dwarf.units();

        let read_unit = read_units.next().unwrap().unwrap();
        let abbrevs = read_dwarf.abbreviations(&read_unit).unwrap();
        let mut read_entries = read_unit.entries(&abbrevs);
        let (_, _root) = read_entries.next_dfs().unwrap().unwrap();
        let (_, entry) = read_entries.next_dfs().unwrap().unwrap();
        let read_unit1_child1_attr = entry.attr_value(constants::DW_AT_type).unwrap();
        let read_unit1_child1_section_offset =
            entry.offset().to_debug_info_offset(&read_unit).unwrap();
        let (_, entry) = read_entries.next_dfs().unwrap().unwrap();
        let read_unit1_child2_attr = entry.attr_value(constants::DW_AT_type).unwrap();
        let read_unit1_child2_offset = entry.offset();

        let read_unit = read_units.next().unwrap().unwrap();
        let abbrevs = read_dwarf.abbreviations(&read_unit).unwrap();
        let mut read_entries = read_unit.entries(&abbrevs);
        let (_, _root) = read_entries.next_dfs().unwrap().unwrap();
        let (_, entry) = read_entries.next_dfs().unwrap().unwrap();
        let read_unit2_child1_attr = entry.attr_value(constants::DW_AT_type).unwrap();
        let read_unit2_child1_section_offset =
            entry.offset().to_debug_info_offset(&read_unit).unwrap();
        let (_, entry) = read_entries.next_dfs().unwrap().unwrap();
        let read_unit2_child2_attr = entry.attr_value(constants::DW_AT_type).unwrap();
        let read_unit2_child2_offset = entry.offset();

        assert_eq!(
            read_unit1_child1_attr,
            Some(read::AttributeValue::UnitRef(read_unit1_child2_offset))
        );
        assert_eq!(
            read_unit1_child2_attr,
            Some(read::AttributeValue::DebugInfoRef(
                read_unit2_child1_section_offset
            ))
        );
        assert_eq!(
            read_unit2_child1_attr,
            Some(read::AttributeValue::UnitRef(read_unit2_child2_offset))
        );
        assert_eq!(
            read_unit2_child2_attr,
            Some(read::AttributeValue::DebugInfoRef(
                read_unit1_child1_section_offset
            ))
        );

        let convert_dwarf =
            Dwarf::from(&read_dwarf, &|address| Some(Address::Constant(address))).unwrap();
        let convert_units = &convert_dwarf.units;
        assert_eq!(convert_units.count(), dwarf.units.count());

        for i in 0..convert_units.count() {
            let unit = dwarf.units.get(dwarf.units.id(i));
            let convert_unit = convert_units.get(convert_units.id(i));
            assert_eq!(convert_unit.version(), unit.version());
            assert_eq!(convert_unit.address_size(), unit.address_size());
            assert_eq!(convert_unit.format(), unit.format());
            assert_eq!(convert_unit.count(), unit.count());

            let root = unit.get(unit.root());
            let convert_root = convert_unit.get(convert_unit.root());
            assert_eq!(convert_root.tag(), root.tag());
            for (convert_attr, attr) in convert_root.attrs().zip(root.attrs()) {
                assert_eq!(convert_attr, attr);
            }

            let child1 = unit.get(UnitEntryId::new(unit.base_id, 1));
            let convert_child1 = convert_unit.get(UnitEntryId::new(convert_unit.base_id, 1));
            assert_eq!(convert_child1.tag(), child1.tag());
            for (convert_attr, attr) in convert_child1.attrs().zip(child1.attrs()) {
                assert_eq!(convert_attr.name, attr.name);
                match (convert_attr.value.clone(), attr.value.clone()) {
                    (
                        AttributeValue::DebugInfoRef(DebugInfoRef::Entry(
                            convert_unit,
                            convert_entry,
                        )),
                        AttributeValue::DebugInfoRef(DebugInfoRef::Entry(unit, entry)),
                    ) => {
                        assert_eq!(convert_unit.index, unit.index);
                        assert_eq!(convert_entry.index, entry.index);
                    }
                    (AttributeValue::UnitRef(convert_id), AttributeValue::UnitRef(id)) => {
                        assert_eq!(convert_id.index, id.index);
                    }
                    (convert_value, value) => assert_eq!(convert_value, value),
                }
            }

            let child2 = unit.get(UnitEntryId::new(unit.base_id, 2));
            let convert_child2 = convert_unit.get(UnitEntryId::new(convert_unit.base_id, 2));
            assert_eq!(convert_child2.tag(), child2.tag());
            for (convert_attr, attr) in convert_child2.attrs().zip(child2.attrs()) {
                assert_eq!(convert_attr.name, attr.name);
                match (convert_attr.value.clone(), attr.value.clone()) {
                    (
                        AttributeValue::DebugInfoRef(DebugInfoRef::Entry(
                            convert_unit,
                            convert_entry,
                        )),
                        AttributeValue::DebugInfoRef(DebugInfoRef::Entry(unit, entry)),
                    ) => {
                        assert_eq!(convert_unit.index, unit.index);
                        assert_eq!(convert_entry.index, entry.index);
                    }
                    (AttributeValue::UnitRef(convert_id), AttributeValue::UnitRef(id)) => {
                        assert_eq!(convert_id.index, id.index);
                    }
                    (convert_value, value) => assert_eq!(convert_value, value),
                }
            }
        }
    }

    #[test]
    fn test_sibling() {
        fn add_child(
            unit: &mut Unit,
            parent: UnitEntryId,
            tag: constants::DwTag,
            name: &str,
        ) -> UnitEntryId {
            let id = unit.add(parent, tag);
            let child = unit.get_mut(id);
            child.set(constants::DW_AT_name, AttributeValue::String(name.into()));
            child.set_sibling(true);
            id
        }

        fn add_children(unit: &mut Unit) {
            let root = unit.root();
            let child1 = add_child(unit, root, constants::DW_TAG_subprogram, "child1");
            add_child(unit, child1, constants::DW_TAG_variable, "grandchild1");
            add_child(unit, root, constants::DW_TAG_subprogram, "child2");
            add_child(unit, root, constants::DW_TAG_subprogram, "child3");
        }

        fn next_child<R: read::Reader<Offset = usize>>(
            entries: &mut read::EntriesCursor<'_, '_, R>,
        ) -> (read::UnitOffset, Option<read::UnitOffset>) {
            let (_, entry) = entries.next_dfs().unwrap().unwrap();
            let offset = entry.offset();
            let sibling =
                entry
                    .attr_value(constants::DW_AT_sibling)
                    .unwrap()
                    .map(|attr| match attr {
                        read::AttributeValue::UnitRef(offset) => offset,
                        _ => panic!("bad sibling value"),
                    });
            (offset, sibling)
        }

        fn check_sibling<R: read::Reader<Offset = usize>>(
            unit: read::UnitHeader<R>,
            dwarf: &read::Dwarf<R>,
        ) {
            let unit = dwarf.unit(unit).unwrap();
            let mut entries = unit.entries();
            // root
            entries.next_dfs().unwrap().unwrap();
            // child1
            let (_, sibling1) = next_child(&mut entries);
            // grandchild1
            entries.next_dfs().unwrap().unwrap();
            // child2
            let (offset2, sibling2) = next_child(&mut entries);
            // child3
            let (_, _) = next_child(&mut entries);
            assert_eq!(sibling1, Some(offset2));
            assert_eq!(sibling2, None);
        }

        let encoding = Encoding {
            format: Format::Dwarf32,
            version: 4,
            address_size: 8,
        };
        let mut dwarf = Dwarf::new();
        let unit_id1 = dwarf.units.add(Unit::new(encoding, LineProgram::none()));
        add_children(dwarf.units.get_mut(unit_id1));
        let unit_id2 = dwarf.units.add(Unit::new(encoding, LineProgram::none()));
        add_children(dwarf.units.get_mut(unit_id2));

        let mut sections = Sections::new(EndianVec::new(LittleEndian));
        dwarf.write(&mut sections).unwrap();

        println!("{:?}", sections.debug_info);
        println!("{:?}", sections.debug_abbrev);

        let read_dwarf = sections.read(LittleEndian);
        let mut read_units = read_dwarf.units();
        check_sibling(read_units.next().unwrap().unwrap(), &read_dwarf);
        check_sibling(read_units.next().unwrap().unwrap(), &read_dwarf);
    }

    #[test]
    fn test_line_ref() {
        let dir_bytes = b"dir";
        let file_bytes1 = b"file1";
        let file_bytes2 = b"file2";
        let file_string1 = LineString::String(file_bytes1.to_vec());
        let file_string2 = LineString::String(file_bytes2.to_vec());

        for &version in &[2, 3, 4, 5] {
            for &address_size in &[4, 8] {
                for &format in &[Format::Dwarf32, Format::Dwarf64] {
                    let encoding = Encoding {
                        format,
                        version,
                        address_size,
                    };

                    // The line program we'll be referencing.
                    let mut line_program = LineProgram::new(
                        encoding,
                        LineEncoding::default(),
                        LineString::String(dir_bytes.to_vec()),
                        None,
                        file_string1.clone(),
                        None,
                    );
                    let dir = line_program.default_directory();
                    // For version >= 5, this will reuse the existing file at index 0.
                    let file1 = line_program.add_file(file_string1.clone(), dir, None);
                    let file2 = line_program.add_file(file_string2.clone(), dir, None);

                    let mut unit = Unit::new(encoding, line_program);
                    let root = unit.get_mut(unit.root());
                    root.set(
                        constants::DW_AT_name,
                        AttributeValue::String(file_bytes1.to_vec()),
                    );
                    root.set(
                        constants::DW_AT_comp_dir,
                        AttributeValue::String(dir_bytes.to_vec()),
                    );
                    root.set(constants::DW_AT_stmt_list, AttributeValue::LineProgramRef);

                    let child = unit.add(unit.root(), constants::DW_TAG_subprogram);
                    unit.get_mut(child).set(
                        constants::DW_AT_decl_file,
                        AttributeValue::FileIndex(Some(file1)),
                    );

                    let child = unit.add(unit.root(), constants::DW_TAG_subprogram);
                    unit.get_mut(child).set(
                        constants::DW_AT_call_file,
                        AttributeValue::FileIndex(Some(file2)),
                    );

                    let mut dwarf = Dwarf::new();
                    dwarf.units.add(unit);

                    let mut sections = Sections::new(EndianVec::new(LittleEndian));
                    dwarf.write(&mut sections).unwrap();

                    let read_dwarf = sections.read(LittleEndian);
                    let mut read_units = read_dwarf.units();
                    let read_unit = read_units.next().unwrap().unwrap();
                    let read_unit = read_dwarf.unit(read_unit).unwrap();
                    let read_unit = read_unit.unit_ref(&read_dwarf);
                    let read_line_program = read_unit.line_program.as_ref().unwrap().header();
                    let mut read_entries = read_unit.entries();
                    let (_, _root) = read_entries.next_dfs().unwrap().unwrap();

                    let mut get_path = |name| {
                        let (_, entry) = read_entries.next_dfs().unwrap().unwrap();
                        let read_attr = entry.attr(name).unwrap().unwrap();
                        let read::AttributeValue::FileIndex(read_file_index) = read_attr.value()
                        else {
                            panic!("unexpected {:?}", read_attr);
                        };
                        let read_file = read_line_program.file(read_file_index).unwrap();
                        let read_path = read_unit
                            .attr_string(read_file.path_name())
                            .unwrap()
                            .slice();
                        (read_file_index, read_path)
                    };

                    let (read_index, read_path) = get_path(constants::DW_AT_decl_file);
                    assert_eq!(read_index, if version >= 5 { 0 } else { 1 });
                    assert_eq!(read_path, file_bytes1);

                    let (read_index, read_path) = get_path(constants::DW_AT_call_file);
                    assert_eq!(read_index, if version >= 5 { 1 } else { 2 });
                    assert_eq!(read_path, file_bytes2);

                    let convert_dwarf =
                        Dwarf::from(&read_dwarf, &|address| Some(Address::Constant(address)))
                            .unwrap();
                    let convert_unit = convert_dwarf.units.get(convert_dwarf.units.id(0));
                    let convert_root = convert_unit.get(convert_unit.root());
                    let mut convert_entries = convert_root.children();

                    let mut get_convert_path = |name| {
                        let convert_entry = convert_unit.get(*convert_entries.next().unwrap());
                        let convert_attr = convert_entry.get(name).unwrap();
                        let AttributeValue::FileIndex(Some(convert_file_index)) = convert_attr
                        else {
                            panic!("unexpected {:?}", convert_attr);
                        };
                        convert_unit.line_program.get_file(*convert_file_index).0
                    };

                    let convert_path = get_convert_path(constants::DW_AT_decl_file);
                    assert_eq!(convert_dwarf.get_line_string(convert_path), file_bytes1);

                    let convert_path = get_convert_path(constants::DW_AT_call_file);
                    assert_eq!(convert_dwarf.get_line_string(convert_path), file_bytes2);
                }
            }
        }
    }

    #[test]
    fn test_line_program_used() {
        for used in [false, true] {
            let encoding = Encoding {
                format: Format::Dwarf32,
                version: 5,
                address_size: 8,
            };

            let line_program = LineProgram::new(
                encoding,
                LineEncoding::default(),
                LineString::String(b"comp_dir".to_vec()),
                None,
                LineString::String(b"comp_name".to_vec()),
                None,
            );

            let mut unit = Unit::new(encoding, line_program);
            let file_id = if used { Some(FileId::new(0)) } else { None };
            let root = unit.root();
            unit.get_mut(root).set(
                constants::DW_AT_decl_file,
                AttributeValue::FileIndex(file_id),
            );

            let mut dwarf = Dwarf::new();
            dwarf.units.add(unit);

            let mut sections = Sections::new(EndianVec::new(LittleEndian));
            dwarf.write(&mut sections).unwrap();
            assert_eq!(!used, sections.debug_line.slice().is_empty());
        }
    }

    #[test]
    fn test_delete_child() {
        fn set_name(unit: &mut Unit, id: UnitEntryId, name: &str) {
            let entry = unit.get_mut(id);
            entry.set(constants::DW_AT_name, AttributeValue::String(name.into()));
        }
        fn check_name<R: read::Reader>(
            entry: &read::DebuggingInformationEntry<'_, '_, R>,
            unit: read::UnitRef<'_, R>,
            name: &str,
        ) {
            let name_attr = entry.attr(constants::DW_AT_name).unwrap().unwrap();
            let entry_name = unit.attr_string(name_attr.value()).unwrap();
            let entry_name_str = entry_name.to_string().unwrap();
            assert_eq!(entry_name_str, name);
        }
        let encoding = Encoding {
            format: Format::Dwarf32,
            version: 4,
            address_size: 8,
        };
        let mut dwarf = DwarfUnit::new(encoding);
        let root = dwarf.unit.root();

        // Add and delete entries in the root unit
        let child1 = dwarf.unit.add(root, constants::DW_TAG_subprogram);
        set_name(&mut dwarf.unit, child1, "child1");
        let grandchild1 = dwarf.unit.add(child1, constants::DW_TAG_variable);
        set_name(&mut dwarf.unit, grandchild1, "grandchild1");
        let child2 = dwarf.unit.add(root, constants::DW_TAG_subprogram);
        set_name(&mut dwarf.unit, child2, "child2");
        // This deletes both `child1` and its child `grandchild1`
        dwarf.unit.get_mut(root).delete_child(child1);
        let child3 = dwarf.unit.add(root, constants::DW_TAG_subprogram);
        set_name(&mut dwarf.unit, child3, "child3");
        let child4 = dwarf.unit.add(root, constants::DW_TAG_subprogram);
        set_name(&mut dwarf.unit, child4, "child4");
        let grandchild4 = dwarf.unit.add(child4, constants::DW_TAG_variable);
        set_name(&mut dwarf.unit, grandchild4, "grandchild4");
        dwarf.unit.get_mut(child4).delete_child(grandchild4);

        let mut sections = Sections::new(EndianVec::new(LittleEndian));

        // Write DWARF data which should only include `child2`, `child3` and `child4`
        dwarf.write(&mut sections).unwrap();

        let read_dwarf = sections.read(LittleEndian);
        let read_unit = read_dwarf.units().next().unwrap().unwrap();
        let read_unit = read_dwarf.unit(read_unit).unwrap();
        let read_unit = read_unit.unit_ref(&read_dwarf);
        let mut entries = read_unit.entries();
        // root
        entries.next_dfs().unwrap().unwrap();
        // child2
        let (_, read_child2) = entries.next_dfs().unwrap().unwrap();
        check_name(read_child2, read_unit, "child2");
        // child3
        let (_, read_child3) = entries.next_dfs().unwrap().unwrap();
        check_name(read_child3, read_unit, "child3");
        // child4
        let (_, read_child4) = entries.next_dfs().unwrap().unwrap();
        check_name(read_child4, read_unit, "child4");
        // There should be no more entries
        assert!(entries.next_dfs().unwrap().is_none());
    }

    #[test]
    fn test_missing_unit_ref() {
        let encoding = Encoding {
            format: Format::Dwarf32,
            version: 5,
            address_size: 8,
        };

        let mut dwarf = Dwarf::new();
        let unit_id = dwarf.units.add(Unit::new(encoding, LineProgram::none()));
        let unit = dwarf.units.get_mut(unit_id);

        // Create the entry to be referenced.
        let entry_id = unit.add(unit.root(), constants::DW_TAG_const_type);
        // And delete it so that it is not available when writing.
        unit.get_mut(unit.root()).delete_child(entry_id);

        // Create a reference to the deleted entry.
        let subprogram_id = unit.add(unit.root(), constants::DW_TAG_subprogram);
        unit.get_mut(subprogram_id)
            .set(constants::DW_AT_type, AttributeValue::UnitRef(entry_id));

        // Writing the DWARF should fail.
        let mut sections = Sections::new(EndianVec::new(LittleEndian));
        assert_eq!(dwarf.write(&mut sections), Err(Error::InvalidReference));
    }

    #[test]
    fn test_missing_debuginfo_ref() {
        let encoding = Encoding {
            format: Format::Dwarf32,
            version: 5,
            address_size: 8,
        };

        let mut dwarf = Dwarf::new();
        let unit_id = dwarf.units.add(Unit::new(encoding, LineProgram::none()));
        let unit = dwarf.units.get_mut(unit_id);

        // Create the entry to be referenced.
        let entry_id = unit.add(unit.root(), constants::DW_TAG_const_type);
        // And delete it so that it is not available when writing.
        unit.get_mut(unit.root()).delete_child(entry_id);

        // Create a reference to the deleted entry.
        let subprogram_id = unit.add(unit.root(), constants::DW_TAG_subprogram);
        unit.get_mut(subprogram_id).set(
            constants::DW_AT_type,
            AttributeValue::DebugInfoRef(DebugInfoRef::Entry(unit_id, entry_id)),
        );

        // Writing the DWARF should fail.
        let mut sections = Sections::new(EndianVec::new(LittleEndian));
        assert_eq!(dwarf.write(&mut sections), Err(Error::InvalidReference));
    }
}
