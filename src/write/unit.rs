use crate::vec::Vec;
use std::ops::{Deref, DerefMut};
use std::{slice, usize};

use crate::common::{
    DebugAbbrevOffset, DebugInfoOffset, DebugLineOffset, DebugMacinfoOffset, DebugStrOffset,
    DebugTypeSignature, Encoding, Format, LocationListsOffset, SectionId, UnitSectionOffset,
};
use crate::constants;
use crate::write::{
    Abbreviation, AbbreviationTable, Address, AttributeSpecification, BaseId, DebugLineStrOffsets,
    DebugStrOffsets, Error, FileId, LineProgram, LineStringId, RangeList, RangeListId,
    RangeListOffsets, RangeListTable, Result, Section, Sections, StringId, Writer,
};

define_id!(UnitId, "An identifier for a unit in a `UnitTable`.");

define_id!(UnitEntryId, "An identifier for an entry in a `Unit`.");

/// The bytecode for a DWARF expression or location description.
// TODO: this needs to be a `Vec<Op>` so we can handle relocations
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Expression(pub Vec<u8>);

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

    /// Write the units to the given sections.
    ///
    /// `strings` must contain the `.debug_str` offsets of the corresponding
    /// `StringTable`.
    pub fn write<W: Writer>(
        &mut self,
        sections: &mut Sections<W>,
        line_strings: &DebugLineStrOffsets,
        strings: &DebugStrOffsets,
    ) -> Result<DebugInfoOffsets> {
        let mut debug_info_refs = Vec::new();
        let mut offsets = DebugInfoOffsets {
            base_id: self.base_id,
            units: Vec::new(),
        };
        for unit in &mut self.units {
            // TODO: maybe share abbreviation tables
            let abbrev_offset = sections.debug_abbrev.offset();
            let mut abbrevs = AbbreviationTable::default();

            offsets.units.push(unit.write(
                sections,
                abbrev_offset,
                &mut abbrevs,
                line_strings,
                strings,
                &mut debug_info_refs,
            )?);

            abbrevs.write(&mut sections.debug_abbrev)?;
        }

        for (offset, (unit, entry), size) in debug_info_refs {
            let entry_offset = offsets.entry(unit, entry).0;
            debug_assert_ne!(entry_offset, 0);
            sections.debug_info.write_offset_at(
                offset.0,
                entry_offset,
                SectionId::DebugInfo,
                size,
            )?;
        }

        Ok(offsets)
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
    /// All entries in this unit. The order is unrelated to the tree order.
    // Requirements:
    // - entries form a tree
    // - entries can be added in any order
    // - entries have a fixed id
    // - able to quickly lookup an entry from its id
    // Limitations of current implemention:
    // - mutable iteration of children is messy due to borrow checker
    entries: Vec<DebuggingInformationEntry>,
    /// The index of the root entry in entries.
    root: UnitEntryId,
}

impl Unit {
    /// Create a new `Unit`.
    pub fn new(encoding: Encoding, line_program: LineProgram) -> Self {
        let base_id = BaseId::default();
        let ranges = RangeListTable::default();
        let mut entries = Vec::new();
        let root = DebuggingInformationEntry::new(
            base_id,
            &mut entries,
            None,
            constants::DW_TAG_compile_unit,
        );
        Unit {
            base_id,
            encoding,
            line_program,
            ranges,
            entries,
            root,
        }
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
        line_strings: &DebugLineStrOffsets,
        strings: &DebugStrOffsets,
        debug_info_refs: &mut Vec<(DebugInfoOffset, (UnitId, UnitEntryId), u8)>,
    ) -> Result<UnitOffsets> {
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
        let range_lists = self.ranges.write(sections, self.encoding)?;

        // TODO: use .debug_types for type units in DWARF v4.
        let w = &mut sections.debug_info;

        let mut offsets = UnitOffsets {
            base_id: self.base_id,
            unit: w.offset(),
            // Entries can be written in any order, so create the complete vec now.
            entries: vec![DebugInfoOffset(0); self.entries.len()],
        };
        let mut unit_refs = Vec::new();

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

        self.entries[self.root.index].write(
            w,
            self,
            &mut offsets,
            abbrevs,
            line_program,
            line_strings,
            strings,
            &range_lists,
            &mut unit_refs,
            debug_info_refs,
        )?;

        let length = (w.len() - length_base) as u64;
        w.write_initial_length_at(length_offset, length, self.format())?;

        for (offset, entry) in unit_refs {
            let entry_offset = offsets.entry(entry).0;
            debug_assert_ne!(entry_offset, 0);
            // This does not need relocation.
            w.write_udata_at(
                offset.0,
                (entry_offset - offsets.unit.0) as u64,
                self.format().word_size(),
            )?;
        }

        Ok(offsets)
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
    pub fn attrs(&self) -> slice::Iter<Attribute> {
        self.attrs.iter()
    }

    /// Iterate over the attributes of this entry for modification.
    #[inline]
    pub fn attrs_mut(&mut self) -> slice::IterMut<Attribute> {
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
    pub fn children(&self) -> slice::Iter<UnitEntryId> {
        self.children.iter()
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

    /// Write the entry to the given sections.
    #[allow(clippy::too_many_arguments)]
    fn write<W: Writer>(
        &self,
        w: &mut DebugInfo<W>,
        unit: &Unit,
        offsets: &mut UnitOffsets,
        abbrevs: &mut AbbreviationTable,
        line_program: Option<DebugLineOffset>,
        line_strings: &DebugLineStrOffsets,
        strings: &DebugStrOffsets,
        range_lists: &RangeListOffsets,
        unit_refs: &mut Vec<(DebugInfoOffset, UnitEntryId)>,
        debug_info_refs: &mut Vec<(DebugInfoOffset, (UnitId, UnitEntryId), u8)>,
    ) -> Result<()> {
        offsets.entries[self.id.index] = w.offset();
        let code = abbrevs.add(self.abbreviation(unit.encoding())?);
        w.write_uleb128(code)?;

        let sibling_offset = if self.sibling && !self.children.is_empty() {
            let offset = w.offset();
            w.write_udata(0, unit.format().word_size())?;
            Some(offset)
        } else {
            None
        };

        for attr in &self.attrs {
            attr.write(
                w,
                unit,
                line_program,
                line_strings,
                strings,
                range_lists,
                unit_refs,
                debug_info_refs,
            )?;
        }

        if !self.children.is_empty() {
            for child in &self.children {
                unit.entries[child.index].write(
                    w,
                    unit,
                    offsets,
                    abbrevs,
                    line_program,
                    line_strings,
                    strings,
                    range_lists,
                    unit_refs,
                    debug_info_refs,
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

    /// Write the attribute to the given sections.
    #[inline]
    #[allow(clippy::too_many_arguments)]
    fn write<W: Writer>(
        &self,
        w: &mut DebugInfo<W>,
        unit: &Unit,
        line_program: Option<DebugLineOffset>,
        line_strings: &DebugLineStrOffsets,
        strings: &DebugStrOffsets,
        range_lists: &RangeListOffsets,
        unit_refs: &mut Vec<(DebugInfoOffset, UnitEntryId)>,
        debug_info_refs: &mut Vec<(DebugInfoOffset, (UnitId, UnitEntryId), u8)>,
    ) -> Result<()> {
        self.value.write(
            w,
            unit,
            line_program,
            line_strings,
            strings,
            range_lists,
            unit_refs,
            debug_info_refs,
        )
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

    /// A reference to a `DebuggingInformationEntry` in the this unit.
    ThisUnitEntryRef(UnitEntryId),

    /// A reference to a `DebuggingInformationEntry` in a potentially different unit.
    AnyUnitEntryRef((UnitId, UnitEntryId)),

    /// A reference to the current `.debug_info` section, but possibly a different
    /// unit from the current one.
    ///
    /// This is an internal attribute that must only be used when converting an
    /// existing `.debug_info` section.
    #[doc(hidden)]
    UnitSectionRef(UnitSectionOffset),

    /// An offset into the `.debug_info` section of the supplementary object file.
    ///
    /// It is the user's responsibility to ensure the offset is valid.
    /// This variant will be removed from the API once support for writing
    /// supplementary object files is implemented.
    DebugInfoRefSup(DebugInfoOffset),

    /// A reference to a line number program.
    LineProgramRef,

    /// An offset into either the `.debug_loc` section or the `.debug_loclists` section.
    ///
    /// It is the user's responsibility to ensure the offset is valid.
    /// This variant will be removed from the API once support for writing
    /// `.debug_loc`/`.debug_loclists` sections is implemented.
    LocationListsRef(LocationListsOffset),

    /// An offset into the `.debug_macinfo` section.
    ///
    /// It is the user's responsibility to ensure the offset is valid.
    /// This variant will be removed from the API once support for writing
    /// `.debug_macinfo` sections is implemented.
    DebugMacinfoRef(DebugMacinfoOffset),

    /// A reference to a range list.
    RangeListRef(RangeListId),

    /// A type signature.
    ///
    /// It is the user's responsibility to ensure the signature is valid.
    /// This variant will be removed from the API once support for writing
    /// `.debug_types` sections is implemented.
    DebugTypesRef(DebugTypeSignature),

    /// A reference to a string in the `.debug_str` section.
    StringRef(StringId),

    /// An offset into the `.debug_str` section of the supplementary object file.
    ///
    /// It is the user's responsibility to ensure the offset is valid.
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
            AttributeValue::Exprloc(_) => constants::DW_FORM_exprloc,
            AttributeValue::Flag(_) => constants::DW_FORM_flag,
            AttributeValue::FlagPresent => constants::DW_FORM_flag_present,
            AttributeValue::ThisUnitEntryRef(_) => {
                // Using a fixed size format lets us write a placeholder before we know
                // the value.
                match encoding.format {
                    Format::Dwarf32 => constants::DW_FORM_ref4,
                    Format::Dwarf64 => constants::DW_FORM_ref8,
                }
            }
            AttributeValue::AnyUnitEntryRef(_) => constants::DW_FORM_ref_addr,
            AttributeValue::DebugInfoRefSup(_) => {
                // TODO: should this depend on the size of supplementary section?
                match encoding.format {
                    Format::Dwarf32 => constants::DW_FORM_ref_sup4,
                    Format::Dwarf64 => constants::DW_FORM_ref_sup8,
                }
            }
            AttributeValue::LineProgramRef
            | AttributeValue::LocationListsRef(_)
            | AttributeValue::DebugMacinfoRef(_)
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
            AttributeValue::UnitSectionRef(_) => {
                return Err(Error::InvalidAttributeValue);
            }
        };
        Ok(form)
    }

    /// Write the attribute value to the given sections.
    #[allow(clippy::cyclomatic_complexity, clippy::too_many_arguments)]
    fn write<W: Writer>(
        &self,
        w: &mut DebugInfo<W>,
        unit: &Unit,
        line_program: Option<DebugLineOffset>,
        line_strings: &DebugLineStrOffsets,
        strings: &DebugStrOffsets,
        range_lists: &RangeListOffsets,
        unit_refs: &mut Vec<(DebugInfoOffset, UnitEntryId)>,
        debug_info_refs: &mut Vec<(DebugInfoOffset, (UnitId, UnitEntryId), u8)>,
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
                w.write(&val)?;
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
                w.write_uleb128(val.0.len() as u64)?;
                w.write(&val.0)?;
            }
            AttributeValue::Flag(val) => {
                debug_assert_form!(constants::DW_FORM_flag);
                w.write_u8(val as u8)?;
            }
            AttributeValue::FlagPresent => {
                debug_assert_form!(constants::DW_FORM_flag_present);
            }
            AttributeValue::ThisUnitEntryRef(id) => {
                match unit.format() {
                    Format::Dwarf32 => debug_assert_form!(constants::DW_FORM_ref4),
                    Format::Dwarf64 => debug_assert_form!(constants::DW_FORM_ref8),
                }
                unit_refs.push((w.offset(), id));
                w.write_udata(0, unit.format().word_size())?;
            }
            AttributeValue::AnyUnitEntryRef(id) => {
                debug_assert_form!(constants::DW_FORM_ref_addr);
                let size = if unit.version() == 2 {
                    unit.address_size()
                } else {
                    unit.format().word_size()
                };
                debug_info_refs.push((w.offset(), id, size));
                w.write_udata(0, size)?;
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
            AttributeValue::LocationListsRef(val) => {
                if unit.version() >= 4 {
                    debug_assert_form!(constants::DW_FORM_sec_offset);
                }
                let section = if unit.version() <= 4 {
                    SectionId::DebugLoc
                } else {
                    SectionId::DebugLocLists
                };
                w.write_offset(val.0, section, unit.format().word_size())?;
            }
            AttributeValue::DebugMacinfoRef(val) => {
                if unit.version() >= 4 {
                    debug_assert_form!(constants::DW_FORM_sec_offset);
                }
                w.write_offset(val.0, SectionId::DebugMacinfo, unit.format().word_size())?;
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
                    strings.get(val).0,
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
                    line_strings.get(val).0,
                    SectionId::DebugLineStr,
                    unit.format().word_size(),
                )?;
            }
            AttributeValue::String(ref val) => {
                debug_assert_form!(constants::DW_FORM_string);
                w.write(&val)?;
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
                w.write_uleb128(val.map(FileId::raw).unwrap_or(0))?;
            }
            AttributeValue::UnitSectionRef(_) => {
                return Err(Error::InvalidAttributeValue);
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

/// The section offsets of all elements within a `.debug_info` section.
#[derive(Debug, Default)]
pub struct DebugInfoOffsets {
    base_id: BaseId,
    units: Vec<UnitOffsets>,
}

impl DebugInfoOffsets {
    /// Get the `.debug_info` section offset for the given unit.
    #[inline]
    pub fn unit(&self, unit: UnitId) -> DebugInfoOffset {
        debug_assert_eq!(self.base_id, unit.base_id);
        self.units[unit.index].unit
    }

    /// Get the `.debug_info` section offset for the given entry.
    #[inline]
    pub fn entry(&self, unit: UnitId, entry: UnitEntryId) -> DebugInfoOffset {
        debug_assert_eq!(self.base_id, unit.base_id);
        self.units[unit.index].entry(entry)
    }
}

/// The section offsets of all elements of a unit within a `.debug_info` section.
#[derive(Debug)]
pub(crate) struct UnitOffsets {
    base_id: BaseId,
    unit: DebugInfoOffset,
    entries: Vec<DebugInfoOffset>,
}

impl UnitOffsets {
    #[inline]
    fn entry(&self, entry: UnitEntryId) -> DebugInfoOffset {
        debug_assert_eq!(self.base_id, entry.base_id);
        self.entries[entry.index]
    }
}

#[cfg(feature = "read")]
pub(crate) mod convert {
    use super::*;
    use crate::collections::HashMap;
    use crate::read::{self, Reader};
    use crate::write::{self, ConvertError, ConvertResult};

    pub(crate) struct ConvertUnitContext<'a, R: Reader<Offset = usize>> {
        pub dwarf: &'a read::Dwarf<R>,
        pub unit: &'a read::Unit<R>,
        pub line_strings: &'a mut write::LineStringTable,
        pub strings: &'a mut write::StringTable,
        pub ranges: &'a mut write::RangeListTable,
        pub convert_address: &'a dyn Fn(u64) -> Option<Address>,
        pub base_address: Address,
        pub line_program_offset: Option<DebugLineOffset>,
        pub line_program_files: Vec<FileId>,
    }

    impl UnitTable {
        /// Create a unit table by reading the data in the given sections.
        ///
        /// This also updates the given tables with the values that are referenced from
        /// attributes in this section.
        ///
        /// `convert_address` is a function to convert read addresses into the `Address`
        /// type. For non-relocatable addresses, this function may simply return
        /// `Address::Constant(address)`. For relocatable addresses, it is the caller's
        /// responsibility to determine the symbol and addend corresponding to the address
        /// and return `Address::Symbol { symbol, addend }`.
        pub fn from<R: Reader<Offset = usize>>(
            dwarf: &read::Dwarf<R>,
            line_strings: &mut write::LineStringTable,
            strings: &mut write::StringTable,
            convert_address: &dyn Fn(u64) -> Option<Address>,
        ) -> ConvertResult<UnitTable> {
            let base_id = BaseId::default();
            let mut units = Vec::new();
            let mut unit_entry_offsets = HashMap::new();

            let mut from_units = dwarf.units();
            while let Some(from_unit) = from_units.next()? {
                let unit_id = UnitId::new(base_id, units.len());
                units.push(Unit::from(
                    from_unit,
                    unit_id,
                    &mut unit_entry_offsets,
                    dwarf,
                    line_strings,
                    strings,
                    convert_address,
                )?);
            }

            // Convert all DebugInfoOffset to UnitEntryId
            for (unit_id, unit) in units.iter_mut().enumerate() {
                let unit_id = UnitId::new(base_id, unit_id);
                for entry in &mut unit.entries {
                    for attr in &mut entry.attrs {
                        let id = match attr.value {
                            AttributeValue::UnitSectionRef(ref offset) => {
                                match unit_entry_offsets.get(offset) {
                                    Some(id) => Some(*id),
                                    None => return Err(ConvertError::InvalidDebugInfoOffset),
                                }
                            }
                            _ => None,
                        };
                        if let Some(id) = id {
                            if id.0 == unit_id {
                                attr.value = AttributeValue::ThisUnitEntryRef(id.1)
                            } else {
                                attr.value = AttributeValue::AnyUnitEntryRef(id)
                            }
                        }
                    }
                }
            }

            Ok(UnitTable { base_id, units })
        }
    }

    impl Unit {
        /// Create a unit by reading the data in the given sections.
        #[allow(clippy::too_many_arguments)]
        pub(crate) fn from<R: Reader<Offset = usize>>(
            from_header: read::CompilationUnitHeader<R>,
            unit_id: UnitId,
            unit_entry_offsets: &mut HashMap<UnitSectionOffset, (UnitId, UnitEntryId)>,
            dwarf: &read::Dwarf<R>,
            line_strings: &mut write::LineStringTable,
            strings: &mut write::StringTable,
            convert_address: &dyn Fn(u64) -> Option<Address>,
        ) -> ConvertResult<Unit> {
            let base_id = BaseId::default();

            let from_unit = dwarf.unit(from_header)?;
            let encoding = from_unit.encoding();
            let base_address =
                convert_address(from_unit.low_pc).ok_or(ConvertError::InvalidAddress)?;

            let (line_program_offset, line_program, line_program_files) =
                match from_unit.line_program {
                    Some(ref from_program) => {
                        let from_program = from_program.clone();
                        let line_program_offset = from_program.header().offset();
                        let (line_program, line_program_files) = LineProgram::from(
                            from_program,
                            dwarf,
                            line_strings,
                            strings,
                            convert_address,
                        )?;
                        (Some(line_program_offset), line_program, line_program_files)
                    }
                    None => (None, LineProgram::none(), Vec::new()),
                };

            let mut ranges = RangeListTable::default();
            let mut entries = Vec::new();
            let root = {
                let mut context = ConvertUnitContext {
                    dwarf,
                    unit: &from_unit,
                    line_strings,
                    strings,
                    ranges: &mut ranges,
                    convert_address,
                    base_address,
                    line_program_offset,
                    line_program_files,
                };
                let mut from_tree = from_unit.entries_tree(None)?;
                let from_root = from_tree.root()?;
                DebuggingInformationEntry::from(
                    &mut context,
                    from_root,
                    base_id,
                    &mut entries,
                    None,
                    unit_id,
                    unit_entry_offsets,
                )?
            };

            Ok(Unit {
                base_id,
                encoding,
                line_program,
                ranges,
                entries,
                root,
            })
        }
    }

    impl DebuggingInformationEntry {
        /// Create an entry by reading the data in the given sections.
        fn from<R: Reader<Offset = usize>>(
            context: &mut ConvertUnitContext<R>,
            from: read::EntriesTreeNode<R>,
            base_id: BaseId,
            entries: &mut Vec<DebuggingInformationEntry>,
            parent: Option<UnitEntryId>,
            unit_id: UnitId,
            unit_entry_offsets: &mut HashMap<UnitSectionOffset, (UnitId, UnitEntryId)>,
        ) -> ConvertResult<UnitEntryId> {
            let id = {
                let from = from.entry();
                let entry = DebuggingInformationEntry::new(base_id, entries, parent, from.tag());
                let entry = &mut entries[entry.index];

                let offset = from.offset().to_unit_section_offset(context.unit);
                unit_entry_offsets.insert(offset, (unit_id, entry.id));

                let mut from_attrs = from.attrs();
                while let Some(from_attr) = from_attrs.next()? {
                    if from_attr.name() == constants::DW_AT_sibling {
                        // This may point to a null entry, so we have to treat it differently.
                        entry.set_sibling(true);
                    } else if let Some(attr) = Attribute::from(context, &from_attr)? {
                        entry.set(attr.name, attr.value);
                    }
                }

                entry.id
            };

            let mut from_children = from.children();
            while let Some(from_child) = from_children.next()? {
                DebuggingInformationEntry::from(
                    context,
                    from_child,
                    base_id,
                    entries,
                    Some(id),
                    unit_id,
                    unit_entry_offsets,
                )?;
            }
            Ok(id)
        }
    }

    impl Attribute {
        /// Create an attribute by reading the data in the given sections.
        pub(crate) fn from<R: Reader<Offset = usize>>(
            context: &mut ConvertUnitContext<R>,
            from: &read::Attribute<R>,
        ) -> ConvertResult<Option<Attribute>> {
            let value = AttributeValue::from(context, from.value())?;
            Ok(value.map(|value| Attribute {
                name: from.name(),
                value,
            }))
        }
    }

    impl AttributeValue {
        /// Create an attribute value by reading the data in the given sections.
        pub(crate) fn from<R: Reader<Offset = usize>>(
            context: &mut ConvertUnitContext<R>,
            from: read::AttributeValue<R>,
        ) -> ConvertResult<Option<AttributeValue>> {
            let to = match from {
                read::AttributeValue::Addr(val) => match (context.convert_address)(val) {
                    Some(val) => AttributeValue::Address(val),
                    None => return Err(ConvertError::InvalidAddress),
                },
                read::AttributeValue::Block(r) => AttributeValue::Block(r.to_slice()?.into()),
                read::AttributeValue::Data1(val) => AttributeValue::Data1(val),
                read::AttributeValue::Data2(val) => AttributeValue::Data2(val),
                read::AttributeValue::Data4(val) => AttributeValue::Data4(val),
                read::AttributeValue::Data8(val) => AttributeValue::Data8(val),
                read::AttributeValue::Sdata(val) => AttributeValue::Sdata(val),
                read::AttributeValue::Udata(val) => AttributeValue::Udata(val),
                // TODO: addresses and offsets in expressions need special handling.
                read::AttributeValue::Exprloc(read::Expression(val)) => {
                    AttributeValue::Exprloc(Expression(val.to_slice()?.into()))
                }
                // TODO: it would be nice to preserve the flag form.
                read::AttributeValue::Flag(val) => AttributeValue::Flag(val),
                read::AttributeValue::DebugAddrBase(_base) => {
                    // We convert all address indices to addresses,
                    // so this is unneeded.
                    return Ok(None);
                }
                read::AttributeValue::DebugAddrIndex(index) => {
                    let val = context.dwarf.address(context.unit, index)?;
                    match (context.convert_address)(val) {
                        Some(val) => AttributeValue::Address(val),
                        None => return Err(ConvertError::InvalidAddress),
                    }
                }
                read::AttributeValue::UnitRef(val) => {
                    AttributeValue::UnitSectionRef(val.to_unit_section_offset(context.unit))
                }
                read::AttributeValue::DebugInfoRef(val) => {
                    AttributeValue::UnitSectionRef(UnitSectionOffset::DebugInfoOffset(val))
                }
                read::AttributeValue::DebugInfoRefSup(val) => AttributeValue::DebugInfoRefSup(val),
                read::AttributeValue::DebugLineRef(val) => {
                    // There should only be the line program in the CU DIE which we've already
                    // converted, so check if it matches that.
                    if Some(val) == context.line_program_offset {
                        AttributeValue::LineProgramRef
                    } else {
                        return Err(ConvertError::InvalidLineRef);
                    }
                }
                read::AttributeValue::DebugMacinfoRef(val) => AttributeValue::DebugMacinfoRef(val),
                read::AttributeValue::LocationListsRef(val) => {
                    AttributeValue::LocationListsRef(val)
                }
                read::AttributeValue::DebugLocListsBase(_base) => {
                    // We convert all location list indices to offsets,
                    // so this is unneeded.
                    return Ok(None);
                }
                read::AttributeValue::DebugLocListsIndex(index) => {
                    let offset = context.dwarf.locations_offset(context.unit, index)?;
                    AttributeValue::LocationListsRef(offset)
                }
                read::AttributeValue::RangeListsRef(val) => {
                    let iter = context
                        .dwarf
                        .ranges
                        .raw_ranges(val, context.unit.encoding())?;
                    let range_list = RangeList::from(iter, context)?;
                    let range_id = context.ranges.add(range_list);
                    AttributeValue::RangeListRef(range_id)
                }
                read::AttributeValue::DebugRngListsBase(_base) => {
                    // We convert all range list indices to offsets,
                    // so this is unneeded.
                    return Ok(None);
                }
                read::AttributeValue::DebugRngListsIndex(index) => {
                    let offset = context.dwarf.ranges_offset(context.unit, index)?;
                    let iter = context
                        .dwarf
                        .ranges
                        .raw_ranges(offset, context.unit.encoding())?;
                    let range_list = RangeList::from(iter, context)?;
                    let range_id = context.ranges.add(range_list);
                    AttributeValue::RangeListRef(range_id)
                }
                read::AttributeValue::DebugTypesRef(val) => AttributeValue::DebugTypesRef(val),
                read::AttributeValue::DebugStrRef(offset) => {
                    let r = context.dwarf.string(offset)?;
                    let id = context.strings.add(r.to_slice()?);
                    AttributeValue::StringRef(id)
                }
                read::AttributeValue::DebugStrRefSup(val) => AttributeValue::DebugStrRefSup(val),
                read::AttributeValue::DebugStrOffsetsBase(_base) => {
                    // We convert all string offsets to `.debug_str` references,
                    // so this is unneeded.
                    return Ok(None);
                }
                read::AttributeValue::DebugStrOffsetsIndex(index) => {
                    let offset = context.dwarf.string_offset(context.unit, index)?;
                    let r = context.dwarf.string(offset)?;
                    let id = context.strings.add(r.to_slice()?);
                    AttributeValue::StringRef(id)
                }
                read::AttributeValue::DebugLineStrRef(offset) => {
                    let r = context.dwarf.line_string(offset)?;
                    let id = context.line_strings.add(r.to_slice()?);
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
                    if val == 0 {
                        // 0 means not specified, even for version 5.
                        AttributeValue::FileIndex(None)
                    } else {
                        match context.line_program_files.get(val as usize) {
                            Some(id) => AttributeValue::FileIndex(Some(*id)),
                            None => return Err(ConvertError::InvalidFileIndex),
                        }
                    }
                }
                // Should always be a more specific section reference.
                read::AttributeValue::SecOffset(_) => {
                    return Err(ConvertError::InvalidAttributeValue);
                }
            };
            Ok(Some(to))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{
        DebugAddrBase, DebugLocListsBase, DebugRngListsBase, DebugStrOffsetsBase, LineEncoding,
    };
    use crate::constants;
    use crate::read;
    use crate::write::{
        DebugLine, DebugLineStr, DebugStr, EndianVec, LineString, LineStringTable, Range,
        RangeListOffsets, RangeListTable, StringTable,
    };
    use crate::LittleEndian;
    use std::mem;

    #[test]
    #[allow(clippy::cyclomatic_complexity)]
    fn test_unit_table() {
        let mut strings = StringTable::default();

        let mut units = UnitTable::default();
        let unit_id1 = units.add(Unit::new(
            Encoding {
                version: 4,
                address_size: 8,
                format: Format::Dwarf32,
            },
            LineProgram::none(),
        ));
        let unit2 = units.add(Unit::new(
            Encoding {
                version: 2,
                address_size: 4,
                format: Format::Dwarf64,
            },
            LineProgram::none(),
        ));
        let unit3 = units.add(Unit::new(
            Encoding {
                version: 5,
                address_size: 4,
                format: Format::Dwarf32,
            },
            LineProgram::none(),
        ));
        assert_eq!(units.count(), 3);
        {
            let unit1 = units.get_mut(unit_id1);
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
                let name = AttributeValue::StringRef(strings.add(&b"child1"[..]));
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
                let name = AttributeValue::StringRef(strings.add(&b"child2"[..]));
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
            let unit2 = units.get(unit2);
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
        let debug_line_str_offsets = DebugLineStrOffsets::none();
        let debug_str_offsets = strings.write(&mut sections.debug_str).unwrap();
        units
            .write(&mut sections, &debug_line_str_offsets, &debug_str_offsets)
            .unwrap();

        println!("{:?}", sections.debug_str);
        println!("{:?}", sections.debug_info);
        println!("{:?}", sections.debug_abbrev);

        let dwarf = read::Dwarf {
            debug_abbrev: read::DebugAbbrev::new(sections.debug_abbrev.slice(), LittleEndian),
            debug_info: read::DebugInfo::new(sections.debug_info.slice(), LittleEndian),
            debug_str: read::DebugStr::new(sections.debug_str.slice(), LittleEndian),
            ..Default::default()
        };
        let mut read_units = dwarf.units();

        {
            let read_unit1 = read_units.next().unwrap().unwrap();
            let unit1 = units.get(unit_id1);
            assert_eq!(unit1.version(), read_unit1.version());
            assert_eq!(unit1.address_size(), read_unit1.address_size());
            assert_eq!(unit1.format(), read_unit1.format());

            let read_unit1 = dwarf.unit(read_unit1).unwrap();
            let mut read_entries = read_unit1.entries();

            let root = unit1.get(unit1.root());
            {
                let (depth, read_root) = read_entries.next_dfs().unwrap().unwrap();
                assert_eq!(depth, 0);
                assert_eq!(root.tag(), read_root.tag());
                assert!(read_root.has_children());

                let producer = match root.get(constants::DW_AT_producer).unwrap() {
                    AttributeValue::String(ref producer) => &**producer,
                    otherwise => panic!("unexpected {:?}", otherwise),
                };
                assert_eq!(producer, b"root");
                let read_producer = read_root
                    .attr_value(constants::DW_AT_producer)
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    dwarf
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
                let name = strings.get(name);
                assert_eq!(name, b"child1");
                let read_name = read_child
                    .attr_value(constants::DW_AT_name)
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    dwarf.attr_string(&read_unit1, read_name).unwrap().slice(),
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
                let name = strings.get(name);
                assert_eq!(name, b"child2");
                let read_name = read_child
                    .attr_value(constants::DW_AT_name)
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    dwarf.attr_string(&read_unit1, read_name).unwrap().slice(),
                    name
                );
            }

            assert!(read_entries.next_dfs().unwrap().is_none());
        }

        {
            let read_unit2 = read_units.next().unwrap().unwrap();
            let unit2 = units.get(unit2);
            assert_eq!(unit2.version(), read_unit2.version());
            assert_eq!(unit2.address_size(), read_unit2.address_size());
            assert_eq!(unit2.format(), read_unit2.format());

            let abbrevs = dwarf.abbreviations(&read_unit2).unwrap();
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
            let unit3 = units.get(unit3);
            assert_eq!(unit3.version(), read_unit3.version());
            assert_eq!(unit3.address_size(), read_unit3.address_size());
            assert_eq!(unit3.format(), read_unit3.format());

            let abbrevs = dwarf.abbreviations(&read_unit3).unwrap();
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

        let mut convert_line_strings = LineStringTable::default();
        let mut convert_strings = StringTable::default();
        let convert_units = UnitTable::from(
            &dwarf,
            &mut convert_line_strings,
            &mut convert_strings,
            &|address| Some(Address::Constant(address)),
        )
        .unwrap();
        assert_eq!(convert_units.count(), units.count());

        for i in 0..convert_units.count() {
            let unit_id = units.id(i);
            let unit = units.get(unit_id);
            let convert_unit_id = convert_units.id(i);
            let convert_unit = convert_units.get(convert_unit_id);
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
        // Create a string table and a string with a non-zero id/offset.
        let mut strings = StringTable::default();
        strings.add("string one");
        let string_id = strings.add("string two");
        let mut ranges = RangeListTable::default();
        let range_id = ranges.add(RangeList(vec![Range::StartEnd {
            begin: Address::Constant(0x1234),
            end: Address::Constant(0x2345),
        }]));

        let mut debug_str = DebugStr::from(EndianVec::new(LittleEndian));
        let debug_str_offsets = strings.write(&mut debug_str).unwrap();
        let read_debug_str = read::DebugStr::new(debug_str.slice(), LittleEndian);

        let mut line_strings = LineStringTable::default();
        line_strings.add("line string one");
        let line_string_id = line_strings.add("line string two");
        let mut debug_line_str = DebugLineStr::from(EndianVec::new(LittleEndian));
        let debug_line_str_offsets = line_strings.write(&mut debug_line_str).unwrap();
        let read_debug_line_str =
            read::DebugLineStr::from(read::EndianSlice::new(debug_line_str.slice(), LittleEndian));

        let data = vec![1, 2, 3, 4];
        let read_data = read::EndianSlice::new(&[1, 2, 3, 4], LittleEndian);

        for &version in &[2, 3, 4, 5] {
            for &address_size in &[4, 8] {
                for &format in &[Format::Dwarf32, Format::Dwarf64] {
                    let encoding = Encoding {
                        format,
                        version,
                        address_size,
                    };

                    let mut sections = Sections::new(EndianVec::new(LittleEndian));
                    let range_list_offsets = ranges.write(&mut sections, encoding).unwrap();
                    let read_debug_ranges =
                        read::DebugRanges::new(sections.debug_ranges.slice(), LittleEndian);
                    let read_debug_rnglists =
                        read::DebugRngLists::new(sections.debug_rnglists.slice(), LittleEndian);

                    let mut units = UnitTable::default();
                    let unit = units.add(Unit::new(encoding, LineProgram::none()));
                    let unit = units.get(unit);
                    let encoding = Encoding {
                        format,
                        version,
                        address_size,
                    };
                    let from_unit = read::UnitHeader::new(
                        encoding,
                        0,
                        DebugAbbrevOffset(0),
                        read::EndianSlice::new(&[], LittleEndian),
                    );

                    for &(ref name, ref value, ref expect_value) in &[
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
                            AttributeValue::Exprloc(Expression(data.clone())),
                            read::AttributeValue::Exprloc(read::Expression(read_data)),
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
                            constants::DW_AT_location,
                            AttributeValue::LocationListsRef(LocationListsOffset(0x1234)),
                            read::AttributeValue::SecOffset(0x1234),
                        ),
                        (
                            constants::DW_AT_macro_info,
                            AttributeValue::DebugMacinfoRef(DebugMacinfoOffset(0x1234)),
                            read::AttributeValue::SecOffset(0x1234),
                        ),
                        (
                            constants::DW_AT_ranges,
                            AttributeValue::RangeListRef(range_id),
                            read::AttributeValue::SecOffset(range_list_offsets.get(range_id).0),
                        ),
                        (
                            constants::DW_AT_name,
                            AttributeValue::DebugTypesRef(DebugTypeSignature(0x1234)),
                            read::AttributeValue::DebugTypesRef(DebugTypeSignature(0x1234)),
                        ),
                        (
                            constants::DW_AT_name,
                            AttributeValue::StringRef(string_id),
                            read::AttributeValue::DebugStrRef(debug_str_offsets.get(string_id)),
                        ),
                        (
                            constants::DW_AT_name,
                            AttributeValue::DebugStrRefSup(DebugStrOffset(0x1234)),
                            read::AttributeValue::DebugStrRefSup(DebugStrOffset(0x1234)),
                        ),
                        (
                            constants::DW_AT_name,
                            AttributeValue::LineStringRef(line_string_id),
                            read::AttributeValue::DebugLineStrRef(
                                debug_line_str_offsets.get(line_string_id),
                            ),
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
                    ][..]
                    {
                        let form = value.form(encoding).unwrap();
                        let attr = Attribute {
                            name: *name,
                            value: value.clone(),
                        };

                        let line_program_offset = None;
                        let mut unit_refs = Vec::new();
                        let mut debug_info_refs = Vec::new();
                        let mut debug_info = DebugInfo::from(EndianVec::new(LittleEndian));
                        attr.write(
                            &mut debug_info,
                            &unit,
                            line_program_offset,
                            &debug_line_str_offsets,
                            &debug_str_offsets,
                            &range_list_offsets,
                            &mut unit_refs,
                            &mut debug_info_refs,
                        )
                        .unwrap();

                        let spec = read::AttributeSpecification::new(*name, form, None);
                        let mut r = read::EndianSlice::new(debug_info.slice(), LittleEndian);
                        let (read_attr, _) =
                            read::parse_attribute(&mut r, &from_unit, &[spec]).unwrap();
                        let read_value = &read_attr.raw_value();
                        // read::AttributeValue is invariant in the lifetime of R.
                        // The lifetimes here are all okay, so transmute it.
                        let read_value = unsafe {
                            mem::transmute::<
                                &read::AttributeValue<read::EndianSlice<LittleEndian>>,
                                &read::AttributeValue<read::EndianSlice<LittleEndian>>,
                            >(read_value)
                        };
                        assert_eq!(read_value, expect_value);

                        let dwarf = read::Dwarf {
                            debug_str: read_debug_str.clone(),
                            debug_line_str: read_debug_line_str.clone(),
                            ranges: read::RangeLists::new(read_debug_ranges, read_debug_rnglists),
                            ..Default::default()
                        };

                        let unit = read::Unit {
                            offset: UnitSectionOffset::DebugInfoOffset(DebugInfoOffset(0)),
                            header: from_unit,
                            abbreviations: read::Abbreviations::default(),
                            name: None,
                            comp_dir: None,
                            low_pc: 0,
                            str_offsets_base: DebugStrOffsetsBase(0),
                            addr_base: DebugAddrBase(0),
                            loclists_base: DebugLocListsBase(0),
                            rnglists_base: DebugRngListsBase(0),
                            line_program: None,
                        };

                        let mut context = convert::ConvertUnitContext {
                            dwarf: &dwarf,
                            unit: &unit,
                            line_strings: &mut line_strings,
                            strings: &mut strings,
                            ranges: &mut ranges,
                            convert_address: &|address| Some(Address::Constant(address)),
                            base_address: Address::Constant(0),
                            line_program_offset: None,
                            line_program_files: Vec::new(),
                        };

                        let convert_attr =
                            Attribute::from(&mut context, &read_attr).unwrap().unwrap();
                        assert_eq!(convert_attr, attr);
                    }
                }
            }
        }
    }

    #[test]
    #[allow(clippy::cyclomatic_complexity)]
    fn test_unit_ref() {
        let mut units = UnitTable::default();
        let unit_id1 = units.add(Unit::new(
            Encoding {
                version: 4,
                address_size: 8,
                format: Format::Dwarf32,
            },
            LineProgram::none(),
        ));
        assert_eq!(unit_id1, UnitId::new(units.base_id, 0));
        let unit_id2 = units.add(Unit::new(
            Encoding {
                version: 2,
                address_size: 4,
                format: Format::Dwarf64,
            },
            LineProgram::none(),
        ));
        assert_eq!(unit_id2, UnitId::new(units.base_id, 1));
        let unit1_child1 = UnitEntryId::new(units.get(unit_id1).base_id, 1);
        let unit1_child2 = UnitEntryId::new(units.get(unit_id1).base_id, 2);
        let unit2_child1 = UnitEntryId::new(units.get(unit_id2).base_id, 1);
        let unit2_child2 = UnitEntryId::new(units.get(unit_id2).base_id, 2);
        {
            let unit1 = units.get_mut(unit_id1);
            let root = unit1.root();
            let child_id1 = unit1.add(root, constants::DW_TAG_subprogram);
            assert_eq!(child_id1, unit1_child1);
            let child_id2 = unit1.add(root, constants::DW_TAG_subprogram);
            assert_eq!(child_id2, unit1_child2);
            {
                let child1 = unit1.get_mut(child_id1);
                child1.set(
                    constants::DW_AT_type,
                    AttributeValue::ThisUnitEntryRef(child_id2),
                );
            }
            {
                let child2 = unit1.get_mut(child_id2);
                child2.set(
                    constants::DW_AT_type,
                    AttributeValue::AnyUnitEntryRef((unit_id2, unit2_child1)),
                );
            }
        }
        {
            let unit2 = units.get_mut(unit_id2);
            let root = unit2.root();
            let child_id1 = unit2.add(root, constants::DW_TAG_subprogram);
            assert_eq!(child_id1, unit2_child1);
            let child_id2 = unit2.add(root, constants::DW_TAG_subprogram);
            assert_eq!(child_id2, unit2_child2);
            {
                let child1 = unit2.get_mut(child_id1);
                child1.set(
                    constants::DW_AT_type,
                    AttributeValue::ThisUnitEntryRef(child_id2),
                );
            }
            {
                let child2 = unit2.get_mut(child_id2);
                child2.set(
                    constants::DW_AT_type,
                    AttributeValue::AnyUnitEntryRef((unit_id1, unit1_child1)),
                );
            }
        }

        let debug_line_str_offsets = DebugLineStrOffsets::none();
        let debug_str_offsets = DebugStrOffsets::none();
        let mut sections = Sections::new(EndianVec::new(LittleEndian));
        let debug_info_offsets = units
            .write(&mut sections, &debug_line_str_offsets, &debug_str_offsets)
            .unwrap();

        println!("{:?}", sections.debug_info);
        println!("{:?}", sections.debug_abbrev);

        let dwarf = read::Dwarf {
            debug_abbrev: read::DebugAbbrev::new(sections.debug_abbrev.slice(), LittleEndian),
            debug_info: read::DebugInfo::new(sections.debug_info.slice(), LittleEndian),
            ..Default::default()
        };

        let mut read_units = dwarf.units();
        {
            let read_unit1 = read_units.next().unwrap().unwrap();
            assert_eq!(read_unit1.offset(), debug_info_offsets.unit(unit_id1));

            let abbrevs = dwarf.abbreviations(&read_unit1).unwrap();
            let mut read_entries = read_unit1.entries(&abbrevs);
            {
                let (_, _read_root) = read_entries.next_dfs().unwrap().unwrap();
            }
            {
                let (_, read_child1) = read_entries.next_dfs().unwrap().unwrap();
                let offset = debug_info_offsets
                    .entry(unit_id1, unit1_child2)
                    .to_unit_offset(&read_unit1)
                    .unwrap();
                assert_eq!(
                    read_child1.attr_value(constants::DW_AT_type).unwrap(),
                    Some(read::AttributeValue::UnitRef(offset))
                );
            }
            {
                let (_, read_child2) = read_entries.next_dfs().unwrap().unwrap();
                let offset = debug_info_offsets.entry(unit_id2, unit2_child1);
                assert_eq!(
                    read_child2.attr_value(constants::DW_AT_type).unwrap(),
                    Some(read::AttributeValue::DebugInfoRef(offset))
                );
            }
        }
        {
            let read_unit2 = read_units.next().unwrap().unwrap();
            assert_eq!(read_unit2.offset(), debug_info_offsets.unit(unit_id2));

            let abbrevs = dwarf.abbreviations(&read_unit2).unwrap();
            let mut read_entries = read_unit2.entries(&abbrevs);
            {
                let (_, _read_root) = read_entries.next_dfs().unwrap().unwrap();
            }
            {
                let (_, read_child1) = read_entries.next_dfs().unwrap().unwrap();
                let offset = debug_info_offsets
                    .entry(unit_id2, unit2_child2)
                    .to_unit_offset(&read_unit2)
                    .unwrap();
                assert_eq!(
                    read_child1.attr_value(constants::DW_AT_type).unwrap(),
                    Some(read::AttributeValue::UnitRef(offset))
                );
            }
            {
                let (_, read_child2) = read_entries.next_dfs().unwrap().unwrap();
                let offset = debug_info_offsets.entry(unit_id1, unit1_child1);
                assert_eq!(
                    read_child2.attr_value(constants::DW_AT_type).unwrap(),
                    Some(read::AttributeValue::DebugInfoRef(offset))
                );
            }
        }

        let mut convert_line_strings = LineStringTable::default();
        let mut convert_strings = StringTable::default();
        let convert_units = UnitTable::from(
            &dwarf,
            &mut convert_line_strings,
            &mut convert_strings,
            &|address| Some(Address::Constant(address)),
        )
        .unwrap();
        assert_eq!(convert_units.count(), units.count());

        for unit_id in 0..convert_units.count() {
            let unit = units.get(UnitId::new(units.base_id, unit_id));
            let convert_unit = convert_units.get(UnitId::new(convert_units.base_id, unit_id));
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
                        AttributeValue::AnyUnitEntryRef(convert_id),
                        AttributeValue::AnyUnitEntryRef(id),
                    ) => {
                        assert_eq!((convert_id.0).index, (id.0).index);
                        assert_eq!((convert_id.1).index, (id.1).index);
                    }
                    (
                        AttributeValue::ThisUnitEntryRef(convert_id),
                        AttributeValue::ThisUnitEntryRef(id),
                    ) => {
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
                        AttributeValue::AnyUnitEntryRef(convert_id),
                        AttributeValue::AnyUnitEntryRef(id),
                    ) => {
                        assert_eq!((convert_id.0).index, (id.0).index);
                        assert_eq!((convert_id.1).index, (id.1).index);
                    }
                    (
                        AttributeValue::ThisUnitEntryRef(convert_id),
                        AttributeValue::ThisUnitEntryRef(id),
                    ) => {
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

        fn add_children(units: &mut UnitTable, unit_id: UnitId) {
            let unit = units.get_mut(unit_id);
            let root = unit.root();
            let child1 = add_child(unit, root, constants::DW_TAG_subprogram, "child1");
            add_child(unit, child1, constants::DW_TAG_variable, "grandchild1");
            add_child(unit, root, constants::DW_TAG_subprogram, "child2");
            add_child(unit, root, constants::DW_TAG_subprogram, "child3");
        }

        fn next_child<R: read::Reader<Offset = usize>>(
            entries: &mut read::EntriesCursor<R>,
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
            unit: &read::CompilationUnitHeader<R>,
            debug_abbrev: &read::DebugAbbrev<R>,
        ) {
            let abbrevs = unit.abbreviations(debug_abbrev).unwrap();
            let mut entries = unit.entries(&abbrevs);
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
        let mut units = UnitTable::default();
        let unit_id1 = units.add(Unit::new(encoding, LineProgram::none()));
        add_children(&mut units, unit_id1);
        let unit_id2 = units.add(Unit::new(encoding, LineProgram::none()));
        add_children(&mut units, unit_id2);

        let debug_line_str_offsets = DebugLineStrOffsets::none();
        let debug_str_offsets = DebugStrOffsets::none();
        let mut sections = Sections::new(EndianVec::new(LittleEndian));
        units
            .write(&mut sections, &debug_line_str_offsets, &debug_str_offsets)
            .unwrap();

        println!("{:?}", sections.debug_info);
        println!("{:?}", sections.debug_abbrev);

        let read_debug_info = read::DebugInfo::new(sections.debug_info.slice(), LittleEndian);
        let read_debug_abbrev = read::DebugAbbrev::new(sections.debug_abbrev.slice(), LittleEndian);
        let mut read_units = read_debug_info.units();
        check_sibling(&read_units.next().unwrap().unwrap(), &read_debug_abbrev);
        check_sibling(&read_units.next().unwrap().unwrap(), &read_debug_abbrev);
    }

    #[test]
    fn test_line_ref() {
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
                        LineString::String(b"comp_dir".to_vec()),
                        LineString::String(b"comp_name".to_vec()),
                        None,
                    );
                    let dir = line_program.default_directory();
                    let file1 =
                        line_program.add_file(LineString::String(b"file1".to_vec()), dir, None);
                    let file2 =
                        line_program.add_file(LineString::String(b"file2".to_vec()), dir, None);

                    // Write, read, and convert the line program, so that we have the info
                    // required to convert the attributes.
                    let line_strings = DebugLineStrOffsets::none();
                    let strings = DebugStrOffsets::none();
                    let mut debug_line = DebugLine::from(EndianVec::new(LittleEndian));
                    let line_program_offset = line_program
                        .write(&mut debug_line, encoding, &line_strings, &strings)
                        .unwrap();
                    let read_debug_line = read::DebugLine::new(debug_line.slice(), LittleEndian);
                    let read_line_program = read_debug_line
                        .program(
                            line_program_offset,
                            address_size,
                            Some(read::EndianSlice::new(b"comp_dir", LittleEndian)),
                            Some(read::EndianSlice::new(b"comp_name", LittleEndian)),
                        )
                        .unwrap();
                    let dwarf = read::Dwarf::default();
                    let mut convert_line_strings = LineStringTable::default();
                    let mut convert_strings = StringTable::default();
                    let (_, line_program_files) = LineProgram::from(
                        read_line_program,
                        &dwarf,
                        &mut convert_line_strings,
                        &mut convert_strings,
                        &|address| Some(Address::Constant(address)),
                    )
                    .unwrap();

                    // Fake the unit.
                    let mut units = UnitTable::default();
                    let unit = units.add(Unit::new(encoding, LineProgram::none()));
                    let unit = units.get(unit);
                    let from_unit = read::UnitHeader::new(
                        encoding,
                        0,
                        DebugAbbrevOffset(0),
                        read::EndianSlice::new(&[], LittleEndian),
                    );

                    for &(ref name, ref value, ref expect_value) in &[
                        (
                            constants::DW_AT_stmt_list,
                            AttributeValue::LineProgramRef,
                            read::AttributeValue::SecOffset(line_program_offset.0),
                        ),
                        (
                            constants::DW_AT_decl_file,
                            AttributeValue::FileIndex(Some(file1)),
                            read::AttributeValue::Udata(file1.raw()),
                        ),
                        (
                            constants::DW_AT_decl_file,
                            AttributeValue::FileIndex(Some(file2)),
                            read::AttributeValue::Udata(file2.raw()),
                        ),
                    ][..]
                    {
                        let mut ranges = RangeListTable::default();
                        let mut strings = StringTable::default();
                        let debug_str_offsets = DebugStrOffsets::none();
                        let mut line_strings = LineStringTable::default();
                        let debug_line_str_offsets = DebugLineStrOffsets::none();

                        let form = value.form(encoding).unwrap();
                        let attr = Attribute {
                            name: *name,
                            value: value.clone(),
                        };

                        let mut unit_refs = Vec::new();
                        let mut debug_info_refs = Vec::new();
                        let mut debug_info = DebugInfo::from(EndianVec::new(LittleEndian));
                        let range_list_offsets = RangeListOffsets::none();
                        attr.write(
                            &mut debug_info,
                            &unit,
                            Some(line_program_offset),
                            &debug_line_str_offsets,
                            &debug_str_offsets,
                            &range_list_offsets,
                            &mut unit_refs,
                            &mut debug_info_refs,
                        )
                        .unwrap();

                        let spec = read::AttributeSpecification::new(*name, form, None);
                        let mut r = read::EndianSlice::new(debug_info.slice(), LittleEndian);
                        let (read_attr, _) =
                            read::parse_attribute(&mut r, &from_unit, &[spec]).unwrap();
                        let read_value = &read_attr.raw_value();
                        // read::AttributeValue is invariant in the lifetime of R.
                        // The lifetimes here are all okay, so transmute it.
                        let read_value = unsafe {
                            mem::transmute::<
                                &read::AttributeValue<read::EndianSlice<LittleEndian>>,
                                &read::AttributeValue<read::EndianSlice<LittleEndian>>,
                            >(read_value)
                        };
                        assert_eq!(read_value, expect_value);

                        let unit = read::Unit {
                            offset: UnitSectionOffset::DebugInfoOffset(DebugInfoOffset(0)),
                            header: from_unit,
                            abbreviations: read::Abbreviations::default(),
                            name: None,
                            comp_dir: None,
                            low_pc: 0,
                            str_offsets_base: DebugStrOffsetsBase(0),
                            addr_base: DebugAddrBase(0),
                            loclists_base: DebugLocListsBase(0),
                            rnglists_base: DebugRngListsBase(0),
                            line_program: None,
                        };

                        let mut context = convert::ConvertUnitContext {
                            dwarf: &dwarf,
                            unit: &unit,
                            line_strings: &mut line_strings,
                            strings: &mut strings,
                            ranges: &mut ranges,
                            convert_address: &|address| Some(Address::Constant(address)),
                            base_address: Address::Constant(0),
                            line_program_offset: Some(line_program_offset),
                            line_program_files: line_program_files.clone(),
                        };

                        let convert_attr =
                            Attribute::from(&mut context, &read_attr).unwrap().unwrap();
                        assert_eq!(convert_attr, attr);
                    }
                }
            }
        }
    }

    #[test]
    fn test_line_program_used() {
        for used in vec![false, true] {
            let encoding = Encoding {
                format: Format::Dwarf32,
                version: 5,
                address_size: 8,
            };

            let line_program = LineProgram::new(
                encoding,
                LineEncoding::default(),
                LineString::String(b"comp_dir".to_vec()),
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

            let mut units = UnitTable::default();
            units.add(unit);

            let debug_line_str_offsets = DebugLineStrOffsets::none();
            let debug_str_offsets = DebugStrOffsets::none();
            let mut sections = Sections::new(EndianVec::new(LittleEndian));
            units
                .write(&mut sections, &debug_line_str_offsets, &debug_str_offsets)
                .unwrap();
            assert_eq!(!used, sections.debug_line.slice().is_empty());
        }
    }
}
