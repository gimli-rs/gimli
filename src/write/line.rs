use indexmap::{IndexMap, IndexSet};
use std::ops::{Deref, DerefMut};
use vec::Vec;

use common::{DebugLineOffset, Format};
use constants;
use leb128;
use write::{Address, Error, Result, Section, SectionId, Writer};

/// A table of line number programs that will be stored in a `.debug_line` section.
#[derive(Debug, Default)]
pub struct LineProgramTable {
    programs: Vec<LineProgram>,
}

impl LineProgramTable {
    /// Add a line number program to the table.
    pub fn add(&mut self, program: LineProgram) -> LineProgramId {
        let id = LineProgramId(self.programs.len());
        self.programs.push(program);
        id
    }

    /// Return the number of line number programs in the table.
    #[inline]
    pub fn count(&self) -> usize {
        self.programs.len()
    }

    /// Get a reference to a line number program.
    ///
    /// # Panics
    ///
    /// Panics if `id` is invalid.
    #[inline]
    pub fn get(&self, id: LineProgramId) -> &LineProgram {
        &self.programs[id.0]
    }

    /// Get a mutable reference to a line number program.
    ///
    /// # Panics
    ///
    /// Panics if `id` is invalid.
    #[inline]
    pub fn get_mut(&mut self, id: LineProgramId) -> &mut LineProgram {
        &mut self.programs[id.0]
    }

    /// Write the line number programs to the given section.
    pub fn write<W: Writer>(&self, debug_line: &mut DebugLine<W>) -> Result<DebugLineOffsets> {
        let mut offsets = Vec::new();
        for program in &self.programs {
            offsets.push(program.write(debug_line)?);
        }
        Ok(DebugLineOffsets { offsets })
    }
}

/// An identifier for a `LineProgram` in a `LineProgramTable`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LineProgramId(pub usize);

/// The initial value of the `is_statement` register.
//
// Currently we don't allow this to be configured.
const DEFAULT_IS_STATEMENT: bool = true;

/// The number assigned to the first special opcode.
//
// We output all instructions for all DWARF versions, since readers
// should be able to ignore instructions they don't support.
const OPCODE_BASE: u8 = 13;

/// A line number program.
#[derive(Debug, Clone)]
pub struct LineProgram {
    /// DWARF version, not necessarily section version.
    version: u16,
    /// The size in bytes of a target machine address.
    address_size: u8,
    // TODO: this should be automatic
    format: Format,
    /// The minimum size in bytes of a target machine instruction.
    /// All instruction lengths must be a multiple of this size.
    minimum_instruction_length: u8,
    /// The maximum number of individual operations that may be encoded in an
    /// instruction. For non-VLIW architectures, this field is 1.
    maximum_operations_per_instruction: u8,
    /// Minimum line increment for special opcodes.
    line_base: i8,
    /// Range of line increment for special opcodes.
    line_range: u8,

    /// A list of source directory path names.
    ///
    /// If a path is relative, then the directory is located relative to the working
    /// directory of the compilation unit.
    ///
    /// The first entry is for the working directory of the compilation unit.
    directories: IndexSet<Vec<u8>>,

    /// A list of source file entries.
    ///
    /// Each entry has a path name and a directory.
    ///
    /// If a path is a relative, then the file is located relative to the
    /// directory. Otherwise the directory is meaningless.
    ///
    /// For version >= 5, the first entry is for the primary source file
    /// of the compilation unit.
    files: IndexMap<(Vec<u8>, DirectoryId), FileInfo>,

    prev_row: LineRow,
    row: LineRow,
    // TODO: this probably should be either rows or sequences instead
    instructions: Vec<LineInstruction>,
    in_sequence: bool,
}

impl LineProgram {
    /// Create a new `LineProgram`.
    ///
    /// `comp_dir` defines the working directory of the compilation unit,
    /// and must be the same as the `DW_AT_comp_dir` attribute
    /// of the compilation unit DIE.
    ///
    /// `comp_file` and `comp_file_info` define the primary source file
    /// of the compilation unit and must be the same as the `DW_AT_name`
    /// attribute of the compilation unit DIE.
    ///
    /// # Panics
    ///
    /// Panics if `line_base` > 0.
    /// Panics if `line_base` + `line_range` <= 0.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        version: u16,
        address_size: u8,
        format: Format,
        minimum_instruction_length: u8,
        maximum_operations_per_instruction: u8,
        line_base: i8,
        line_range: u8,
        comp_dir: &[u8],
        comp_file: &[u8],
        comp_file_info: Option<FileInfo>,
    ) -> LineProgram {
        // We require a special opcode for a line advance of 0.
        // See the debug_asserts in generate_row().
        assert!(line_base <= 0);
        assert!(line_base + line_range as i8 > 0);
        let mut program = LineProgram {
            version,
            address_size,
            format,
            minimum_instruction_length,
            maximum_operations_per_instruction,
            line_base,
            line_range,
            directories: IndexSet::new(),
            files: IndexMap::new(),
            prev_row: LineRow::initial_state(),
            row: LineRow::new(version),
            instructions: Vec::new(),
            in_sequence: false,
        };
        // For all DWARF versions, directory index 0 is comp_dir.
        // For version <= 4, the entry is implicit. We still add
        // it here so that we use it, but we don't emit it.
        let dir = program.add_directory(comp_dir);
        // For DWARF version >= 5, file index 0 is comp_name.
        // For version <= 4, file index 0 is invalid. We potentially could
        // add comp_name as index 1, but don't in case it is unused.
        if version >= 5 {
            program.add_file(comp_file, dir, comp_file_info);
        }
        program
    }

    /// Return the DWARF version for this line program.
    #[inline]
    pub fn version(&self) -> u16 {
        self.version
    }

    /// Return the address size in bytes for this line program.
    #[inline]
    pub fn address_size(&self) -> u8 {
        self.address_size
    }

    /// Return the DWARF format for this line program.
    #[inline]
    pub fn format(&self) -> Format {
        self.format
    }

    /// Return the id for the working directory of the compilation unit.
    #[inline]
    pub fn default_directory(&self) -> DirectoryId {
        DirectoryId(0)
    }

    /// Add a directory entry and return its id.
    ///
    /// If the directory already exists, then return the id of the existing entry.
    ///
    /// If the path is relative, then the directory is located relative to the working
    /// directory of the compilation unit.
    ///
    /// # Panics
    ///
    /// Panics if `directory` contains a null byte.
    pub fn add_directory(&mut self, directory: &[u8]) -> DirectoryId {
        // Duplicate entries are common, so only allocate if it doesn't exist.
        if let Some((index, _)) = self.directories.get_full(directory) {
            DirectoryId(index)
        } else {
            assert!(!directory.contains(&0));
            let (index, _) = self.directories.insert_full(directory.to_vec());
            DirectoryId(index)
        }
    }

    /// Get a reference to a directory entry.
    ///
    /// # Panics
    ///
    /// Panics if `id` is invalid.
    pub fn get_directory(&self, id: DirectoryId) -> &[u8] {
        self.directories.get_index(id.0).map(Vec::as_slice).unwrap()
    }

    /// Add a file entry and return its id.
    ///
    /// If the file already exists, then return the id of the existing entry.
    ///
    /// If the file path is relative, then the file is located relative
    /// to the directory. Otherwise the directory is meaningless, but it
    /// is still used as a key for file entries.
    ///
    /// If `info` is `None`, then new entries are assigned
    /// default information, and existing entries are unmodified.
    ///
    /// If `info` is not `None`, then it is always assigned to the
    /// entry, even if the entry already exists.
    ///
    /// # Panics
    ///
    /// Panics if 'file' contain a null byte.
    pub fn add_file(
        &mut self,
        file: &[u8],
        directory: DirectoryId,
        info: Option<FileInfo>,
    ) -> FileId {
        assert!(!file.contains(&0));
        // Always allocates because we can't implement Borrow for this.
        let key = (file.to_vec(), directory);
        let index = if let Some(info) = info {
            let (index, _) = self.files.insert_full(key, info);
            index
        } else {
            let entry = self.files.entry(key);
            let index = entry.index();
            entry.or_insert(FileInfo::default());
            index
        };
        FileId::new(index, self.version)
    }

    /// Get a reference to a file entry.
    ///
    /// # Panics
    ///
    /// Panics if `id` is invalid.
    pub fn get_file(&self, id: FileId) -> (&[u8], DirectoryId) {
        self.files
            .get_index(id.index(self.version))
            .map(|entry| ((entry.0).0.as_slice(), (entry.0).1))
            .unwrap()
    }

    /// Get a reference to the info for a file entry.
    ///
    /// # Panics
    ///
    /// Panics if `id` is invalid.
    pub fn get_file_info(&self, id: FileId) -> &FileInfo {
        self.files
            .get_index(id.index(self.version))
            .map(|entry| entry.1)
            .unwrap()
    }

    /// Get a mutable reference to the info for a file entry.
    ///
    /// # Panics
    ///
    /// Panics if `id` is invalid.
    pub fn get_file_info_mut(&mut self, id: FileId) -> &mut FileInfo {
        self.files
            .get_index_mut(id.index(self.version))
            .map(|entry| entry.1)
            .unwrap()
    }

    /// Begin a new sequence and set its base address.
    ///
    /// # Panics
    ///
    /// Panics if a sequence has already begun.
    pub fn begin_sequence(&mut self, address: Option<Address>) {
        assert!(!self.in_sequence);
        self.in_sequence = true;
        if let Some(address) = address {
            self.instructions.push(LineInstruction::SetAddress(address));
        }
    }

    /// End the sequence, and reset the row to its default values.
    ///
    /// Only the `address_offset` and op_index` fields of the current row are used.
    ///
    /// # Panics
    ///
    /// Panics if a sequence has not begun.
    pub fn end_sequence(&mut self, address_offset: u64) {
        assert!(self.in_sequence);
        self.in_sequence = false;
        self.row.address_offset = address_offset;
        let op_advance = self.op_advance();
        if op_advance != 0 {
            self.instructions
                .push(LineInstruction::AdvancePc(op_advance));
        }
        self.instructions.push(LineInstruction::EndSequence);
        self.prev_row = LineRow::initial_state();
        self.row = LineRow::new(self.version);
    }

    /// Return true if a sequence has begun.
    #[inline]
    pub fn in_sequence(&self) -> bool {
        self.in_sequence
    }

    /// Returns a reference to the data for the current row.
    #[inline]
    pub fn row(&mut self) -> &mut LineRow {
        &mut self.row
    }

    /// Generates the line number information instructions for the current row.
    ///
    /// After the instructions are generated, it sets `discriminator` to 0, and sets
    /// `basic_block`, `prologue_end`, and `epilogue_begin` to false.
    ///
    /// # Panics
    ///
    /// Panics if a sequence has not begun.
    /// Panics if the address_offset decreases.
    pub fn generate_row(&mut self) {
        assert!(self.in_sequence);

        // Output fields that are reset on every row.
        if self.row.discriminator != 0 {
            self.instructions
                .push(LineInstruction::SetDiscriminator(self.row.discriminator));
            self.row.discriminator = 0;
        }
        if self.row.basic_block {
            self.instructions.push(LineInstruction::SetBasicBlock);
            self.row.basic_block = false;
        }
        if self.row.prologue_end {
            self.instructions.push(LineInstruction::SetPrologueEnd);
            self.row.prologue_end = false;
        }
        if self.row.epilogue_begin {
            self.instructions.push(LineInstruction::SetEpilogueBegin);
            self.row.epilogue_begin = false;
        }

        // Output fields that are not reset on every row.
        if self.row.is_statement != self.prev_row.is_statement {
            self.instructions.push(LineInstruction::NegateStatement);
        }
        if self.row.file != self.prev_row.file {
            self.instructions
                .push(LineInstruction::SetFile(self.row.file));
        }
        if self.row.column != self.prev_row.column {
            self.instructions
                .push(LineInstruction::SetColumn(self.row.column));
        }
        if self.row.isa != self.prev_row.isa {
            self.instructions
                .push(LineInstruction::SetIsa(self.row.isa));
        }

        // Advance the line, address, and operation index.
        let line_base = i64::from(self.line_base) as u64;
        let line_range = u64::from(self.line_range);
        let line_advance = self.row.line as i64 - self.prev_row.line as i64;
        let op_advance = self.op_advance();

        // Default to special advances of 0.
        let special_base = u64::from(OPCODE_BASE);
        // TODO: handle lack of special opcodes for 0 line advance
        debug_assert!(self.line_base <= 0);
        debug_assert!(self.line_base + self.line_range as i8 >= 0);
        let special_default = special_base.wrapping_sub(line_base);
        let mut special = special_default;
        let mut use_special = false;

        if line_advance != 0 {
            let special_line = (line_advance as u64).wrapping_sub(line_base);
            if special_line < line_range {
                special = special_base + special_line;
                use_special = true;
            } else {
                self.instructions
                    .push(LineInstruction::AdvanceLine(line_advance));
            }
        }

        if op_advance != 0 {
            // Using ConstAddPc can save a byte.
            let (special_op_advance, const_add_pc) = if special + op_advance * line_range <= 255 {
                (op_advance, false)
            } else {
                let op_range = (255 - special_base) / line_range;
                (op_advance - op_range, true)
            };

            let special_op = special_op_advance * line_range;
            if special + special_op <= 255 {
                special += special_op;
                use_special = true;
                if const_add_pc {
                    self.instructions.push(LineInstruction::ConstAddPc);
                }
            } else {
                self.instructions
                    .push(LineInstruction::AdvancePc(op_advance));
            }
        }

        if use_special && special != special_default {
            debug_assert!(special >= special_base);
            debug_assert!(special <= 255);
            self.instructions
                .push(LineInstruction::Special(special as u8));
        } else {
            self.instructions.push(LineInstruction::Copy);
        }

        self.prev_row = self.row;
    }

    fn op_advance(&self) -> u64 {
        debug_assert!(self.row.address_offset >= self.prev_row.address_offset);
        debug_assert_eq!(
            self.row.address_offset % u64::from(self.minimum_instruction_length),
            0
        );
        let address_advance = (self.row.address_offset - self.prev_row.address_offset)
            / u64::from(self.minimum_instruction_length);
        address_advance * u64::from(self.maximum_operations_per_instruction) + self.row.op_index
            - self.prev_row.op_index
    }

    /// Write the line number program to the given section.
    pub fn write<W: Writer>(&self, w: &mut DebugLine<W>) -> Result<DebugLineOffset> {
        let offset = w.offset();

        let length_offset = w.write_initial_length(self.format)?;
        let length_base = w.len();

        if self.version < 2 || self.version > 4 {
            return Err(Error::UnsupportedVersion(self.version));
        }
        w.write_u16(self.version)?;

        let header_length_offset = w.len();
        w.write_word(0, self.format.word_size())?;
        let header_length_base = w.len();

        w.write_u8(self.minimum_instruction_length)?;
        if self.version >= 4 {
            w.write_u8(self.maximum_operations_per_instruction)?;
        } else if self.maximum_operations_per_instruction != 1 {
            return Err(Error::NeedVersion(4));
        };
        w.write_u8(if DEFAULT_IS_STATEMENT { 1 } else { 0 })?;
        w.write_u8(self.line_base as u8)?;
        w.write_u8(self.line_range)?;
        w.write_u8(OPCODE_BASE)?;
        w.write(&[0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1])?;

        let dir_base = if self.version <= 4 { 1 } else { 0 };
        for dir in self.directories.iter().skip(dir_base) {
            w.write(dir)?;
            w.write_u8(0)?;
        }
        w.write_u8(0)?;

        for ((file, dir), info) in self.files.iter() {
            w.write(file)?;
            w.write_u8(0)?;
            w.write_uleb128(dir.0 as u64)?;
            w.write_uleb128(info.last_modification)?;
            w.write_uleb128(info.length)?;
        }
        w.write_u8(0)?;

        let header_length = (w.len() - header_length_base) as u64;
        w.write_word_at(header_length_offset, header_length, self.format.word_size())?;

        for instruction in &self.instructions {
            instruction.write(w, self.address_size)?;
        }

        let length = (w.len() - length_base) as u64;
        w.write_initial_length_at(length_offset, length, self.format)?;

        Ok(offset)
    }
}

/// A row in the line number table that corresponds to a machine instruction.
#[derive(Debug, Clone, Copy)]
pub struct LineRow {
    /// The offset of the instruction from the start address of the sequence.
    pub address_offset: u64,
    /// The index of an operation within a VLIW instruction.
    ///
    /// The index of the first operation is 0.
    /// Set to 0 for non-VLIW instructions.
    pub op_index: u64,

    /// The source file corresponding to the instruction.
    pub file: FileId,
    /// The line number within the source file.
    ///
    /// Lines are numbered beginning at 1. Set to 0 if there is no source line.
    pub line: u64,
    /// The column number within the source line.
    ///
    /// Columns are numbered beginning at 1. Set to 0 for the "left edge" of the line.
    pub column: u64,
    /// An additional discriminator used to distinguish between source locations.
    /// This value is assigned arbitrarily by the DWARF producer.
    pub discriminator: u64,

    /// Set to true if the instruction is a recommended breakpoint for a statement.
    pub is_statement: bool,
    /// Set to true if the instruction is the beginning of a basic block.
    pub basic_block: bool,
    /// Set to true if the instruction is a recommended breakpoint at the entry of a
    /// function.
    pub prologue_end: bool,
    /// Set to true if the instruction is a recommended breakpoint prior to the exit of
    /// a function.
    pub epilogue_begin: bool,

    /// The instruction set architecture of the instruction.
    ///
    /// Set to 0 for the default ISA. Other values are defined by the architecture ABI.
    pub isa: u64,
}

impl LineRow {
    /// Return the initial state as specified in the DWARF standard.
    fn initial_state() -> Self {
        LineRow {
            address_offset: 0,
            op_index: 0,

            file: FileId::initial_state(),
            line: 1,
            column: 0,
            discriminator: 0,

            is_statement: DEFAULT_IS_STATEMENT,
            basic_block: false,
            prologue_end: false,
            epilogue_begin: false,

            isa: 0,
        }
    }

    fn new(version: u16) -> Self {
        let mut row = LineRow::initial_state();
        // This is a safer default than FileId(1) if version >= 5.
        row.file = FileId::new(0, version);
        row
    }
}

/// An instruction in a line number program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LineInstruction {
    // Special opcodes
    Special(u8),

    // Standard opcodes
    Copy,
    AdvancePc(u64),
    AdvanceLine(i64),
    SetFile(FileId),
    SetColumn(u64),
    NegateStatement,
    SetBasicBlock,
    ConstAddPc,
    // DW_LNS_fixed_advance_pc is not supported.
    SetPrologueEnd,
    SetEpilogueBegin,
    SetIsa(u64),

    // Extended opcodes
    EndSequence,
    // TODO: this doubles the size of this enum.
    SetAddress(Address),
    // DW_LNE_define_file is not supported.
    SetDiscriminator(u64),
}

impl LineInstruction {
    /// Write the line number instruction to the given section.
    fn write<W: Writer>(self, w: &mut DebugLine<W>, address_size: u8) -> Result<()> {
        use self::LineInstruction::*;
        match self {
            Special(val) => w.write_u8(val)?,
            Copy => w.write_u8(constants::DW_LNS_copy.0)?,
            AdvancePc(val) => {
                w.write_u8(constants::DW_LNS_advance_pc.0)?;
                w.write_uleb128(val)?;
            }
            AdvanceLine(val) => {
                w.write_u8(constants::DW_LNS_advance_line.0)?;
                w.write_sleb128(val)?;
            }
            SetFile(val) => {
                w.write_u8(constants::DW_LNS_set_file.0)?;
                w.write_uleb128(val.raw())?;
            }
            SetColumn(val) => {
                w.write_u8(constants::DW_LNS_set_column.0)?;
                w.write_uleb128(val)?;
            }
            NegateStatement => w.write_u8(constants::DW_LNS_negate_stmt.0)?,
            SetBasicBlock => w.write_u8(constants::DW_LNS_set_basic_block.0)?,
            ConstAddPc => w.write_u8(constants::DW_LNS_const_add_pc.0)?,
            SetPrologueEnd => w.write_u8(constants::DW_LNS_set_prologue_end.0)?,
            SetEpilogueBegin => w.write_u8(constants::DW_LNS_set_epilogue_begin.0)?,
            SetIsa(val) => {
                w.write_u8(constants::DW_LNS_set_isa.0)?;
                w.write_uleb128(val)?;
            }
            EndSequence => {
                w.write_u8(0)?;
                w.write_uleb128(1)?;
                w.write_u8(constants::DW_LNE_end_sequence.0)?;
            }
            SetAddress(address) => {
                w.write_u8(0)?;
                w.write_uleb128(1 + u64::from(address_size))?;
                w.write_u8(constants::DW_LNE_set_address.0)?;
                w.write_address(address, address_size)?;
            }
            SetDiscriminator(val) => {
                let mut bytes = [0u8; 10];
                // bytes is long enough so this will never fail.
                let len = leb128::write::unsigned(&mut { &mut bytes[..] }, val).unwrap();
                w.write_u8(0)?;
                w.write_uleb128(1 + len as u64)?;
                w.write_u8(constants::DW_LNE_set_discriminator.0)?;
                w.write(&bytes[..len])?;
            }
        }
        Ok(())
    }
}

/// An identifier for a directory in a `LineProgram`.
///
/// Defaults to the working directory of the compilation unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DirectoryId(usize);

// Force FileId access via the methods.
mod id {
    /// An identifier for a file in a `LineProgram`.
    ///
    /// Defaults to the primary source file of the compilation unit.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FileId(usize);

    impl FileId {
        pub(crate) fn new(index: usize, version: u16) -> Self {
            if version <= 4 {
                FileId(index + 1)
            } else {
                FileId(index)
            }
        }

        /// The index of the file in `LineProgram::files`.
        pub(crate) fn index(self, version: u16) -> usize {
            if version <= 4 {
                // There's never a FileId(0) for version <= 4.
                self.0 - 1
            } else {
                self.0
            }
        }

        /// The initial state of the file register.
        pub(crate) fn initial_state() -> Self {
            FileId(1)
        }

        /// The raw value used when writing.
        pub(crate) fn raw(self) -> u64 {
            self.0 as u64
        }
    }
}
pub use self::id::*;

/// Extra information for file in a `LineProgram`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct FileInfo {
    /// The implementation defined timestamp of the last modification of the file,
    /// or 0 if not available.
    pub last_modification: u64,
    /// The size of the file in bytes, or 0 if not available.
    pub length: u64,
}

define_section!(DebugLine, DebugLineOffset, "A writable `.debug_line` section.");

define_offsets!(
    DebugLineOffsets: LineProgramId => DebugLineOffset,
    "The section offsets of all line number programs within a `.debug_line` section."
);

#[cfg(feature = "read")]
mod convert {
    use super::*;
    use read::{self, Reader};
    use write::{ConvertError, ConvertResult};

    impl LineProgram {
        /// Create a line number program by reading the data from the given program.
        ///
        /// Return the program and a mapping from file index to `FileId`.
        pub fn from<R: Reader<Offset = usize>>(
            mut from_program: read::IncompleteLineProgram<R, R::Offset>,
            convert_address: &Fn(u64) -> Option<Address>,
        ) -> ConvertResult<(LineProgram, Vec<FileId>)> {
            // Create mappings in case the source has duplicate files or directories.
            let mut dirs = Vec::new();
            let mut files = Vec::new();

            let mut program = {
                let from_header = from_program.header();

                let comp_dir = from_header
                    .directory(0)
                    .ok_or(ConvertError::MissingCompilationDirectory)?;

                let comp_file = from_header
                    .file(0)
                    .ok_or(ConvertError::MissingCompilationFile)?;
                if comp_file.directory_index() != 0 {
                    return Err(ConvertError::InvalidDirectoryIndex);
                }
                let comp_file_info = FileInfo {
                    last_modification: comp_file.last_modification(),
                    length: comp_file.length(),
                };

                if from_header.line_base() > 0 {
                    return Err(ConvertError::InvalidLineBase);
                }
                let mut program = LineProgram::new(
                    from_header.version(),
                    from_header.address_size(),
                    from_header.format(),
                    from_header.minimum_instruction_length(),
                    from_header.maximum_operations_per_instruction(),
                    from_header.line_base(),
                    from_header.line_range(),
                    &*comp_dir.to_slice()?,
                    &*comp_file.path_name().to_slice()?,
                    Some(comp_file_info),
                );

                if from_header.version() <= 4 {
                    // Define the index 0 entries.
                    // A file index of 0 is invalid for version <= 4, but
                    // putting something there makes the indexing easier.
                    dirs.push(DirectoryId(0));
                    files.push(FileId::new(0, from_header.version()));
                }

                for from_dir in from_header.include_directories() {
                    dirs.push(program.add_directory(&*from_dir.to_slice()?));
                }

                for from_file in from_header.file_names() {
                    let from_dir = from_file.directory_index();
                    if from_dir >= dirs.len() as u64 {
                        return Err(ConvertError::InvalidDirectoryIndex);
                    }
                    let from_dir = dirs[from_dir as usize];
                    let from_info = Some(FileInfo {
                        last_modification: from_file.last_modification(),
                        length: from_file.length(),
                    });
                    files.push(program.add_file(
                        &*from_file.path_name().to_slice()?,
                        from_dir,
                        from_info,
                    ));
                }

                program
            };

            // We can't use the `from_program.rows()` because that wouldn't let
            // us preserve address relocations.
            let mut from_row = read::LineRow::new(from_program.header());
            let mut instructions = from_program.header().instructions();
            let mut address = None;
            while let Some(instruction) = instructions.next_instruction(from_program.header())? {
                match instruction {
                    read::LineInstruction::SetAddress(val) => {
                        if program.in_sequence() {
                            return Err(ConvertError::UnsupportedLineInstruction);
                        }
                        match convert_address(val) {
                            Some(val) => address = Some(val),
                            None => return Err(ConvertError::InvalidAddress),
                        }
                        from_row.execute(read::LineInstruction::SetAddress(0), &mut from_program);
                    }
                    read::LineInstruction::DefineFile(_) => {
                        return Err(ConvertError::UnsupportedLineInstruction);
                    }
                    _ => {
                        if from_row.execute(instruction, &mut from_program) {
                            if !program.in_sequence() {
                                program.begin_sequence(address);
                                address = None;
                            }
                            if from_row.end_sequence() {
                                program.end_sequence(from_row.address());
                            } else {
                                program.row().address_offset = from_row.address();
                                program.row().op_index = from_row.op_index();
                                program.row().file = {
                                    let file = from_row.file_index();
                                    if file >= files.len() as u64 {
                                        return Err(ConvertError::InvalidFileIndex);
                                    }
                                    files[file as usize]
                                };
                                program.row().line = from_row.line().unwrap_or(0);
                                program.row().column = match from_row.column() {
                                    read::ColumnType::LeftEdge => 0,
                                    read::ColumnType::Column(val) => val,
                                };
                                program.row().discriminator = from_row.discriminator();
                                program.row().is_statement = from_row.is_stmt();
                                program.row().basic_block = from_row.basic_block();
                                program.row().prologue_end = from_row.prologue_end();
                                program.row().epilogue_begin = from_row.epilogue_begin();
                                program.row().isa = from_row.isa();
                                program.generate_row();
                            }
                            from_row.reset(from_program.header());
                        }
                    }
                };
            }
            Ok((program, files))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use read;
    use write::EndianVec;
    use LittleEndian;

    #[test]
    fn test_line_program_table() {
        let mut programs = LineProgramTable::default();

        let dir1 = &b"dir1"[..];
        let file1 = &b"file1"[..];
        let program1 = LineProgram::new(4, 8, Format::Dwarf32, 4, 2, -5, 14, dir1, file1, None);
        let program_id1 = programs.add(program1);

        let dir2 = &b"dir2"[..];
        let file2 = &b"file2"[..];
        let program2 = LineProgram::new(2, 4, Format::Dwarf64, 1, 1, -3, 12, dir2, file2, None);
        let program_id2 = programs.add(program2);
        {
            let program2 = programs.get_mut(program_id2);
            assert_eq!(dir2, program2.get_directory(program2.default_directory()));

            let dir3 = &b"dir3"[..];
            let dir3_id = program2.add_directory(dir3);
            assert_eq!(dir3, program2.get_directory(dir3_id));
            assert_eq!(dir3_id, program2.add_directory(dir3));

            let file3 = &b"file3"[..];
            let file3_info = FileInfo {
                last_modification: 1,
                length: 2,
            };
            let file3_id = program2.add_file(file3, dir3_id, Some(file3_info));
            assert_eq!((file3, dir3_id), program2.get_file(file3_id));
            assert_eq!(file3_info, *program2.get_file_info(file3_id));

            program2.get_file_info_mut(file3_id).length = 3;
            assert_ne!(file3_info, *program2.get_file_info(file3_id));
            assert_eq!(file3_id, program2.add_file(file3, dir3_id, None));
            assert_ne!(file3_info, *program2.get_file_info(file3_id));
            assert_eq!(
                file3_id,
                program2.add_file(file3, dir3_id, Some(file3_info))
            );
            assert_eq!(file3_info, *program2.get_file_info(file3_id));
        }

        assert_eq!(programs.count(), 2);

        let mut debug_line = DebugLine::from(EndianVec::new(LittleEndian));
        let debug_line_offsets = programs.write(&mut debug_line).unwrap();
        assert_eq!(debug_line_offsets.count(), 2);

        let read_debug_line = read::DebugLine::new(debug_line.slice(), LittleEndian);
        let read_program1 = read_debug_line
            .program(
                debug_line_offsets.get(program_id1),
                8,
                Some(read::EndianSlice::new(dir1, LittleEndian)),
                Some(read::EndianSlice::new(file1, LittleEndian)),
            )
            .unwrap();
        let read_program2 = read_debug_line
            .program(
                debug_line_offsets.get(program_id2),
                4,
                Some(read::EndianSlice::new(dir2, LittleEndian)),
                Some(read::EndianSlice::new(file2, LittleEndian)),
            )
            .unwrap();

        let convert_address = &|address| Some(Address::Absolute(address));
        for (program_id, read_program) in
            vec![(program_id1, read_program1), (program_id2, read_program2)]
        {
            let program = programs.get(program_id);
            let (convert_program, _convert_files) =
                LineProgram::from(read_program, convert_address).unwrap();
            assert_eq!(convert_program.version(), program.version());
            assert_eq!(convert_program.address_size(), program.address_size());
            assert_eq!(convert_program.format(), program.format());
        }
    }

    #[test]
    fn test_line_row() {
        let dir1 = &b"dir1"[..];
        let file1 = &b"file1"[..];
        let file2 = &b"file2"[..];
        let convert_address = &|address| Some(Address::Absolute(address));

        // TODO: version 5
        for &version in &[2, 3, 4] {
            for &address_size in &[4, 8] {
                for &format in &[Format::Dwarf32, Format::Dwarf64] {
                    let line_base = -5;
                    let line_range = 14;
                    let neg_line_base = (-line_base) as u8;
                    let mut program = LineProgram::new(
                        version,
                        address_size,
                        format,
                        1,
                        1,
                        line_base,
                        line_range,
                        dir1,
                        file1,
                        None,
                    );
                    let dir_id = program.default_directory();
                    program.add_file(file1, dir_id, None);
                    let file_id = program.add_file(file2, dir_id, None);

                    // Test sequences.
                    {
                        let mut program = program.clone();
                        let address = Address::Absolute(0x12);
                        program.begin_sequence(Some(address));
                        assert_eq!(
                            program.instructions,
                            vec![LineInstruction::SetAddress(address)]
                        );
                    }

                    {
                        let mut program = program.clone();
                        program.begin_sequence(None);
                        assert_eq!(program.instructions, Vec::new());
                    }

                    {
                        let mut program = program.clone();
                        program.begin_sequence(None);
                        program.end_sequence(0x1234);
                        assert_eq!(
                            program.instructions,
                            vec![
                                LineInstruction::AdvancePc(0x1234),
                                LineInstruction::EndSequence
                            ]
                        );
                    }

                    // Create a base program.
                    program.begin_sequence(None);
                    program.row.line = 0x1000;
                    program.generate_row();
                    let base_row = program.row;
                    let base_instructions = program.instructions.clone();

                    // Create test cases.
                    let mut tests = Vec::new();

                    let mut row = base_row;
                    tests.push((row, vec![LineInstruction::Copy]));

                    let mut row = base_row;
                    row.line -= u64::from(neg_line_base);
                    tests.push((row, vec![LineInstruction::Special(OPCODE_BASE)]));

                    let mut row = base_row;
                    row.line += u64::from(line_range) - 1;
                    row.line -= u64::from(neg_line_base);
                    tests.push((
                        row,
                        vec![LineInstruction::Special(OPCODE_BASE + line_range - 1)],
                    ));

                    let mut row = base_row;
                    row.line += u64::from(line_range);
                    row.line -= u64::from(neg_line_base);
                    tests.push((
                        row,
                        vec![
                            LineInstruction::AdvanceLine(i64::from(line_range - neg_line_base)),
                            LineInstruction::Copy,
                        ],
                    ));

                    let mut row = base_row;
                    row.address_offset = 1;
                    row.line -= u64::from(neg_line_base);
                    tests.push((
                        row,
                        vec![LineInstruction::Special(OPCODE_BASE + line_range)],
                    ));

                    let op_range = (255 - OPCODE_BASE) / line_range;
                    let mut row = base_row;
                    row.address_offset = u64::from(op_range);
                    row.line -= u64::from(neg_line_base);
                    tests.push((
                        row,
                        vec![LineInstruction::Special(
                            OPCODE_BASE + op_range * line_range,
                        )],
                    ));

                    let mut row = base_row;
                    row.address_offset = u64::from(op_range);
                    row.line += u64::from(255 - OPCODE_BASE - op_range * line_range);
                    row.line -= u64::from(neg_line_base);
                    tests.push((row, vec![LineInstruction::Special(255)]));

                    let mut row = base_row;
                    row.address_offset = u64::from(op_range);
                    row.line += u64::from(255 - OPCODE_BASE - op_range * line_range) + 1;
                    row.line -= u64::from(neg_line_base);
                    tests.push((
                        row,
                        vec![LineInstruction::ConstAddPc, LineInstruction::Copy],
                    ));

                    let mut row = base_row;
                    row.address_offset = u64::from(op_range);
                    row.line += u64::from(255 - OPCODE_BASE - op_range * line_range) + 2;
                    row.line -= u64::from(neg_line_base);
                    tests.push((
                        row,
                        vec![
                            LineInstruction::ConstAddPc,
                            LineInstruction::Special(OPCODE_BASE + 6),
                        ],
                    ));

                    let mut row = base_row;
                    row.address_offset = u64::from(op_range) * 2;
                    row.line += u64::from(255 - OPCODE_BASE - op_range * line_range);
                    row.line -= u64::from(neg_line_base);
                    tests.push((
                        row,
                        vec![LineInstruction::ConstAddPc, LineInstruction::Special(255)],
                    ));

                    let mut row = base_row;
                    row.address_offset = u64::from(op_range) * 2;
                    row.line += u64::from(255 - OPCODE_BASE - op_range * line_range) + 1;
                    row.line -= u64::from(neg_line_base);
                    tests.push((
                        row,
                        vec![
                            LineInstruction::AdvancePc(row.address_offset),
                            LineInstruction::Copy,
                        ],
                    ));

                    let mut row = base_row;
                    row.address_offset = u64::from(op_range) * 2;
                    row.line += u64::from(255 - OPCODE_BASE - op_range * line_range) + 2;
                    row.line -= u64::from(neg_line_base);
                    tests.push((
                        row,
                        vec![
                            LineInstruction::AdvancePc(row.address_offset),
                            LineInstruction::Special(OPCODE_BASE + 6),
                        ],
                    ));

                    let mut row = base_row;
                    row.address_offset = 0x1234;
                    tests.push((
                        row,
                        vec![LineInstruction::AdvancePc(0x1234), LineInstruction::Copy],
                    ));

                    let mut row = base_row;
                    row.line += 0x1234;
                    tests.push((
                        row,
                        vec![LineInstruction::AdvanceLine(0x1234), LineInstruction::Copy],
                    ));

                    let mut row = base_row;
                    row.file = file_id;
                    tests.push((
                        row,
                        vec![LineInstruction::SetFile(file_id), LineInstruction::Copy],
                    ));

                    let mut row = base_row;
                    row.column = 0x1234;
                    tests.push((
                        row,
                        vec![LineInstruction::SetColumn(0x1234), LineInstruction::Copy],
                    ));

                    let mut row = base_row;
                    row.discriminator = 0x1234;
                    tests.push((
                        row,
                        vec![
                            LineInstruction::SetDiscriminator(0x1234),
                            LineInstruction::Copy,
                        ],
                    ));

                    let mut row = base_row;
                    row.is_statement = !row.is_statement;
                    tests.push((
                        row,
                        vec![LineInstruction::NegateStatement, LineInstruction::Copy],
                    ));

                    let mut row = base_row;
                    row.basic_block = true;
                    tests.push((
                        row,
                        vec![LineInstruction::SetBasicBlock, LineInstruction::Copy],
                    ));

                    let mut row = base_row;
                    row.prologue_end = true;
                    tests.push((
                        row,
                        vec![LineInstruction::SetPrologueEnd, LineInstruction::Copy],
                    ));

                    let mut row = base_row;
                    row.epilogue_begin = true;
                    tests.push((
                        row,
                        vec![LineInstruction::SetEpilogueBegin, LineInstruction::Copy],
                    ));

                    let mut row = base_row;
                    row.isa = 0x1234;
                    tests.push((
                        row,
                        vec![LineInstruction::SetIsa(0x1234), LineInstruction::Copy],
                    ));

                    for test in tests {
                        // Test generate_row().
                        let mut program = program.clone();
                        program.row = test.0;
                        program.generate_row();
                        assert_eq!(
                            &program.instructions[base_instructions.len()..],
                            &test.1[..]
                        );

                        // Test LineProgram::from().
                        let mut programs = LineProgramTable::default();
                        let program_id = programs.add(program);

                        let mut debug_line = DebugLine::from(EndianVec::new(LittleEndian));
                        let debug_line_offsets = programs.write(&mut debug_line).unwrap();

                        let read_debug_line =
                            read::DebugLine::new(debug_line.slice(), LittleEndian);
                        let read_program = read_debug_line
                            .program(
                                debug_line_offsets.get(program_id),
                                address_size,
                                Some(read::EndianSlice::new(dir1, LittleEndian)),
                                Some(read::EndianSlice::new(file1, LittleEndian)),
                            )
                            .unwrap();

                        let (convert_program, _convert_files) =
                            LineProgram::from(read_program, convert_address).unwrap();
                        assert_eq!(
                            &convert_program.instructions[base_instructions.len()..],
                            &test.1[..]
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn test_line_instruction() {
        let dir1 = &b"dir1"[..];
        let file1 = &b"file1"[..];

        // TODO: version 5
        for &version in &[2, 3, 4] {
            for &address_size in &[4, 8] {
                for &format in &[Format::Dwarf32, Format::Dwarf64] {
                    let mut program = LineProgram::new(
                        version,
                        address_size,
                        format,
                        1,
                        1,
                        -5,
                        14,
                        dir1,
                        file1,
                        None,
                    );
                    let dir_id = program.default_directory();
                    let file_id = program.add_file(file1, dir_id, None);

                    for &(ref inst, ref expect_inst) in &[
                        (
                            LineInstruction::Special(OPCODE_BASE),
                            read::LineInstruction::Special(OPCODE_BASE),
                        ),
                        (
                            LineInstruction::Special(255),
                            read::LineInstruction::Special(255),
                        ),
                        (LineInstruction::Copy, read::LineInstruction::Copy),
                        (
                            LineInstruction::AdvancePc(0x12),
                            read::LineInstruction::AdvancePc(0x12),
                        ),
                        (
                            LineInstruction::AdvanceLine(0x12),
                            read::LineInstruction::AdvanceLine(0x12),
                        ),
                        (
                            LineInstruction::SetFile(file_id),
                            read::LineInstruction::SetFile(file_id.raw()),
                        ),
                        (
                            LineInstruction::SetColumn(0x12),
                            read::LineInstruction::SetColumn(0x12),
                        ),
                        (
                            LineInstruction::NegateStatement,
                            read::LineInstruction::NegateStatement,
                        ),
                        (
                            LineInstruction::SetBasicBlock,
                            read::LineInstruction::SetBasicBlock,
                        ),
                        (
                            LineInstruction::ConstAddPc,
                            read::LineInstruction::ConstAddPc,
                        ),
                        (
                            LineInstruction::SetPrologueEnd,
                            read::LineInstruction::SetPrologueEnd,
                        ),
                        (
                            LineInstruction::SetEpilogueBegin,
                            read::LineInstruction::SetEpilogueBegin,
                        ),
                        (
                            LineInstruction::SetIsa(0x12),
                            read::LineInstruction::SetIsa(0x12),
                        ),
                        (
                            LineInstruction::EndSequence,
                            read::LineInstruction::EndSequence,
                        ),
                        (
                            LineInstruction::SetAddress(Address::Absolute(0x12)),
                            read::LineInstruction::SetAddress(0x12),
                        ),
                        (
                            LineInstruction::SetDiscriminator(0x12),
                            read::LineInstruction::SetDiscriminator(0x12),
                        ),
                    ][..]
                    {
                        let mut programs = LineProgramTable::default();
                        let mut program = program.clone();
                        program.instructions.push(*inst);
                        let program_id = programs.add(program);

                        let mut debug_line = DebugLine::from(EndianVec::new(LittleEndian));
                        let debug_line_offsets = programs.write(&mut debug_line).unwrap();

                        let read_debug_line =
                            read::DebugLine::new(debug_line.slice(), LittleEndian);
                        let read_program = read_debug_line
                            .program(
                                debug_line_offsets.get(program_id),
                                address_size,
                                Some(read::EndianSlice::new(dir1, LittleEndian)),
                                Some(read::EndianSlice::new(file1, LittleEndian)),
                            )
                            .unwrap();
                        let read_header = read_program.header();
                        let mut read_insts = read_header.instructions();
                        assert_eq!(
                            *expect_inst,
                            read_insts.next_instruction(read_header).unwrap().unwrap()
                        );
                        assert_eq!(None, read_insts.next_instruction(read_header).unwrap());
                    }
                }
            }
        }
    }

    // Test that the address/line advance is correct. We don't test for optimality.
    #[test]
    #[allow(clippy::useless_vec)]
    fn test_advance() {
        let dir1 = &b"dir1"[..];
        let file1 = &b"file1"[..];

        let addresses = 0..50;
        let lines = -10..25i64;

        for minimum_instruction_length in vec![1, 4] {
            for maximum_operations_per_instruction in vec![1, 3] {
                for line_base in vec![-5, 0] {
                    for line_range in vec![10, 20] {
                        let mut program = LineProgram::new(
                            4,
                            8,
                            Format::Dwarf32,
                            minimum_instruction_length,
                            maximum_operations_per_instruction,
                            line_base,
                            line_range,
                            dir1,
                            file1,
                            None,
                        );
                        for address_advance in addresses.clone() {
                            program.begin_sequence(Some(Address::Absolute(0x1000)));
                            program.row().line = 0x10000;
                            program.generate_row();
                            for line_advance in lines.clone() {
                                {
                                    let row = program.row();
                                    row.address_offset +=
                                        address_advance * u64::from(minimum_instruction_length);
                                    row.line = row.line.wrapping_add(line_advance as u64);
                                }
                                program.generate_row();
                            }
                            let address_offset = program.row().address_offset
                                + u64::from(minimum_instruction_length);
                            program.end_sequence(address_offset);
                        }

                        let mut programs = LineProgramTable::default();
                        let program_id = programs.add(program);
                        let mut debug_line = DebugLine::from(EndianVec::new(LittleEndian));
                        let debug_line_offsets = programs.write(&mut debug_line).unwrap();

                        let read_debug_line =
                            read::DebugLine::new(debug_line.slice(), LittleEndian);
                        let read_program = read_debug_line
                            .program(
                                debug_line_offsets.get(program_id),
                                8,
                                Some(read::EndianSlice::new(dir1, LittleEndian)),
                                Some(read::EndianSlice::new(file1, LittleEndian)),
                            )
                            .unwrap();

                        let mut rows = read_program.rows();
                        for address_advance in addresses.clone() {
                            let mut address;
                            let mut line;
                            {
                                let row = rows.next_row().unwrap().unwrap().1;
                                address = row.address();
                                line = row.line().unwrap();
                            }
                            assert_eq!(address, 0x1000);
                            assert_eq!(line, 0x10000);
                            for line_advance in lines.clone() {
                                let row = rows.next_row().unwrap().unwrap().1;
                                assert_eq!(
                                    row.address() - address,
                                    address_advance * u64::from(minimum_instruction_length)
                                );
                                assert_eq!(
                                    (row.line().unwrap() as i64) - (line as i64),
                                    line_advance
                                );
                                address = row.address();
                                line = row.line().unwrap();
                            }
                            let row = rows.next_row().unwrap().unwrap().1;
                            assert!(row.end_sequence());
                        }
                    }
                }
            }
        }
    }
}
