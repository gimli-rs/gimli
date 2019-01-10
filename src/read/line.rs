use std::fmt;
use std::result;
use vec::Vec;

use common::{DebugLineOffset, Format};
use constants;
use endianity::Endianity;
use read::{EndianSlice, Error, Reader, ReaderOffset, Result, Section};

/// The `DebugLine` struct contains the source location to instruction mapping
/// found in the `.debug_line` section.
#[derive(Debug, Default, Clone, Copy)]
pub struct DebugLine<R: Reader> {
    debug_line_section: R,
}

impl<'input, Endian> DebugLine<EndianSlice<'input, Endian>>
where
    Endian: Endianity,
{
    /// Construct a new `DebugLine` instance from the data in the `.debug_line`
    /// section.
    ///
    /// It is the caller's responsibility to read the `.debug_line` section and
    /// present it as a `&[u8]` slice. That means using some ELF loader on
    /// Linux, a Mach-O loader on OSX, etc.
    ///
    /// ```
    /// use gimli::{DebugLine, LittleEndian};
    ///
    /// # let buf = [0x00, 0x01, 0x02, 0x03];
    /// # let read_debug_line_section_somehow = || &buf;
    /// let debug_line = DebugLine::new(read_debug_line_section_somehow(), LittleEndian);
    /// ```
    pub fn new(debug_line_section: &'input [u8], endian: Endian) -> Self {
        Self::from(EndianSlice::new(debug_line_section, endian))
    }
}

impl<R: Reader> DebugLine<R> {
    /// Parse the line number program whose header is at the given `offset` in the
    /// `.debug_line` section.
    ///
    /// The `address_size` must match the compilation unit that the lines apply to.
    /// The `comp_dir` should be from the `DW_AT_comp_dir` attribute of the compilation
    /// unit. The `comp_name` should be from the `DW_AT_name` attribute of the
    /// compilation unit.
    ///
    /// ```rust,no_run
    /// use gimli::{DebugLine, DebugLineOffset, IncompleteLineNumberProgram, EndianSlice, LittleEndian};
    ///
    /// # let buf = [];
    /// # let read_debug_line_section_somehow = || &buf;
    /// let debug_line = DebugLine::new(read_debug_line_section_somehow(), LittleEndian);
    ///
    /// // In a real example, we'd grab the offset via a compilation unit
    /// // entry's `DW_AT_stmt_list` attribute, and the address size from that
    /// // unit directly.
    /// let offset = DebugLineOffset(0);
    /// let address_size = 8;
    ///
    /// let program = debug_line.program(offset, address_size, None, None)
    ///     .expect("should have found a header at that offset, and parsed it OK");
    /// ```
    pub fn program(
        &self,
        offset: DebugLineOffset<R::Offset>,
        address_size: u8,
        comp_dir: Option<R>,
        comp_name: Option<R>,
    ) -> Result<IncompleteLineNumberProgram<R, R::Offset>> {
        let input = &mut self.debug_line_section.clone();
        input.skip(offset.0)?;
        let header =
            LineNumberProgramHeader::parse(input, offset, address_size, comp_dir, comp_name)?;
        let program = IncompleteLineNumberProgram { header };
        Ok(program)
    }
}

impl<R: Reader> Section<R> for DebugLine<R> {
    fn section_name() -> &'static str {
        ".debug_line"
    }
}

impl<R: Reader> From<R> for DebugLine<R> {
    fn from(debug_line_section: R) -> Self {
        DebugLine { debug_line_section }
    }
}

/// A `LineNumberProgram` provides access to a `LineNumberProgramHeader` and
/// a way to add files to the files table if necessary. Gimli consumers should
/// never need to use or see this trait.
pub trait LineNumberProgram<R, Offset = usize>
where
    R: Reader<Offset = Offset>,
    Offset: ReaderOffset,
{
    /// Get a reference to the held `LineNumberProgramHeader`.
    fn header(&self) -> &LineNumberProgramHeader<R, Offset>;
    /// Add a file to the file table if necessary.
    fn add_file(&mut self, file: FileEntry<R>);
}

impl<R, Offset> LineNumberProgram<R, Offset> for IncompleteLineNumberProgram<R, Offset>
where
    R: Reader<Offset = Offset>,
    Offset: ReaderOffset,
{
    fn header(&self) -> &LineNumberProgramHeader<R, Offset> {
        &self.header
    }
    fn add_file(&mut self, file: FileEntry<R>) {
        self.header.file_names.push(file);
    }
}

impl<'program, R, Offset> LineNumberProgram<R, Offset>
    for &'program CompleteLineNumberProgram<R, Offset>
where
    R: Reader<Offset = Offset>,
    Offset: ReaderOffset,
{
    fn header(&self) -> &LineNumberProgramHeader<R, Offset> {
        &self.header
    }
    fn add_file(&mut self, _: FileEntry<R>) {
        // Nop. Our file table is already complete.
    }
}

/// Executes a `LineNumberProgram` to recreate the matrix mapping to and from
/// instructions to source locations.
///
/// "The hypothetical machine used by a consumer of the line number information
/// to expand the byte-coded instruction stream into a matrix of line number
/// information." -- Section 6.2.1
#[derive(Debug, Clone)]
pub struct StateMachine<R, Program, Offset = usize>
where
    Program: LineNumberProgram<R, Offset>,
    R: Reader<Offset = Offset>,
    Offset: ReaderOffset,
{
    program: Program,
    row: LineNumberRow,
    opcodes: OpcodesIter<R>,
}

type OneShotStateMachine<R, Offset = usize> =
    StateMachine<R, IncompleteLineNumberProgram<R, Offset>, Offset>;

type ResumedStateMachine<'program, R, Offset = usize> =
    StateMachine<R, &'program CompleteLineNumberProgram<R, Offset>, Offset>;

impl<R, Program, Offset> StateMachine<R, Program, Offset>
where
    Program: LineNumberProgram<R, Offset>,
    R: Reader<Offset = Offset>,
    Offset: ReaderOffset,
{
    #[allow(clippy::new_ret_no_self)]
    fn new(program: IncompleteLineNumberProgram<R, Offset>) -> OneShotStateMachine<R, Offset> {
        let row = LineNumberRow::new(&program);
        let opcodes = OpcodesIter {
            input: program.header().program_buf.clone(),
        };
        StateMachine {
            program,
            row,
            opcodes,
        }
    }

    fn resume<'program>(
        program: &'program CompleteLineNumberProgram<R, Offset>,
        sequence: &LineNumberSequence<R>,
    ) -> ResumedStateMachine<'program, R, Offset> {
        let row = LineNumberRow::new(&program);
        let opcodes = sequence.opcodes.clone();
        StateMachine {
            program,
            row,
            opcodes,
        }
    }

    /// Get a reference to the header for this state machine's line number
    /// program.
    pub fn header(&self) -> &LineNumberProgramHeader<R, Offset> {
        self.program.header()
    }

    /// Parse and execute the next opcodes in the line number program until
    /// another row in the line number matrix is computed.
    ///
    /// The freshly computed row is returned as `Ok(Some((header, row)))`.
    /// If the matrix is complete, and there are no more new rows in the line
    /// number matrix, then `Ok(None)` is returned. If there was an error parsing
    /// an opcode, then `Err(e)` is returned.
    ///
    /// Unfortunately, the references mean that this cannot be a
    /// `FallibleIterator`.
    pub fn next_row(
        &mut self,
    ) -> Result<Option<(&LineNumberProgramHeader<R, Offset>, &LineNumberRow)>> {
        // Perform any reset that was required after copying the previous row.
        self.row.reset(&self.program);

        loop {
            // Split the borrow here, rather than calling `self.header()`.
            match self.opcodes.next_opcode(self.program.header()) {
                Err(err) => return Err(err),
                Ok(None) => return Ok(None),
                Ok(Some(opcode)) => {
                    if self.row.execute(opcode, &mut self.program) {
                        return Ok(Some((self.header(), &self.row)));
                    }
                    // Fall through, parse the next opcode, and see if that
                    // yields a row.
                }
            }
        }
    }

    /// Parse and execute opcodes until we reach a row matching `addr`, the end of the program,
    /// or an error.
    pub fn run_to_address(
        &mut self,
        addr: u64,
    ) -> Result<Option<(&LineNumberProgramHeader<R, Offset>, &LineNumberRow)>> {
        loop {
            match self.next_row() {
                Ok(Some((_, row))) => {
                    if row.address() == addr {
                        // Can't return 'row' directly here because of rust-lang/rust#21906.
                        break;
                    }
                }
                Ok(None) => return Ok(None),
                Err(err) => return Err(err),
            }
        }

        Ok(Some((self.header(), &self.row)))
    }
}

/// A parsed line number program opcode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Opcode<R: Reader> {
    /// > ### 6.2.5.1 Special Opcodes
    /// >
    /// > Each ubyte special opcode has the following effect on the state machine:
    /// >
    /// >   1. Add a signed integer to the line register.
    /// >
    /// >   2. Modify the operation pointer by incrementing the address and
    /// >   op_index registers as described below.
    /// >
    /// >   3. Append a row to the matrix using the current values of the state
    /// >   machine registers.
    /// >
    /// >   4. Set the basic_block register to “false.”
    /// >
    /// >   5. Set the prologue_end register to “false.”
    /// >
    /// >   6. Set the epilogue_begin register to “false.”
    /// >
    /// >   7. Set the discriminator register to 0.
    /// >
    /// > All of the special opcodes do those same seven things; they differ from
    /// > one another only in what values they add to the line, address and
    /// > op_index registers.
    Special(u8),

    /// "[`Opcode::Copy`] appends a row to the matrix using the current values of the state
    /// machine registers. Then it sets the discriminator register to 0, and
    /// sets the basic_block, prologue_end and epilogue_begin registers to
    /// “false.”"
    Copy,

    /// "The DW_LNS_advance_pc opcode takes a single unsigned LEB128 operand as
    /// the operation advance and modifies the address and op_index registers
    /// [the same as `Opcode::Special`]"
    AdvancePc(u64),

    /// "The DW_LNS_advance_line opcode takes a single signed LEB128 operand and
    /// adds that value to the line register of the state machine."
    AdvanceLine(i64),

    /// "The DW_LNS_set_file opcode takes a single unsigned LEB128 operand and
    /// stores it in the file register of the state machine."
    SetFile(u64),

    /// "The DW_LNS_set_column opcode takes a single unsigned LEB128 operand and
    /// stores it in the column register of the state machine."
    SetColumn(u64),

    /// "The DW_LNS_negate_stmt opcode takes no operands. It sets the is_stmt
    /// register of the state machine to the logical negation of its current
    /// value."
    NegateStatement,

    /// "The DW_LNS_set_basic_block opcode takes no operands. It sets the
    /// basic_block register of the state machine to “true.”"
    SetBasicBlock,

    /// > The DW_LNS_const_add_pc opcode takes no operands. It advances the
    /// > address and op_index registers by the increments corresponding to
    /// > special opcode 255.
    /// >
    /// > When the line number program needs to advance the address by a small
    /// > amount, it can use a single special opcode, which occupies a single
    /// > byte. When it needs to advance the address by up to twice the range of
    /// > the last special opcode, it can use DW_LNS_const_add_pc followed by a
    /// > special opcode, for a total of two bytes. Only if it needs to advance
    /// > the address by more than twice that range will it need to use both
    /// > DW_LNS_advance_pc and a special opcode, requiring three or more bytes.
    ConstAddPc,

    /// > The DW_LNS_fixed_advance_pc opcode takes a single uhalf (unencoded)
    /// > operand and adds it to the address register of the state machine and
    /// > sets the op_index register to 0. This is the only standard opcode whose
    /// > operand is not a variable length number. It also does not multiply the
    /// > operand by the minimum_instruction_length field of the header.
    FixedAddPc(u16),

    /// "[`Opcode::SetPrologueEnd`] sets the prologue_end register to “true”."
    SetPrologueEnd,

    /// "[`Opcode::SetEpilogueBegin`] sets the epilogue_begin register to
    /// “true”."
    SetEpilogueBegin,

    /// "The DW_LNS_set_isa opcode takes a single unsigned LEB128 operand and
    /// stores that value in the isa register of the state machine."
    SetIsa(u64),

    /// An unknown standard opcode with zero operands.
    UnknownStandard0(constants::DwLns),

    /// An unknown standard opcode with one operand.
    UnknownStandard1(constants::DwLns, u64),

    /// An unknown standard opcode with multiple operands.
    UnknownStandardN(constants::DwLns, R),

    /// > [`Opcode::EndSequence`] sets the end_sequence register of the state
    /// > machine to “true” and appends a row to the matrix using the current
    /// > values of the state-machine registers. Then it resets the registers to
    /// > the initial values specified above (see Section 6.2.2). Every line
    /// > number program sequence must end with a DW_LNE_end_sequence instruction
    /// > which creates a row whose address is that of the byte after the last
    /// > target machine instruction of the sequence.
    EndSequence,

    /// > The DW_LNE_set_address opcode takes a single relocatable address as an
    /// > operand. The size of the operand is the size of an address on the target
    /// > machine. It sets the address register to the value given by the
    /// > relocatable address and sets the op_index register to 0.
    /// >
    /// > All of the other line number program opcodes that affect the address
    /// > register add a delta to it. This instruction stores a relocatable value
    /// > into it instead.
    SetAddress(u64),

    /// Defines a new source file in the line number program and appends it to
    /// the line number program header's list of source files.
    DefineFile(FileEntry<R>),

    /// "The DW_LNE_set_discriminator opcode takes a single parameter, an
    /// unsigned LEB128 integer. It sets the discriminator register to the new
    /// value."
    SetDiscriminator(u64),

    /// An unknown extended opcode and the slice of its unparsed operands.
    UnknownExtended(constants::DwLne, R),
}

impl<R: Reader> Opcode<R> {
    fn parse<'header>(
        header: &'header LineNumberProgramHeader<R, R::Offset>,
        input: &mut R,
    ) -> Result<Opcode<R>>
    where
        R: 'header,
    {
        let opcode = input.read_u8()?;
        if opcode == 0 {
            let length = input.read_uleb128().and_then(R::Offset::from_u64)?;
            let mut instr_rest = input.split(length)?;
            let opcode = instr_rest.read_u8()?;

            match constants::DwLne(opcode) {
                constants::DW_LNE_end_sequence => Ok(Opcode::EndSequence),

                constants::DW_LNE_set_address => {
                    let address = instr_rest.read_address(header.address_size)?;
                    Ok(Opcode::SetAddress(address))
                }

                constants::DW_LNE_define_file => {
                    let path_name = instr_rest.read_null_terminated_slice()?;
                    let entry = FileEntry::parse(&mut instr_rest, path_name)?;
                    Ok(Opcode::DefineFile(entry))
                }

                constants::DW_LNE_set_discriminator => {
                    let discriminator = instr_rest.read_uleb128()?;
                    Ok(Opcode::SetDiscriminator(discriminator))
                }

                otherwise => Ok(Opcode::UnknownExtended(otherwise, instr_rest)),
            }
        } else if opcode >= header.opcode_base {
            Ok(Opcode::Special(opcode))
        } else {
            match constants::DwLns(opcode) {
                constants::DW_LNS_copy => Ok(Opcode::Copy),

                constants::DW_LNS_advance_pc => {
                    let advance = input.read_uleb128()?;
                    Ok(Opcode::AdvancePc(advance))
                }

                constants::DW_LNS_advance_line => {
                    let increment = input.read_sleb128()?;
                    Ok(Opcode::AdvanceLine(increment))
                }

                constants::DW_LNS_set_file => {
                    let file = input.read_uleb128()?;
                    Ok(Opcode::SetFile(file))
                }

                constants::DW_LNS_set_column => {
                    let column = input.read_uleb128()?;
                    Ok(Opcode::SetColumn(column))
                }

                constants::DW_LNS_negate_stmt => Ok(Opcode::NegateStatement),

                constants::DW_LNS_set_basic_block => Ok(Opcode::SetBasicBlock),

                constants::DW_LNS_const_add_pc => Ok(Opcode::ConstAddPc),

                constants::DW_LNS_fixed_advance_pc => {
                    let advance = input.read_u16()?;
                    Ok(Opcode::FixedAddPc(advance))
                }

                constants::DW_LNS_set_prologue_end => Ok(Opcode::SetPrologueEnd),

                constants::DW_LNS_set_epilogue_begin => Ok(Opcode::SetEpilogueBegin),

                constants::DW_LNS_set_isa => {
                    let isa = input.read_uleb128()?;
                    Ok(Opcode::SetIsa(isa))
                }

                otherwise => {
                    let mut opcode_lengths = header.standard_opcode_lengths().clone();
                    opcode_lengths.skip(R::Offset::from_u8(opcode - 1))?;
                    let num_args = opcode_lengths.read_u8()? as usize;
                    match num_args {
                        0 => Ok(Opcode::UnknownStandard0(otherwise)),
                        1 => {
                            let arg = input.read_uleb128()?;
                            Ok(Opcode::UnknownStandard1(otherwise, arg))
                        }
                        _ => {
                            let mut args = input.clone();
                            for _ in 0..num_args {
                                input.read_uleb128()?;
                            }
                            let len = input.offset_from(&args);
                            args.truncate(len)?;
                            Ok(Opcode::UnknownStandardN(otherwise, args))
                        }
                    }
                }
            }
        }
    }
}

impl<R: Reader> fmt::Display for Opcode<R> {
    fn fmt(&self, f: &mut fmt::Formatter) -> result::Result<(), fmt::Error> {
        match *self {
            Opcode::Special(opcode) => write!(f, "Special opcode {}", opcode),
            Opcode::Copy => write!(f, "{}", constants::DW_LNS_copy),
            Opcode::AdvancePc(advance) => {
                write!(f, "{} by {}", constants::DW_LNS_advance_pc, advance)
            }
            Opcode::AdvanceLine(increment) => {
                write!(f, "{} by {}", constants::DW_LNS_advance_line, increment)
            }
            Opcode::SetFile(file) => write!(f, "{} to {}", constants::DW_LNS_set_file, file),
            Opcode::SetColumn(column) => {
                write!(f, "{} to {}", constants::DW_LNS_set_column, column)
            }
            Opcode::NegateStatement => write!(f, "{}", constants::DW_LNS_negate_stmt),
            Opcode::SetBasicBlock => write!(f, "{}", constants::DW_LNS_set_basic_block),
            Opcode::ConstAddPc => write!(f, "{}", constants::DW_LNS_const_add_pc),
            Opcode::FixedAddPc(advance) => {
                write!(f, "{} by {}", constants::DW_LNS_fixed_advance_pc, advance)
            }
            Opcode::SetPrologueEnd => write!(f, "{}", constants::DW_LNS_set_prologue_end),
            Opcode::SetEpilogueBegin => write!(f, "{}", constants::DW_LNS_set_epilogue_begin),
            Opcode::SetIsa(isa) => write!(f, "{} to {}", constants::DW_LNS_set_isa, isa),
            Opcode::UnknownStandard0(opcode) => write!(f, "Unknown {}", opcode),
            Opcode::UnknownStandard1(opcode, arg) => {
                write!(f, "Unknown {} with operand {}", opcode, arg)
            }
            Opcode::UnknownStandardN(opcode, ref args) => {
                write!(f, "Unknown {} with operands {:?}", opcode, args)
            }
            Opcode::EndSequence => write!(f, "{}", constants::DW_LNE_end_sequence),
            Opcode::SetAddress(address) => {
                write!(f, "{} to {}", constants::DW_LNE_set_address, address)
            }
            Opcode::DefineFile(_) => write!(f, "{}", constants::DW_LNE_define_file),
            Opcode::SetDiscriminator(discr) => {
                write!(f, "{} to {}", constants::DW_LNE_set_discriminator, discr)
            }
            Opcode::UnknownExtended(opcode, _) => write!(f, "Unknown {}", opcode),
        }
    }
}

/// An iterator yielding parsed opcodes.
///
/// See
/// [`LineNumberProgramHeader::opcodes`](./struct.LineNumberProgramHeader.html#method.opcodes)
/// for more details.
#[derive(Clone, Debug)]
pub struct OpcodesIter<R: Reader> {
    input: R,
}

impl<R: Reader> OpcodesIter<R> {
    fn remove_trailing(&self, other: &OpcodesIter<R>) -> Result<OpcodesIter<R>> {
        let offset = other.input.offset_from(&self.input);
        let mut input = self.input.clone();
        input.truncate(offset)?;
        Ok(OpcodesIter { input })
    }
}

impl<R: Reader> OpcodesIter<R> {
    /// Advance the iterator and return the next opcode.
    ///
    /// Returns the newly parsed opcode as `Ok(Some(opcode))`. Returns
    /// `Ok(None)` when iteration is complete and all opcodes have already been
    /// parsed and yielded. If an error occurs while parsing the next attribute,
    /// then this error is returned as `Err(e)`, and all subsequent calls return
    /// `Ok(None)`.
    ///
    /// Unfortunately, the `header` parameter means that this cannot be a
    /// `FallibleIterator`.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    pub fn next_opcode(
        &mut self,
        header: &LineNumberProgramHeader<R, R::Offset>,
    ) -> Result<Option<Opcode<R>>> {
        if self.input.is_empty() {
            return Ok(None);
        }

        match Opcode::parse(header, &mut self.input) {
            Ok(opcode) => Ok(Some(opcode)),
            Err(e) => {
                self.input.empty();
                Err(e)
            }
        }
    }
}

/// A row in the line number program's resulting matrix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LineNumberRow {
    registers: StateMachineRegisters,
}

impl LineNumberRow {
    /// Create a line number row in the initial state for the given program.
    pub fn new<R, Program>(program: &Program) -> Self
    where
        Program: LineNumberProgram<R, R::Offset>,
        R: Reader,
    {
        let default_is_stmt = program.header().default_is_stmt;
        LineNumberRow {
            registers: StateMachineRegisters::new(default_is_stmt),
        }
    }

    /// "The program-counter value corresponding to a machine instruction
    /// generated by the compiler."
    #[inline]
    pub fn address(&self) -> u64 {
        self.registers.address
    }

    /// > An unsigned integer representing the index of an operation within a VLIW
    /// > instruction. The index of the first operation is 0. For non-VLIW
    /// > architectures, this register will always be 0.
    /// >
    /// > The address and op_index registers, taken together, form an operation
    /// > pointer that can reference any individual operation with the
    /// > instruction stream.
    #[inline]
    pub fn op_index(&self) -> u64 {
        self.registers.op_index
    }

    /// "An unsigned integer indicating the identity of the source file
    /// corresponding to a machine instruction."
    #[inline]
    pub fn file_index(&self) -> u64 {
        self.registers.file
    }

    /// The source file corresponding to the current machine instruction.
    #[inline]
    pub fn file<'header, R: Reader>(
        &self,
        header: &'header LineNumberProgramHeader<R, R::Offset>,
    ) -> Option<&'header FileEntry<R>> {
        header.file(self.registers.file)
    }

    /// "An unsigned integer indicating a source line number. Lines are numbered
    /// beginning at 1. The compiler may emit the value 0 in cases where an
    /// instruction cannot be attributed to any source line."
    #[inline]
    pub fn line(&self) -> Option<u64> {
        if self.registers.line == 0 {
            None
        } else {
            Some(self.registers.line)
        }
    }

    /// "An unsigned integer indicating a column number within a source
    /// line. Columns are numbered beginning at 1. The value 0 is reserved to
    /// indicate that a statement begins at the “left edge” of the line."
    #[inline]
    pub fn column(&self) -> ColumnType {
        if self.registers.column == 0 {
            ColumnType::LeftEdge
        } else {
            ColumnType::Column(self.registers.column)
        }
    }

    /// "A boolean indicating that the current instruction is a recommended
    /// breakpoint location. A recommended breakpoint location is intended to
    /// “represent” a line, a statement and/or a semantically distinct subpart
    /// of a statement."
    #[inline]
    pub fn is_stmt(&self) -> bool {
        self.registers.is_stmt
    }

    /// "A boolean indicating that the current instruction is the beginning of a
    /// basic block."
    #[inline]
    pub fn basic_block(&self) -> bool {
        self.registers.basic_block
    }

    /// "A boolean indicating that the current address is that of the first byte
    /// after the end of a sequence of target machine instructions. end_sequence
    /// terminates a sequence of lines; therefore other information in the same
    /// row is not meaningful."
    #[inline]
    pub fn end_sequence(&self) -> bool {
        self.registers.end_sequence
    }

    /// "A boolean indicating that the current address is one (of possibly many)
    /// where execution should be suspended for an entry breakpoint of a
    /// function."
    #[inline]
    pub fn prologue_end(&self) -> bool {
        self.registers.prologue_end
    }

    /// "A boolean indicating that the current address is one (of possibly many)
    /// where execution should be suspended for an exit breakpoint of a
    /// function."
    #[inline]
    pub fn epilogue_begin(&self) -> bool {
        self.registers.epilogue_begin
    }

    /// Tag for the current instruction set architecture.
    ///
    /// > An unsigned integer whose value encodes the applicable instruction set
    /// > architecture for the current instruction.
    /// >
    /// > The encoding of instruction sets should be shared by all users of a
    /// > given architecture. It is recommended that this encoding be defined by
    /// > the ABI authoring committee for each architecture.
    #[inline]
    pub fn isa(&self) -> u64 {
        self.registers.isa
    }

    /// "An unsigned integer identifying the block to which the current
    /// instruction belongs. Discriminator values are assigned arbitrarily by
    /// the DWARF producer and serve to distinguish among multiple blocks that
    /// may all be associated with the same source file, line, and column. Where
    /// only one block exists for a given source position, the discriminator
    /// value should be zero."
    #[inline]
    pub fn discriminator(&self) -> u64 {
        self.registers.discriminator
    }

    /// Execute the given opcode, and return true if a new row in the
    /// line number matrix needs to be generated.
    ///
    /// Unknown opcodes are treated as no-ops.
    #[inline]
    pub fn execute<R, Program>(&mut self, opcode: Opcode<R>, program: &mut Program) -> bool
    where
        Program: LineNumberProgram<R, R::Offset>,
        R: Reader,
    {
        self.registers.execute(opcode, program)
    }

    /// Perform any reset that was required after copying the previous row.
    #[inline]
    pub fn reset<R, Program>(&mut self, program: &Program)
    where
        Program: LineNumberProgram<R, R::Offset>,
        R: Reader,
    {
        self.registers.reset(program.header().default_is_stmt);
    }
}

/// The type of column that a row is referring to.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ColumnType {
    /// The `LeftEdge` means that the statement begins at the start of the new
    /// line.
    LeftEdge,
    /// A column number, whose range begins at 1.
    Column(u64),
}

/// The registers for a state machine, as defined in section 6.2.2.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct StateMachineRegisters {
    address: u64,
    op_index: u64,
    file: u64,
    line: u64,
    column: u64,
    is_stmt: bool,
    basic_block: bool,
    end_sequence: bool,
    prologue_end: bool,
    epilogue_begin: bool,
    isa: u64,
    discriminator: u64,
}

impl StateMachineRegisters {
    fn new(default_is_stmt: bool) -> Self {
        StateMachineRegisters {
            // "At the beginning of each sequence within a line number program, the
            // state of the registers is:" -- Section 6.2.2
            address: 0,
            op_index: 0,
            file: 1,
            line: 1,
            column: 0,
            // "determined by default_is_stmt in the line number program header"
            is_stmt: default_is_stmt,
            basic_block: false,
            end_sequence: false,
            prologue_end: false,
            epilogue_begin: false,
            // "The isa value 0 specifies that the instruction set is the
            // architecturally determined default instruction set. This may be fixed
            // by the ABI, or it may be specified by other means, for example, by
            // the object file description."
            isa: 0,
            discriminator: 0,
        }
    }

    /// Step 1 of section 6.2.5.1
    fn apply_line_advance(&mut self, line_increment: i64) {
        if line_increment < 0 {
            let decrement = -line_increment as u64;
            if decrement <= self.line {
                self.line -= decrement;
            } else {
                self.line = 0;
            }
        } else {
            self.line += line_increment as u64;
        }
    }

    /// Step 2 of section 6.2.5.1
    fn apply_operation_advance<R: Reader>(
        &mut self,
        operation_advance: u64,
        header: &LineNumberProgramHeader<R, R::Offset>,
    ) {
        let minimum_instruction_length = u64::from(header.minimum_instruction_length);
        let maximum_operations_per_instruction =
            u64::from(header.maximum_operations_per_instruction);

        if maximum_operations_per_instruction == 1 {
            self.address += minimum_instruction_length * operation_advance;
            self.op_index = 0;
        } else {
            let op_index_with_advance = self.op_index + operation_advance;
            self.address += minimum_instruction_length
                * (op_index_with_advance / maximum_operations_per_instruction);
            self.op_index = op_index_with_advance % maximum_operations_per_instruction;
        }
    }

    #[inline]
    fn adjust_opcode<R: Reader>(
        &self,
        opcode: u8,
        header: &LineNumberProgramHeader<R, R::Offset>,
    ) -> u8 {
        opcode - header.opcode_base
    }

    /// Section 6.2.5.1
    fn exec_special_opcode<R: Reader>(
        &mut self,
        opcode: u8,
        header: &LineNumberProgramHeader<R, R::Offset>,
    ) {
        let adjusted_opcode = self.adjust_opcode(opcode, header);

        let line_range = header.line_range;
        let line_advance = adjusted_opcode % line_range;
        let operation_advance = adjusted_opcode / line_range;

        // Step 1
        let line_base = i64::from(header.line_base);
        self.apply_line_advance(line_base + i64::from(line_advance));

        // Step 2
        self.apply_operation_advance(u64::from(operation_advance), header);
    }

    /// Execute the given opcode, and return true if a new row in the
    /// line number matrix needs to be generated.
    ///
    /// Unknown opcodes are treated as no-ops.
    fn execute<R, Program>(&mut self, opcode: Opcode<R>, program: &mut Program) -> bool
    where
        Program: LineNumberProgram<R, R::Offset>,
        R: Reader,
    {
        match opcode {
            Opcode::Special(opcode) => {
                self.exec_special_opcode(opcode, program.header());
                true
            }

            Opcode::Copy => true,

            Opcode::AdvancePc(operation_advance) => {
                self.apply_operation_advance(operation_advance, program.header());
                false
            }

            Opcode::AdvanceLine(line_increment) => {
                self.apply_line_advance(line_increment);
                false
            }

            Opcode::SetFile(file) => {
                self.file = file;
                false
            }

            Opcode::SetColumn(column) => {
                self.column = column;
                false
            }

            Opcode::NegateStatement => {
                self.is_stmt = !self.is_stmt;
                false
            }

            Opcode::SetBasicBlock => {
                self.basic_block = true;
                false
            }

            Opcode::ConstAddPc => {
                let adjusted = self.adjust_opcode(255, program.header());
                let operation_advance = adjusted / program.header().line_range;
                self.apply_operation_advance(u64::from(operation_advance), program.header());
                false
            }

            Opcode::FixedAddPc(operand) => {
                self.address += u64::from(operand);
                self.op_index = 0;
                false
            }

            Opcode::SetPrologueEnd => {
                self.prologue_end = true;
                false
            }

            Opcode::SetEpilogueBegin => {
                self.epilogue_begin = true;
                false
            }

            Opcode::SetIsa(isa) => {
                self.isa = isa;
                false
            }

            Opcode::EndSequence => {
                self.end_sequence = true;
                true
            }

            Opcode::SetAddress(address) => {
                self.address = address;
                self.op_index = 0;
                false
            }

            Opcode::DefineFile(entry) => {
                program.add_file(entry);
                false
            }

            Opcode::SetDiscriminator(discriminator) => {
                self.discriminator = discriminator;
                false
            }

            // Compatibility with future opcodes.
            Opcode::UnknownStandard0(_)
            | Opcode::UnknownStandard1(_, _)
            | Opcode::UnknownStandardN(_, _)
            | Opcode::UnknownExtended(_, _) => false,
        }
    }

    /// Perform any reset that was required after copying the previous row.
    fn reset(&mut self, default_is_stmt: bool) {
        if self.end_sequence {
            // Previous opcode was EndSequence, so reset everything
            // as specified in Section 6.2.5.3.
            *self = Self::new(default_is_stmt);
        } else {
            // Previous opcode was one of:
            // - Special - specified in Section 6.2.5.1, steps 4-7
            // - Copy - specified in Section 6.2.5.2
            // The reset behaviour is the same in both cases.
            self.discriminator = 0;
            self.basic_block = false;
            self.prologue_end = false;
            self.epilogue_begin = false;
        }
    }
}

/// A sequence within a line number program.  A sequence, as defined in section
/// 6.2.5 of the standard, is a linear subset of a line number program within
/// which addresses are monotonically increasing.
#[derive(Clone, Debug)]
pub struct LineNumberSequence<R: Reader> {
    /// The first address that is covered by this sequence within the line number
    /// program.
    pub start: u64,
    /// The first address that is *not* covered by this sequence within the line
    /// number program.
    pub end: u64,
    opcodes: OpcodesIter<R>,
}

/// A header for a line number program in the `.debug_line` section, as defined
/// in section 6.2.4 of the standard.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LineNumberProgramHeader<R, Offset = usize>
where
    R: Reader<Offset = Offset>,
    Offset: ReaderOffset,
{
    offset: DebugLineOffset<Offset>,
    unit_length: Offset,

    /// "A version number. This number is specific to the line number
    /// information and is independent of the DWARF version number."
    version: u16,

    header_length: Offset,

    /// "The size in bytes of the smallest target machine instruction. Line
    /// number program opcodes that alter the address and `op_index` registers
    /// use this and `maximum_operations_per_instruction` in their
    /// calculations."
    minimum_instruction_length: u8,

    /// > The maximum number of individual operations that may be encoded in an
    /// > instruction. Line number program opcodes that alter the address and
    /// > op_index registers use this and `minimum_instruction_length` in their
    /// > calculations.
    /// >
    /// > For non-VLIW architectures, this field is 1, the `op_index` register
    /// > is always 0, and the operation pointer is simply the address register.
    maximum_operations_per_instruction: u8,

    /// "The initial value of the `is_stmt` register."
    default_is_stmt: bool,

    /// "This parameter affects the meaning of the special opcodes."
    line_base: i8,

    /// "This parameter affects the meaning of the special opcodes."
    line_range: u8,

    /// "The number assigned to the first special opcode."
    opcode_base: u8,

    /// "This array specifies the number of LEB128 operands for each of the
    /// standard opcodes. The first element of the array corresponds to the
    /// opcode whose value is 1, and the last element corresponds to the opcode
    /// whose value is `opcode_base - 1`."
    standard_opcode_lengths: R,

    /// > Entries in this sequence describe each path that was searched for
    /// > included source files in this compilation. (The paths include those
    /// > directories specified explicitly by the user for the compiler to search
    /// > and those the compiler searches without explicit direction.) Each path
    /// > entry is either a full path name or is relative to the current directory
    /// > of the compilation.
    /// >
    /// > The last entry is followed by a single null byte.
    include_directories: Vec<R>,

    /// "Entries in this sequence describe source files that contribute to the
    /// line number information for this compilation unit or is used in other
    /// contexts."
    file_names: Vec<FileEntry<R>>,

    /// Whether this line program is encoded in the 32- or 64-bit DWARF format.
    format: Format,

    /// The encoded line program instructions.
    program_buf: R,

    /// The size of an address on the debuggee architecture, in bytes.
    address_size: u8,

    /// The `DW_AT_comp_dir` value from the compilation unit.
    comp_dir: Option<R>,

    /// The `DW_AT_name` value from the compilation unit.
    comp_name: Option<FileEntry<R>>,
}

impl<R, Offset> LineNumberProgramHeader<R, Offset>
where
    R: Reader<Offset = Offset>,
    Offset: ReaderOffset,
{
    /// Return the offset of the line number program header in the `.debug_line` section.
    pub fn offset(&self) -> DebugLineOffset<R::Offset> {
        self.offset
    }

    /// Return the length of the line number program and header, not including
    /// the length of the encoded length itself.
    pub fn unit_length(&self) -> R::Offset {
        self.unit_length
    }

    /// Get the version of this header's line program.
    pub fn version(&self) -> u16 {
        self.version
    }

    /// Get the length of the encoded line number program header, not including
    /// the length of the encoded length itself.
    pub fn header_length(&self) -> R::Offset {
        self.header_length
    }

    /// Get the size in bytes of a target machine address.
    pub fn address_size(&self) -> u8 {
        self.address_size
    }

    /// Whether this line program is encoded in 64- or 32-bit DWARF.
    pub fn format(&self) -> Format {
        self.format
    }

    /// Get the minimum instruction length any opcode in this header's line
    /// program may have.
    pub fn minimum_instruction_length(&self) -> u8 {
        self.minimum_instruction_length
    }

    /// Get the maximum number of operations each instruction in this header's
    /// line program may have.
    pub fn maximum_operations_per_instruction(&self) -> u8 {
        self.maximum_operations_per_instruction
    }

    /// Get the default value of the `is_stmt` register for this header's line
    /// program.
    pub fn default_is_stmt(&self) -> bool {
        self.default_is_stmt
    }

    /// Get the line base for this header's line program.
    pub fn line_base(&self) -> i8 {
        self.line_base
    }

    /// Get the line range for this header's line program.
    pub fn line_range(&self) -> u8 {
        self.line_range
    }

    /// Get opcode base for this header's line program.
    pub fn opcode_base(&self) -> u8 {
        self.opcode_base
    }

    /// The byte lengths of each standard opcode in this header's line program.
    pub fn standard_opcode_lengths(&self) -> &R {
        &self.standard_opcode_lengths
    }

    /// Get the set of include directories for this header's line program.
    ///
    /// The compilation's current directory is not included in the return value,
    /// but is implicitly considered to be in the set per spec.
    pub fn include_directories(&self) -> &[R] {
        &self.include_directories[..]
    }

    /// The include directory with the given directory index.
    ///
    /// A directory index of 0 corresponds to the compilation unit directory.
    pub fn directory(&self, directory: u64) -> Option<R> {
        if directory == 0 {
            self.comp_dir.clone()
        } else {
            let directory = directory as usize - 1;
            self.include_directories.get(directory).cloned()
        }
    }

    /// Get the list of source files that appear in this header's line program.
    pub fn file_names(&self) -> &[FileEntry<R>] {
        &self.file_names[..]
    }

    /// The source file with the given file index.
    ///
    /// A file index of 0 corresponds to the compilation unit file.
    /// Note that a file index of 0 is invalid for DWARF version <= 4,
    /// but we support it anyway.
    pub fn file(&self, file: u64) -> Option<&FileEntry<R>> {
        if file == 0 {
            self.comp_name.as_ref()
        } else {
            let file = file as usize - 1;
            self.file_names.get(file)
        }
    }

    /// Get the raw, un-parsed `EndianSlice` containing this header's line number
    /// program.
    ///
    /// ```
    /// # fn foo() {
    /// use gimli::{LineNumberProgramHeader, EndianSlice, NativeEndian};
    ///
    /// fn get_line_number_program_header<'a>() -> LineNumberProgramHeader<EndianSlice<'a, NativeEndian>> {
    ///     // Get a line number program header from some offset in a
    ///     // `.debug_line` section...
    /// #   unimplemented!()
    /// }
    ///
    /// let header = get_line_number_program_header();
    /// let raw_program = header.raw_program_buf();
    /// println!("The length of the raw program in bytes is {}", raw_program.len());
    /// # }
    /// ```
    pub fn raw_program_buf(&self) -> R {
        self.program_buf.clone()
    }

    /// Iterate over the opcodes in this header's line number program, parsing
    /// them as we go.
    pub fn opcodes(&self) -> OpcodesIter<R> {
        OpcodesIter {
            input: self.program_buf.clone(),
        }
    }

    fn parse(
        input: &mut R,
        offset: DebugLineOffset<Offset>,
        address_size: u8,
        comp_dir: Option<R>,
        comp_name: Option<R>,
    ) -> Result<LineNumberProgramHeader<R, Offset>> {
        let (unit_length, format) = input.read_initial_length()?;
        let rest = &mut input.split(unit_length)?;

        let version = rest.read_u16()?;
        if version < 2 || version > 4 {
            return Err(Error::UnknownVersion(u64::from(version)));
        }

        let header_length = rest.read_length(format)?;

        let mut program_buf = rest.clone();
        program_buf.skip(header_length)?;
        rest.truncate(header_length)?;

        let minimum_instruction_length = rest.read_u8()?;
        if minimum_instruction_length == 0 {
            return Err(Error::MinimumInstructionLengthZero);
        }

        // This field did not exist before DWARF 4, but is specified to be 1 for
        // non-VLIW architectures, which makes it a no-op.
        let maximum_operations_per_instruction = if version >= 4 { rest.read_u8()? } else { 1 };
        if maximum_operations_per_instruction == 0 {
            return Err(Error::MaximumOperationsPerInstructionZero);
        }

        let default_is_stmt = rest.read_u8()?;
        let line_base = rest.read_i8()?;
        let line_range = rest.read_u8()?;
        if line_range == 0 {
            return Err(Error::LineRangeZero);
        }

        let opcode_base = rest.read_u8()?;
        if opcode_base == 0 {
            return Err(Error::OpcodeBaseZero);
        }

        let standard_opcode_count = R::Offset::from_u8(opcode_base - 1);
        let standard_opcode_lengths = rest.split(standard_opcode_count)?;

        let mut include_directories = Vec::new();
        loop {
            let directory = rest.read_null_terminated_slice()?;
            if directory.is_empty() {
                break;
            }
            include_directories.push(directory);
        }

        let mut file_names = Vec::new();
        loop {
            let path_name = rest.read_null_terminated_slice()?;
            if path_name.is_empty() {
                break;
            }
            file_names.push(FileEntry::parse(rest, path_name)?);
        }

        let comp_name = comp_name.map(|name| FileEntry {
            path_name: name,
            directory_index: 0,
            last_modification: 0,
            length: 0,
        });

        let header = LineNumberProgramHeader {
            offset,
            unit_length,
            version,
            header_length,
            minimum_instruction_length,
            maximum_operations_per_instruction,
            default_is_stmt: default_is_stmt != 0,
            line_base,
            line_range,
            opcode_base,
            standard_opcode_lengths,
            include_directories,
            file_names,
            format,
            program_buf,
            address_size,
            comp_dir,
            comp_name,
        };
        Ok(header)
    }
}

/// A line number program that has not been run to completion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IncompleteLineNumberProgram<R, Offset = usize>
where
    R: Reader<Offset = Offset>,
    Offset: ReaderOffset,
{
    header: LineNumberProgramHeader<R, Offset>,
}

impl<R, Offset> IncompleteLineNumberProgram<R, Offset>
where
    R: Reader<Offset = Offset>,
    Offset: ReaderOffset,
{
    /// Retrieve the `LineNumberProgramHeader` for this program.
    pub fn header(&self) -> &LineNumberProgramHeader<R, Offset> {
        &self.header
    }

    /// Construct a new `StateMachine` for executing line programs and
    /// generating the line information matrix.
    pub fn rows(self) -> OneShotStateMachine<R, Offset> {
        OneShotStateMachine::new(self)
    }

    /// Execute the line number program, completing the `IncompleteLineNumberProgram`
    /// into a `CompleteLineNumberProgram` and producing an array of sequences within
    /// the line number program that can later be used with
    /// `CompleteLineNumberProgram::resume_from`.
    ///
    /// ```
    /// # fn foo() {
    /// use gimli::{IncompleteLineNumberProgram, EndianSlice, NativeEndian};
    ///
    /// fn get_line_number_program<'a>() -> IncompleteLineNumberProgram<EndianSlice<'a, NativeEndian>> {
    ///     // Get a line number program from some offset in a
    ///     // `.debug_line` section...
    /// #   unimplemented!()
    /// }
    ///
    /// let program = get_line_number_program();
    /// let (program, sequences) = program.sequences().unwrap();
    /// println!("There are {} sequences in this line number program", sequences.len());
    /// # }
    /// ```
    #[allow(clippy::type_complexity)]
    pub fn sequences(
        self,
    ) -> Result<(
        CompleteLineNumberProgram<R, Offset>,
        Vec<LineNumberSequence<R>>,
    )> {
        let mut sequences = Vec::new();
        let mut state_machine = self.rows();
        let mut opcodes = state_machine.opcodes.clone();
        let mut sequence_start_addr = None;
        loop {
            let sequence_end_addr;
            if state_machine.next_row()?.is_none() {
                break;
            }

            let row = &state_machine.row;
            if row.end_sequence() {
                sequence_end_addr = row.address();
            } else if sequence_start_addr.is_none() {
                sequence_start_addr = Some(row.address());
                continue;
            } else {
                continue;
            }

            // We just finished a sequence.
            sequences.push(LineNumberSequence {
                // In theory one could have multiple DW_LNE_end_sequence opcodes
                // in a row.
                start: sequence_start_addr.unwrap_or(0),
                end: sequence_end_addr,
                opcodes: opcodes.remove_trailing(&state_machine.opcodes)?,
            });
            sequence_start_addr = None;
            opcodes = state_machine.opcodes.clone();
        }

        let program = CompleteLineNumberProgram {
            header: state_machine.program.header,
        };
        Ok((program, sequences))
    }
}

/// A line number program that has previously been run to completion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteLineNumberProgram<R, Offset = usize>
where
    R: Reader<Offset = Offset>,
    Offset: ReaderOffset,
{
    header: LineNumberProgramHeader<R, Offset>,
}

impl<R, Offset> CompleteLineNumberProgram<R, Offset>
where
    R: Reader<Offset = Offset>,
    Offset: ReaderOffset,
{
    /// Retrieve the `LineNumberProgramHeader` for this program.
    pub fn header(&self) -> &LineNumberProgramHeader<R, Offset> {
        &self.header
    }

    /// Construct a new `StateMachine` for executing the subset of the line
    /// number program identified by 'sequence' and  generating the line information
    /// matrix.
    ///
    /// ```
    /// # fn foo() {
    /// use gimli::{IncompleteLineNumberProgram, EndianSlice, NativeEndian};
    ///
    /// fn get_line_number_program<'a>() -> IncompleteLineNumberProgram<EndianSlice<'a, NativeEndian>> {
    ///     // Get a line number program from some offset in a
    ///     // `.debug_line` section...
    /// #   unimplemented!()
    /// }
    ///
    /// let program = get_line_number_program();
    /// let (program, sequences) = program.sequences().unwrap();
    /// for sequence in &sequences {
    ///     let mut sm = program.resume_from(sequence);
    /// }
    /// # }
    /// ```
    pub fn resume_from<'program>(
        &'program self,
        sequence: &LineNumberSequence<R>,
    ) -> ResumedStateMachine<'program, R, Offset> {
        ResumedStateMachine::resume(self, sequence)
    }
}

/// An entry in the `LineNumberProgramHeader`'s `file_names` set.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FileEntry<R: Reader> {
    path_name: R,
    directory_index: u64,
    last_modification: u64,
    length: u64,
}

impl<R: Reader> FileEntry<R> {
    fn parse(input: &mut R, path_name: R) -> Result<FileEntry<R>> {
        let directory_index = input.read_uleb128()?;
        let last_modification = input.read_uleb128()?;
        let length = input.read_uleb128()?;

        let entry = FileEntry {
            path_name,
            directory_index,
            last_modification,
            length,
        };

        Ok(entry)
    }

    /// > A slice containing the full or relative path name of
    /// > a source file. If the entry contains a file name or a relative path
    /// > name, the file is located relative to either the compilation directory
    /// > (as specified by the DW_AT_comp_dir attribute given in the compilation
    /// > unit) or one of the directories in the include_directories section.
    pub fn path_name(&self) -> R {
        self.path_name.clone()
    }

    /// > An unsigned LEB128 number representing the directory index of the
    /// > directory in which the file was found.
    /// >
    /// > ...
    /// >
    /// > The directory index represents an entry in the include_directories
    /// > section of the line number program header. The index is 0 if the file
    /// > was found in the current directory of the compilation, 1 if it was found
    /// > in the first directory in the include_directories section, and so
    /// > on. The directory index is ignored for file names that represent full
    /// > path names.
    pub fn directory_index(&self) -> u64 {
        self.directory_index
    }

    /// Get this file's directory.
    ///
    /// A directory index of 0 corresponds to the compilation unit directory.
    pub fn directory(&self, header: &LineNumberProgramHeader<R, R::Offset>) -> Option<R> {
        header.directory(self.directory_index)
    }

    /// "An unsigned LEB128 number representing the time of last modification of
    /// the file, or 0 if not available."
    pub fn last_modification(&self) -> u64 {
        self.last_modification
    }

    /// "An unsigned LEB128 number representing the length in bytes of the file,
    /// or 0 if not available."
    pub fn length(&self) -> u64 {
        self.length
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use constants;
    use endianity::LittleEndian;
    use read::{EndianSlice, Error};
    use std::u8;

    #[test]
    fn test_parse_debug_line_32_ok() {
        #[cfg_attr(rustfmt, rustfmt_skip)]
        let buf = [
            // 32-bit length = 62.
            0x3e, 0x00, 0x00, 0x00,
            // Version.
            0x04, 0x00,
            // Header length = 40.
            0x28, 0x00, 0x00, 0x00,
            // Minimum instruction length.
            0x01,
            // Maximum operations per byte.
            0x01,
            // Default is_stmt.
            0x01,
            // Line base.
            0x00,
            // Line range.
            0x01,
            // Opcode base.
            0x03,
            // Standard opcode lengths for opcodes 1 .. opcode base - 1.
            0x01, 0x02,
            // Include directories = '/', 'i', 'n', 'c', '\0', '/', 'i', 'n', 'c', '2', '\0', '\0'
            0x2f, 0x69, 0x6e, 0x63, 0x00, 0x2f, 0x69, 0x6e, 0x63, 0x32, 0x00, 0x00,
            // File names
                // foo.rs
                0x66, 0x6f, 0x6f, 0x2e, 0x72, 0x73, 0x00,
                0x00,
                0x00,
                0x00,
                // bar.h
                0x62, 0x61, 0x72, 0x2e, 0x68, 0x00,
                0x01,
                0x00,
                0x00,
            // End file names.
            0x00,

            // Dummy line program data.
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,

            // Dummy next line program.
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        let rest = &mut EndianSlice::new(&buf, LittleEndian);
        let comp_dir = EndianSlice::new(b"/comp_dir", LittleEndian);
        let comp_name = EndianSlice::new(b"/comp_name", LittleEndian);

        let header = LineNumberProgramHeader::parse(
            rest,
            DebugLineOffset(0),
            4,
            Some(comp_dir),
            Some(comp_name),
        )
        .expect("should parse header ok");

        assert_eq!(
            *rest,
            EndianSlice::new(&buf[buf.len() - 16..], LittleEndian)
        );

        assert_eq!(header.offset, DebugLineOffset(0));
        assert_eq!(header.version, 4);
        assert_eq!(header.minimum_instruction_length(), 1);
        assert_eq!(header.maximum_operations_per_instruction(), 1);
        assert_eq!(header.default_is_stmt(), true);
        assert_eq!(header.line_base(), 0);
        assert_eq!(header.line_range(), 1);
        assert_eq!(header.opcode_base(), 3);
        assert_eq!(header.directory(0), Some(comp_dir));
        assert_eq!(header.file(0).unwrap().path_name, comp_name);

        let expected_lengths = [1, 2];
        assert_eq!(header.standard_opcode_lengths().slice(), &expected_lengths);

        let expected_include_directories = [
            EndianSlice::new(b"/inc", LittleEndian),
            EndianSlice::new(b"/inc2", LittleEndian),
        ];
        assert_eq!(header.include_directories(), &expected_include_directories);

        let expected_file_names = [
            FileEntry {
                path_name: EndianSlice::new(b"foo.rs", LittleEndian),
                directory_index: 0,
                last_modification: 0,
                length: 0,
            },
            FileEntry {
                path_name: EndianSlice::new(b"bar.h", LittleEndian),
                directory_index: 1,
                last_modification: 0,
                length: 0,
            },
        ];
        assert_eq!(&*header.file_names(), &expected_file_names);
    }

    #[test]
    fn test_parse_debug_line_header_length_too_short() {
        #[cfg_attr(rustfmt, rustfmt_skip)]
        let buf = [
            // 32-bit length = 62.
            0x3e, 0x00, 0x00, 0x00,
            // Version.
            0x04, 0x00,
            // Header length = 20. TOO SHORT!!!
            0x15, 0x00, 0x00, 0x00,
            // Minimum instruction length.
            0x01,
            // Maximum operations per byte.
            0x01,
            // Default is_stmt.
            0x01,
            // Line base.
            0x00,
            // Line range.
            0x01,
            // Opcode base.
            0x03,
            // Standard opcode lengths for opcodes 1 .. opcode base - 1.
            0x01, 0x02,
            // Include directories = '/', 'i', 'n', 'c', '\0', '/', 'i', 'n', 'c', '2', '\0', '\0'
            0x2f, 0x69, 0x6e, 0x63, 0x00, 0x2f, 0x69, 0x6e, 0x63, 0x32, 0x00, 0x00,
            // File names
                // foo.rs
                0x66, 0x6f, 0x6f, 0x2e, 0x72, 0x73, 0x00,
                0x00,
                0x00,
                0x00,
                // bar.h
                0x62, 0x61, 0x72, 0x2e, 0x68, 0x00,
                0x01,
                0x00,
                0x00,
            // End file names.
            0x00,

            // Dummy line program data.
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,

            // Dummy next line program.
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        let input = &mut EndianSlice::new(&buf, LittleEndian);

        match LineNumberProgramHeader::parse(input, DebugLineOffset(0), 4, None, None) {
            Err(Error::UnexpectedEof) => return,
            otherwise => panic!("Unexpected result: {:?}", otherwise),
        }
    }

    #[test]
    fn test_parse_debug_line_unit_length_too_short() {
        #[cfg_attr(rustfmt, rustfmt_skip)]
        let buf = [
            // 32-bit length = 40. TOO SHORT!!!
            0x28, 0x00, 0x00, 0x00,
            // Version.
            0x04, 0x00,
            // Header length = 40.
            0x28, 0x00, 0x00, 0x00,
            // Minimum instruction length.
            0x01,
            // Maximum operations per byte.
            0x01,
            // Default is_stmt.
            0x01,
            // Line base.
            0x00,
            // Line range.
            0x01,
            // Opcode base.
            0x03,
            // Standard opcode lengths for opcodes 1 .. opcode base - 1.
            0x01, 0x02,
            // Include directories = '/', 'i', 'n', 'c', '\0', '/', 'i', 'n', 'c', '2', '\0', '\0'
            0x2f, 0x69, 0x6e, 0x63, 0x00, 0x2f, 0x69, 0x6e, 0x63, 0x32, 0x00, 0x00,
            // File names
                // foo.rs
                0x66, 0x6f, 0x6f, 0x2e, 0x72, 0x73, 0x00,
                0x00,
                0x00,
                0x00,
                // bar.h
                0x62, 0x61, 0x72, 0x2e, 0x68, 0x00,
                0x01,
                0x00,
                0x00,
            // End file names.
            0x00,

            // Dummy line program data.
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,

            // Dummy next line program.
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        let input = &mut EndianSlice::new(&buf, LittleEndian);

        match LineNumberProgramHeader::parse(input, DebugLineOffset(0), 4, None, None) {
            Err(Error::UnexpectedEof) => return,
            otherwise => panic!("Unexpected result: {:?}", otherwise),
        }
    }

    const OPCODE_BASE: u8 = 13;
    const STANDARD_OPCODE_LENGTHS: &[u8] = &[0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1];

    fn make_test_header(
        buf: EndianSlice<LittleEndian>,
    ) -> LineNumberProgramHeader<EndianSlice<LittleEndian>> {
        LineNumberProgramHeader {
            offset: DebugLineOffset(0),
            opcode_base: OPCODE_BASE,
            address_size: 8,
            minimum_instruction_length: 1,
            maximum_operations_per_instruction: 1,
            default_is_stmt: true,
            program_buf: buf,
            version: 4,
            header_length: 1,
            file_names: vec![
                FileEntry {
                    path_name: EndianSlice::new(b"foo.c", LittleEndian),
                    directory_index: 0,
                    last_modification: 0,
                    length: 0,
                },
                FileEntry {
                    path_name: EndianSlice::new(b"bar.rs", LittleEndian),
                    directory_index: 0,
                    last_modification: 0,
                    length: 0,
                },
            ],
            format: Format::Dwarf32,
            line_base: -3,
            unit_length: 1,
            standard_opcode_lengths: EndianSlice::new(STANDARD_OPCODE_LENGTHS, LittleEndian),
            include_directories: vec![],
            line_range: 12,
            comp_dir: None,
            comp_name: None,
        }
    }

    fn make_test_program(
        buf: EndianSlice<LittleEndian>,
    ) -> IncompleteLineNumberProgram<EndianSlice<LittleEndian>> {
        IncompleteLineNumberProgram {
            header: make_test_header(buf),
        }
    }

    #[test]
    fn test_parse_special_opcodes() {
        for i in OPCODE_BASE..u8::MAX {
            let input = [i, 0, 0, 0];
            let input = EndianSlice::new(&input, LittleEndian);
            let header = make_test_header(input);

            let mut rest = input;
            let opcode = Opcode::parse(&header, &mut rest).expect("Should parse the opcode OK");

            assert_eq!(*rest, *input.range_from(1..));
            assert_eq!(opcode, Opcode::Special(i));
        }
    }

    #[test]
    fn test_parse_standard_opcodes() {
        fn test<Operands>(
            raw: constants::DwLns,
            operands: Operands,
            expected: Opcode<EndianSlice<LittleEndian>>,
        ) where
            Operands: AsRef<[u8]>,
        {
            let mut input = Vec::new();
            input.push(raw.0);
            input.extend_from_slice(operands.as_ref());

            let expected_rest = [0, 1, 2, 3, 4];
            input.extend_from_slice(&expected_rest);

            let input = EndianSlice::new(&*input, LittleEndian);
            let header = make_test_header(input);

            let mut rest = input;
            let opcode = Opcode::parse(&header, &mut rest).expect("Should parse the opcode OK");

            assert_eq!(opcode, expected);
            assert_eq!(*rest, expected_rest);
        }

        test(constants::DW_LNS_copy, [], Opcode::Copy);
        test(constants::DW_LNS_advance_pc, [42], Opcode::AdvancePc(42));
        test(constants::DW_LNS_advance_line, [9], Opcode::AdvanceLine(9));
        test(constants::DW_LNS_set_file, [7], Opcode::SetFile(7));
        test(constants::DW_LNS_set_column, [1], Opcode::SetColumn(1));
        test(constants::DW_LNS_negate_stmt, [], Opcode::NegateStatement);
        test(constants::DW_LNS_set_basic_block, [], Opcode::SetBasicBlock);
        test(constants::DW_LNS_const_add_pc, [], Opcode::ConstAddPc);
        test(
            constants::DW_LNS_fixed_advance_pc,
            [42, 0],
            Opcode::FixedAddPc(42),
        );
        test(
            constants::DW_LNS_set_prologue_end,
            [],
            Opcode::SetPrologueEnd,
        );
        test(
            constants::DW_LNS_set_isa,
            [57 + 0x80, 100],
            Opcode::SetIsa(12857),
        );
    }

    #[test]
    fn test_parse_unknown_standard_opcode_no_args() {
        let input = [OPCODE_BASE, 1, 2, 3];
        let input = EndianSlice::new(&input, LittleEndian);
        let mut standard_opcode_lengths = Vec::new();
        let mut header = make_test_header(input);
        standard_opcode_lengths.extend(header.standard_opcode_lengths.slice());
        standard_opcode_lengths.push(0);
        header.opcode_base += 1;
        header.standard_opcode_lengths = EndianSlice::new(&standard_opcode_lengths, LittleEndian);

        let mut rest = input;
        let opcode = Opcode::parse(&header, &mut rest).expect("Should parse the opcode OK");

        assert_eq!(
            opcode,
            Opcode::UnknownStandard0(constants::DwLns(OPCODE_BASE))
        );
        assert_eq!(*rest, *input.range_from(1..));
    }

    #[test]
    fn test_parse_unknown_standard_opcode_one_arg() {
        let input = [OPCODE_BASE, 1, 2, 3];
        let input = EndianSlice::new(&input, LittleEndian);
        let mut standard_opcode_lengths = Vec::new();
        let mut header = make_test_header(input);
        standard_opcode_lengths.extend(header.standard_opcode_lengths.slice());
        standard_opcode_lengths.push(1);
        header.opcode_base += 1;
        header.standard_opcode_lengths = EndianSlice::new(&standard_opcode_lengths, LittleEndian);

        let mut rest = input;
        let opcode = Opcode::parse(&header, &mut rest).expect("Should parse the opcode OK");

        assert_eq!(
            opcode,
            Opcode::UnknownStandard1(constants::DwLns(OPCODE_BASE), 1)
        );
        assert_eq!(*rest, *input.range_from(2..));
    }

    #[test]
    fn test_parse_unknown_standard_opcode_many_args() {
        let input = [OPCODE_BASE, 1, 2, 3];
        let input = EndianSlice::new(&input, LittleEndian);
        let args = EndianSlice::new(&input[1..], LittleEndian);
        let mut standard_opcode_lengths = Vec::new();
        let mut header = make_test_header(input);
        standard_opcode_lengths.extend(header.standard_opcode_lengths.slice());
        standard_opcode_lengths.push(3);
        header.opcode_base += 1;
        header.standard_opcode_lengths = EndianSlice::new(&standard_opcode_lengths, LittleEndian);

        let mut rest = input;
        let opcode = Opcode::parse(&header, &mut rest).expect("Should parse the opcode OK");

        assert_eq!(
            opcode,
            Opcode::UnknownStandardN(constants::DwLns(OPCODE_BASE), args)
        );
        assert_eq!(*rest, []);
    }

    #[test]
    fn test_parse_extended_opcodes() {
        fn test<Operands>(
            raw: constants::DwLne,
            operands: Operands,
            expected: Opcode<EndianSlice<LittleEndian>>,
        ) where
            Operands: AsRef<[u8]>,
        {
            let mut input = Vec::new();
            input.push(0);

            let operands = operands.as_ref();
            input.push(1 + operands.len() as u8);

            input.push(raw.0);
            input.extend_from_slice(operands);

            let expected_rest = [0, 1, 2, 3, 4];
            input.extend_from_slice(&expected_rest);

            let input = EndianSlice::new(&input, LittleEndian);
            let header = make_test_header(input);

            let mut rest = input;
            let opcode = Opcode::parse(&header, &mut rest).expect("Should parse the opcode OK");

            assert_eq!(opcode, expected);
            assert_eq!(*rest, expected_rest);
        }

        test(constants::DW_LNE_end_sequence, [], Opcode::EndSequence);
        test(
            constants::DW_LNE_set_address,
            [1, 2, 3, 4, 5, 6, 7, 8],
            Opcode::SetAddress(578_437_695_752_307_201),
        );
        test(
            constants::DW_LNE_set_discriminator,
            [42],
            Opcode::SetDiscriminator(42),
        );

        let mut file = Vec::new();
        // "foo.c"
        let path_name = [b'f', b'o', b'o', b'.', b'c', 0];
        file.extend_from_slice(&path_name);
        // Directory index.
        file.push(0);
        // Last modification of file.
        file.push(1);
        // Size of file.
        file.push(2);

        test(
            constants::DW_LNE_define_file,
            file,
            Opcode::DefineFile(FileEntry {
                path_name: EndianSlice::new(b"foo.c", LittleEndian),
                directory_index: 0,
                last_modification: 1,
                length: 2,
            }),
        );

        // Unknown extended opcode.
        let operands = [1, 2, 3, 4, 5, 6];
        let opcode = constants::DwLne(99);
        test(
            opcode,
            operands,
            Opcode::UnknownExtended(opcode, EndianSlice::new(&operands, LittleEndian)),
        );
    }

    #[test]
    fn test_file_entry_directory() {
        let path_name = [b'f', b'o', b'o', b'.', b'r', b's', 0];

        let mut file = FileEntry {
            path_name: EndianSlice::new(&path_name, LittleEndian),
            directory_index: 1,
            last_modification: 0,
            length: 0,
        };

        let mut header = make_test_header(EndianSlice::new(&[], LittleEndian));

        let dir = EndianSlice::new(b"dir", LittleEndian);
        header.include_directories.push(dir);

        assert_eq!(file.directory(&header), Some(dir));

        // Now test the compilation's current directory.
        file.directory_index = 0;
        assert_eq!(file.directory(&header), None);
    }

    fn new_registers() -> StateMachineRegisters {
        let mut regs = StateMachineRegisters::default();
        regs.reset(true);
        regs
    }

    fn assert_exec_opcode<'input>(
        header: LineNumberProgramHeader<EndianSlice<'input, LittleEndian>>,
        initial_registers: StateMachineRegisters,
        opcode: Opcode<EndianSlice<'input, LittleEndian>>,
        expected_registers: StateMachineRegisters,
        expect_new_row: bool,
    ) {
        let mut program = IncompleteLineNumberProgram { header };
        let mut row = LineNumberRow {
            registers: initial_registers,
        };

        let is_new_row = row.execute(opcode, &mut program);

        assert_eq!(is_new_row, expect_new_row);
        assert_eq!(row.registers, expected_registers);
    }

    #[test]
    fn test_exec_special_noop() {
        let header = make_test_header(EndianSlice::new(&[], LittleEndian));

        let initial_registers = new_registers();
        let opcode = Opcode::Special(16);
        let expected_registers = initial_registers;

        assert_exec_opcode(header, initial_registers, opcode, expected_registers, true);
    }

    #[test]
    fn test_exec_special_negative_line_advance() {
        let header = make_test_header(EndianSlice::new(&[], LittleEndian));

        let mut initial_registers = new_registers();
        initial_registers.line = 10;

        let opcode = Opcode::Special(13);

        let mut expected_registers = initial_registers;
        expected_registers.line -= 3;

        assert_exec_opcode(header, initial_registers, opcode, expected_registers, true);
    }

    #[test]
    fn test_exec_special_positive_line_advance() {
        let header = make_test_header(EndianSlice::new(&[], LittleEndian));

        let initial_registers = new_registers();

        let opcode = Opcode::Special(19);

        let mut expected_registers = initial_registers;
        expected_registers.line += 3;

        assert_exec_opcode(header, initial_registers, opcode, expected_registers, true);
    }

    #[test]
    fn test_exec_special_positive_address_advance() {
        let header = make_test_header(EndianSlice::new(&[], LittleEndian));

        let initial_registers = new_registers();

        let opcode = Opcode::Special(52);

        let mut expected_registers = initial_registers;
        expected_registers.address += 3;

        assert_exec_opcode(header, initial_registers, opcode, expected_registers, true);
    }

    #[test]
    fn test_exec_special_positive_address_and_line_advance() {
        let header = make_test_header(EndianSlice::new(&[], LittleEndian));

        let initial_registers = new_registers();

        let opcode = Opcode::Special(55);

        let mut expected_registers = initial_registers;
        expected_registers.address += 3;
        expected_registers.line += 3;

        assert_exec_opcode(header, initial_registers, opcode, expected_registers, true);
    }

    #[test]
    fn test_exec_special_positive_address_and_negative_line_advance() {
        let header = make_test_header(EndianSlice::new(&[], LittleEndian));

        let mut initial_registers = new_registers();
        initial_registers.line = 10;

        let opcode = Opcode::Special(49);

        let mut expected_registers = initial_registers;
        expected_registers.address += 3;
        expected_registers.line -= 3;

        assert_exec_opcode(header, initial_registers, opcode, expected_registers, true);
    }

    #[test]
    fn test_exec_special_line_underflow() {
        let header = make_test_header(EndianSlice::new(&[], LittleEndian));

        let mut initial_registers = new_registers();
        initial_registers.line = 2;

        // -3 line advance.
        let opcode = Opcode::Special(13);

        let mut expected_registers = initial_registers;
        // Clamp at 0. No idea if this is the best way to handle this situation
        // or not...
        expected_registers.line = 0;

        assert_exec_opcode(header, initial_registers, opcode, expected_registers, true);
    }

    #[test]
    fn test_exec_copy() {
        let header = make_test_header(EndianSlice::new(&[], LittleEndian));

        let mut initial_registers = new_registers();
        initial_registers.address = 1337;
        initial_registers.line = 42;

        let opcode = Opcode::Copy;

        let expected_registers = initial_registers;

        assert_exec_opcode(header, initial_registers, opcode, expected_registers, true);
    }

    #[test]
    fn test_exec_advance_pc() {
        let header = make_test_header(EndianSlice::new(&[], LittleEndian));
        let initial_registers = new_registers();
        let opcode = Opcode::AdvancePc(42);

        let mut expected_registers = initial_registers;
        expected_registers.address += 42;

        assert_exec_opcode(header, initial_registers, opcode, expected_registers, false);
    }

    #[test]
    fn test_exec_advance_line() {
        let header = make_test_header(EndianSlice::new(&[], LittleEndian));
        let initial_registers = new_registers();
        let opcode = Opcode::AdvanceLine(42);

        let mut expected_registers = initial_registers;
        expected_registers.line += 42;

        assert_exec_opcode(header, initial_registers, opcode, expected_registers, false);
    }

    #[test]
    fn test_exec_set_file_in_bounds() {
        for file_idx in 1..3 {
            let header = make_test_header(EndianSlice::new(&[], LittleEndian));
            let initial_registers = new_registers();
            let opcode = Opcode::SetFile(file_idx);

            let mut expected_registers = initial_registers;
            expected_registers.file = file_idx;

            assert_exec_opcode(header, initial_registers, opcode, expected_registers, false);
        }
    }

    #[test]
    fn test_exec_set_file_out_of_bounds() {
        let header = make_test_header(EndianSlice::new(&[], LittleEndian));
        let initial_registers = new_registers();
        let opcode = Opcode::SetFile(100);

        // The spec doesn't say anything about rejecting input programs
        // that set the file register out of bounds of the actual number
        // of files that have been defined. Instead, we cross our
        // fingers and hope that one gets defined before
        // `LineNumberRow::file` gets called and handle the error at
        // that time if need be.
        let mut expected_registers = initial_registers;
        expected_registers.file = 100;

        assert_exec_opcode(header, initial_registers, opcode, expected_registers, false);
    }

    #[test]
    fn test_file_entry_file_index_out_of_bounds() {
        // These indices are 1-based, so 0 is invalid. 100 is way more than the
        // number of files defined in the header.
        let out_of_bounds_indices = [0, 100];

        for file_idx in &out_of_bounds_indices[..] {
            let header = make_test_header(EndianSlice::new(&[], LittleEndian));
            let mut regs = new_registers();

            regs.file = *file_idx;

            let row = LineNumberRow { registers: regs };

            assert_eq!(row.file(&header), None);
        }
    }

    #[test]
    fn test_file_entry_file_index_in_bounds() {
        let header = make_test_header(EndianSlice::new(&[], LittleEndian));
        let mut regs = new_registers();

        regs.file = 2;

        let row = LineNumberRow { registers: regs };

        assert_eq!(row.file(&header), Some(&header.file_names()[1]));
    }

    #[test]
    fn test_exec_set_column() {
        let header = make_test_header(EndianSlice::new(&[], LittleEndian));
        let initial_registers = new_registers();
        let opcode = Opcode::SetColumn(42);

        let mut expected_registers = initial_registers;
        expected_registers.column = 42;

        assert_exec_opcode(header, initial_registers, opcode, expected_registers, false);
    }

    #[test]
    fn test_exec_negate_statement() {
        let header = make_test_header(EndianSlice::new(&[], LittleEndian));
        let initial_registers = new_registers();
        let opcode = Opcode::NegateStatement;

        let mut expected_registers = initial_registers;
        expected_registers.is_stmt = !initial_registers.is_stmt;

        assert_exec_opcode(header, initial_registers, opcode, expected_registers, false);
    }

    #[test]
    fn test_exec_set_basic_block() {
        let header = make_test_header(EndianSlice::new(&[], LittleEndian));

        let mut initial_registers = new_registers();
        initial_registers.basic_block = false;

        let opcode = Opcode::SetBasicBlock;

        let mut expected_registers = initial_registers;
        expected_registers.basic_block = true;

        assert_exec_opcode(header, initial_registers, opcode, expected_registers, false);
    }

    #[test]
    fn test_exec_const_add_pc() {
        let header = make_test_header(EndianSlice::new(&[], LittleEndian));
        let initial_registers = new_registers();
        let opcode = Opcode::ConstAddPc;

        let mut expected_registers = initial_registers;
        expected_registers.address += 20;

        assert_exec_opcode(header, initial_registers, opcode, expected_registers, false);
    }

    #[test]
    fn test_exec_fixed_add_pc() {
        let header = make_test_header(EndianSlice::new(&[], LittleEndian));

        let mut initial_registers = new_registers();
        initial_registers.op_index = 1;

        let opcode = Opcode::FixedAddPc(10);

        let mut expected_registers = initial_registers;
        expected_registers.address += 10;
        expected_registers.op_index = 0;

        assert_exec_opcode(header, initial_registers, opcode, expected_registers, false);
    }

    #[test]
    fn test_exec_set_prologue_end() {
        let header = make_test_header(EndianSlice::new(&[], LittleEndian));

        let mut initial_registers = new_registers();
        initial_registers.prologue_end = false;

        let opcode = Opcode::SetPrologueEnd;

        let mut expected_registers = initial_registers;
        expected_registers.prologue_end = true;

        assert_exec_opcode(header, initial_registers, opcode, expected_registers, false);
    }

    #[test]
    fn test_exec_set_isa() {
        let header = make_test_header(EndianSlice::new(&[], LittleEndian));
        let initial_registers = new_registers();
        let opcode = Opcode::SetIsa(1993);

        let mut expected_registers = initial_registers;
        expected_registers.isa = 1993;

        assert_exec_opcode(header, initial_registers, opcode, expected_registers, false);
    }

    #[test]
    fn test_exec_unknown_standard_0() {
        let header = make_test_header(EndianSlice::new(&[], LittleEndian));
        let initial_registers = new_registers();
        let opcode = Opcode::UnknownStandard0(constants::DwLns(111));
        let expected_registers = initial_registers;
        assert_exec_opcode(header, initial_registers, opcode, expected_registers, false);
    }

    #[test]
    fn test_exec_unknown_standard_1() {
        let header = make_test_header(EndianSlice::new(&[], LittleEndian));
        let initial_registers = new_registers();
        let opcode = Opcode::UnknownStandard1(constants::DwLns(111), 2);
        let expected_registers = initial_registers;
        assert_exec_opcode(header, initial_registers, opcode, expected_registers, false);
    }

    #[test]
    fn test_exec_unknown_standard_n() {
        let header = make_test_header(EndianSlice::new(&[], LittleEndian));
        let initial_registers = new_registers();
        let opcode = Opcode::UnknownStandardN(
            constants::DwLns(111),
            EndianSlice::new(&[2, 2, 2], LittleEndian),
        );
        let expected_registers = initial_registers;
        assert_exec_opcode(header, initial_registers, opcode, expected_registers, false);
    }

    #[test]
    fn test_exec_end_sequence() {
        let header = make_test_header(EndianSlice::new(&[], LittleEndian));
        let initial_registers = new_registers();
        let opcode = Opcode::EndSequence;

        let mut expected_registers = initial_registers;
        expected_registers.end_sequence = true;

        assert_exec_opcode(header, initial_registers, opcode, expected_registers, true);
    }

    #[test]
    fn test_exec_set_address() {
        let header = make_test_header(EndianSlice::new(&[], LittleEndian));
        let initial_registers = new_registers();
        let opcode = Opcode::SetAddress(3030);

        let mut expected_registers = initial_registers;
        expected_registers.address = 3030;

        assert_exec_opcode(header, initial_registers, opcode, expected_registers, false);
    }

    #[test]
    fn test_exec_define_file() {
        let mut program = make_test_program(EndianSlice::new(&[], LittleEndian));
        let mut row = LineNumberRow::new(&program);

        let file = FileEntry {
            path_name: EndianSlice::new(b"test.cpp", LittleEndian),
            directory_index: 0,
            last_modification: 0,
            length: 0,
        };

        let opcode = Opcode::DefineFile(file);
        let is_new_row = row.execute(opcode, &mut program);

        assert_eq!(is_new_row, false);
        assert_eq!(Some(&file), program.header().file_names.last());
    }

    #[test]
    fn test_exec_set_discriminator() {
        let header = make_test_header(EndianSlice::new(&[], LittleEndian));
        let initial_registers = new_registers();
        let opcode = Opcode::SetDiscriminator(9);

        let mut expected_registers = initial_registers;
        expected_registers.discriminator = 9;

        assert_exec_opcode(header, initial_registers, opcode, expected_registers, false);
    }

    #[test]
    fn test_exec_unknown_extended() {
        let header = make_test_header(EndianSlice::new(&[], LittleEndian));
        let initial_registers = new_registers();
        let opcode =
            Opcode::UnknownExtended(constants::DwLne(74), EndianSlice::new(&[], LittleEndian));
        let expected_registers = initial_registers;
        assert_exec_opcode(header, initial_registers, opcode, expected_registers, false);
    }

    /// Ensure that `StateMachine<R,P>` is covariant wrt R.
    /// This only needs to compile.
    #[allow(dead_code, unreachable_code, unused_variables)]
    fn test_statemachine_variance<'a, 'b>(_: &'a [u8], _: &'b [u8])
    where
        'a: 'b,
    {
        let a: &OneShotStateMachine<EndianSlice<'a, LittleEndian>> = unimplemented!();
        let _: &OneShotStateMachine<EndianSlice<'b, LittleEndian>> = a;
    }
}
