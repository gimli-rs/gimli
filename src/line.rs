use constants;
use endianity::{Endianity, EndianBuf};
use parser;
use std::ffi;
use std::fmt;
use std::marker::PhantomData;

/// An offset into the `.debug_line` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugLineOffset(pub u64);

/// The `DebugLine` struct contains the source location to instruction mapping
/// found in the `.debug_line` section.
#[derive(Debug, Clone, Copy)]
pub struct DebugLine<'input, Endian>
    where Endian: Endianity
{
    debug_line_section: EndianBuf<'input, Endian>,
}

impl<'input, Endian> DebugLine<'input, Endian>
    where Endian: Endianity
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
    /// let debug_line = DebugLine::<LittleEndian>::new(read_debug_line_section_somehow());
    /// ```
    pub fn new(debug_line_section: &'input [u8]) -> DebugLine<'input, Endian> {
        DebugLine { debug_line_section: EndianBuf(debug_line_section, PhantomData) }
    }
}

/// Executes a `LineNumberProgram` to recreate the matrix mapping to and from
/// instructions to source locations.
///
/// "The hypothetical machine used by a consumer of the line number information
/// to expand the byte-coded instruction stream into a matrix of line number
/// information." -- Section 6.2.1
#[derive(Debug)]
pub struct StateMachine<'input, Endian>
    where Endian: Endianity
{
    header: LineNumberProgramHeader<'input, Endian>,
    registers: StateMachineRegisters,
    opcodes: OpcodesIter<'input, Endian>,
}

impl<'input, Endian> StateMachine<'input, Endian>
    where Endian: Endianity
{
    /// Construct a new `StateMachine` for executing line programs and
    /// generating the line information matrix.
    pub fn new(header: LineNumberProgramHeader<'input, Endian>) -> Self {
        let mut registers = StateMachineRegisters::default();
        registers.reset(header.default_is_stmt());
        let opcodes = OpcodesIter {
            input: header.program_buf.0,
            endian: PhantomData,
        };
        StateMachine {
            header: header,
            registers: registers,
            opcodes: opcodes,
        }
    }

    /// Step 1 of section 6.2.5.1
    fn apply_line_advance(&mut self, line_increment: i64) {
        if line_increment < 0 {
            let decrement = -line_increment as u64;
            if decrement <= self.registers.line {
                self.registers.line -= decrement;
            } else {
                self.registers.line = 0;
            }
        } else {
            self.registers.line += line_increment as u64;
        }
    }

    /// Step 2 of section 6.2.5.1
    fn apply_operation_advance(&mut self, operation_advance: u64) {
        let minimum_instruction_length = self.header.minimum_instruction_length as u64;
        let maximum_operations_per_instruction =
            self.header.maximum_operations_per_instruction as u64;

        let op_index_with_advance = self.registers.op_index + operation_advance;

        self.registers.address = self.registers.address +
                                 minimum_instruction_length *
                                 (op_index_with_advance / maximum_operations_per_instruction);

        self.registers.op_index = op_index_with_advance % maximum_operations_per_instruction;
    }

    fn adjust_opcode(&self, opcode: u8) -> u8 {
        opcode - self.header.opcode_base
    }

    /// Section 6.2.5.1
    fn exec_special_opcode(&mut self, opcode: u8) {
        let adjusted_opcode = self.adjust_opcode(opcode);

        // Step 1

        let line_base = self.header.line_base as i64;
        let line_range = self.header.line_range;
        let line_increment = line_base + (adjusted_opcode % line_range) as i64;
        self.apply_line_advance(line_increment);

        // Step 2

        let operation_advance = adjusted_opcode / self.header.line_range;
        self.apply_operation_advance(operation_advance as u64);
    }

    /// Execute the given opcode, and return true if a new row in the
    /// line number matrix needs to be generated.
    ///
    /// Unknown opcodes are treated as no-ops.
    fn execute(&mut self, opcode: Opcode<'input>) -> bool {
        match opcode {
            Opcode::Special(opcode) => {
                self.exec_special_opcode(opcode);
                true
            }

            Opcode::Copy => true,

            Opcode::AdvancePc(operation_advance) => {
                self.apply_operation_advance(operation_advance);
                false
            }

            Opcode::AdvanceLine(line_increment) => {
                self.apply_line_advance(line_increment);
                false
            }

            Opcode::SetFile(file) => {
                self.registers.file = file;
                false
            }

            Opcode::SetColumn(column) => {
                self.registers.column = column;
                false
            }

            Opcode::NegateStatement => {
                self.registers.is_stmt = !self.registers.is_stmt;
                false
            }

            Opcode::SetBasicBlock => {
                self.registers.basic_block = true;
                false
            }

            Opcode::ConstAddPc => {
                let adjusted = self.adjust_opcode(255);
                let operation_advance = adjusted / self.header.line_range;
                self.apply_operation_advance(operation_advance as u64);
                false
            }

            Opcode::FixedAddPc(operand) => {
                self.registers.address += operand as u64;
                false
            }

            Opcode::SetPrologueEnd => {
                self.registers.prologue_end = true;
                false
            }

            Opcode::SetEpilogueBegin => {
                self.registers.epilogue_begin = true;
                false
            }

            Opcode::SetIsa(isa) => {
                self.registers.isa = isa;
                false
            }

            Opcode::EndSequence => {
                self.registers.end_sequence = true;
                true
            }

            Opcode::SetAddress(address) => {
                self.registers.address = address;
                self.registers.op_index = 0;
                false
            }

            Opcode::DefineFile(entry) => {
                self.header.file_names.push(entry);
                false
            }

            Opcode::SetDiscriminator(discriminator) => {
                self.registers.discriminator = discriminator;
                false
            }

            // Compatibility with future opcodes.
            Opcode::UnknownStandard0(_) |
            Opcode::UnknownStandard1(_, _) |
            Opcode::UnknownStandardN(_, _) |
            Opcode::UnknownExtended(_, _) => false,
        }
    }
}

impl<'input, Endian> StateMachine<'input, Endian>
    where Endian: Endianity
{
    /// Get a reference to the header for this state machine's line number
    /// program.
    pub fn header(&self) -> &LineNumberProgramHeader<'input, Endian> {
        &self.header
    }

    /// Parse and execute the next opcodes in the line number program until
    /// another row in the line number matrix is computed.
    ///
    /// The freshly computed row is returned as `Ok(Some(row))`. If the matrix
    /// is complete, and there are no more new rows in the line number matrix,
    /// then `Ok(None)` is returned. If there was an error parsing an opcode,
    /// then `Err(e)` is returned.
    pub fn next_row<'me>(&'me mut self)
                         -> parser::ParseResult<Option<LineNumberRow<'me, 'input, Endian>>> {
        // Perform any reset that was required after copying the previous row.
        if self.registers.end_sequence {
            // Previous opcode was EndSequence, so reset everything
            // as specified in Section 6.2.5.3.
            self.registers.reset(self.header.default_is_stmt);
        } else {
            // Previous opcode was one of:
            // - Special - specified in Section 6.2.5.1, steps 4-7
            // - Copy - specified in Section 6.2.5.2
            // The reset behaviour is the same in both cases.
            self.registers.discriminator = 0;
            self.registers.basic_block = false;
            self.registers.prologue_end = false;
            self.registers.epilogue_begin = false;
        }

        loop {
            match self.opcodes.next_opcode(&self.header) {
                Err(err) => return Err(err),
                Ok(None) => return Ok(None),
                Ok(Some(opcode)) => {
                    if self.execute(opcode) {
                        return Ok(Some(LineNumberRow::new(&self.header, &self.registers)));
                    }
                    // Fall through, parse the next opcode, and see if that
                    // yields a row.
                }
            }
        }
    }

    /// Parse and execute opcodes until we reach a row matching `addr`, the end of the program,
    /// or an error.
    pub fn run_to_address<'me>
        (&'me mut self,
         addr: &u64)
         -> parser::ParseResult<Option<LineNumberRow<'me, 'input, Endian>>> {
        loop {
            match self.next_row() {
                Ok(Some(row)) => {
                    if row.address() == *addr {
                        // Can't return 'row' directly here because of rust-lang/rust#21906.
                        break;
                    }
                }
                Ok(None) => return Ok(None),
                Err(err) => return Err(err),
            };
        }

        Ok(Some(LineNumberRow::new(&self.header, &self.registers)))
    }
}

/// A parsed line number program opcode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Opcode<'input> {
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
    UnknownStandardN(constants::DwLns, Vec<u64>),

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
    DefineFile(FileEntry<'input>),

    /// "The DW_LNE_set_discriminator opcode takes a single parameter, an
    /// unsigned LEB128 integer. It sets the discriminator register to the new
    /// value."
    SetDiscriminator(u64),

    /// An unknown extended opcode and the slice of its unparsed operands.
    UnknownExtended(constants::DwLne, &'input [u8]),
}

impl<'input> Opcode<'input> {
    fn parse<'header, Endian>(header: &'header LineNumberProgramHeader<'input, Endian>,
                              input: &'input [u8])
                              -> parser::ParseResult<(&'input [u8], Opcode<'input>)>
        where Endian: 'header + Endianity,
              'input: 'header
    {
        let (rest, opcode) = try!(parser::parse_u8(input));
        if opcode == 0 {
            let (rest, length) = try!(parser::parse_unsigned_leb(rest));
            let length = length as usize;
            if rest.len() < length {
                return Err(parser::Error::UnexpectedEof);
            }

            let instr_rest = &rest[..length];
            let rest = &rest[length..];
            let (instr_rest, opcode) = try!(parser::parse_u8(instr_rest));

            match constants::DwLne(opcode) {
                constants::DW_LNE_end_sequence => Ok((rest, Opcode::EndSequence)),

                constants::DW_LNE_set_address => {
                    let (_, address) =
                        try!(parser::parse_address(EndianBuf::<Endian>::new(instr_rest),
                                                   header.address_size));
                    Ok((rest, Opcode::SetAddress(address)))
                }

                constants::DW_LNE_define_file => {
                    let (_, entry) = try!(FileEntry::parse(instr_rest));
                    Ok((rest, Opcode::DefineFile(entry)))
                }

                constants::DW_LNE_set_discriminator => {
                    let (_, discriminator) = try!(parser::parse_unsigned_leb(instr_rest));
                    Ok((rest, Opcode::SetDiscriminator(discriminator)))
                }

                otherwise => Ok((rest, Opcode::UnknownExtended(otherwise, instr_rest))),
            }
        } else if opcode >= header.opcode_base {
            Ok((rest, Opcode::Special(opcode)))
        } else {
            match constants::DwLns(opcode) {
                constants::DW_LNS_copy => Ok((rest, Opcode::Copy)),

                constants::DW_LNS_advance_pc => {
                    let (rest, advance) = try!(parser::parse_unsigned_leb(rest));
                    Ok((rest, Opcode::AdvancePc(advance)))
                }

                constants::DW_LNS_advance_line => {
                    let (rest, increment) = try!(parser::parse_signed_leb(rest));
                    Ok((rest, Opcode::AdvanceLine(increment)))
                }

                constants::DW_LNS_set_file => {
                    let (rest, file) = try!(parser::parse_unsigned_leb(rest));
                    Ok((rest, Opcode::SetFile(file)))
                }

                constants::DW_LNS_set_column => {
                    let (rest, column) = try!(parser::parse_unsigned_leb(rest));
                    Ok((rest, Opcode::SetColumn(column)))
                }

                constants::DW_LNS_negate_stmt => Ok((rest, Opcode::NegateStatement)),

                constants::DW_LNS_set_basic_block => Ok((rest, Opcode::SetBasicBlock)),

                constants::DW_LNS_const_add_pc => Ok((rest, Opcode::ConstAddPc)),

                constants::DW_LNS_fixed_advance_pc => {
                    let (rest, advance) = try!(parser::parse_u16(EndianBuf::<Endian>::new(rest)));
                    Ok((rest.into(), Opcode::FixedAddPc(advance)))
                }

                constants::DW_LNS_set_prologue_end => Ok((rest, Opcode::SetPrologueEnd)),

                constants::DW_LNS_set_epilogue_begin => Ok((rest, Opcode::SetEpilogueBegin)),

                constants::DW_LNS_set_isa => {
                    let (rest, isa) = try!(parser::parse_unsigned_leb(rest));
                    Ok((rest, Opcode::SetIsa(isa)))
                }

                otherwise if header.standard_opcode_lengths[(opcode - 1) as usize] == 0 => {
                    Ok((rest, Opcode::UnknownStandard0(otherwise)))
                }

                otherwise if header.standard_opcode_lengths[(opcode - 1) as usize] == 1 => {
                    let (rest, arg) = try!(parser::parse_unsigned_leb(rest));
                    Ok((rest, Opcode::UnknownStandard1(otherwise, arg)))
                }

                otherwise => {
                    let num_args = header.standard_opcode_lengths[(opcode - 1) as usize];
                    let mut args = Vec::with_capacity(num_args as usize);
                    let mut rest = rest;
                    for _ in 0..num_args {
                        let (rest1, arg) = try!(parser::parse_unsigned_leb(rest));
                        args.push(arg);
                        rest = rest1;
                    }
                    Ok((rest, Opcode::UnknownStandardN(otherwise, args)))
                }
            }
        }
    }
}

impl<'input> fmt::Display for Opcode<'input> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
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
#[derive(Debug)]
pub struct OpcodesIter<'input, Endian>
    where Endian: Endianity
{
    input: &'input [u8],
    endian: PhantomData<Endian>,
}

impl<'input, Endian> OpcodesIter<'input, Endian>
    where Endian: Endianity
{
    /// Advance the iterator and return the next opcode.
    ///
    /// Returns the newly parsed opcode as `Ok(Some(opcode))`. Returns
    /// `Ok(None)` when iteration is complete and all opcodes have already been
    /// parsed and yielded. If an error occurs while parsing the next attribute,
    /// then this error is returned on all subsequent calls as `Err(e)`.
    pub fn next_opcode(&mut self,
                       header: &LineNumberProgramHeader<'input, Endian>)
                       -> parser::ParseResult<Option<Opcode<'input>>> {
        if self.input.len() == 0 {
            return Ok(None);
        }

        Opcode::parse(header, self.input).map(|(rest, opcode)| {
            self.input = rest;
            Some(opcode)
        })
    }
}

/// A row in the line number program's resulting matrix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineNumberRow<'statemachine, 'input, Endian>
    where Endian: 'statemachine + Endianity,
          'input: 'statemachine
{
    header: &'statemachine LineNumberProgramHeader<'input, Endian>,
    registers: &'statemachine StateMachineRegisters,
}

impl<'statemachine, 'input, Endian> LineNumberRow<'statemachine, 'input, Endian>
    where Endian: 'statemachine + Endianity,
          'input: 'statemachine
{
    fn new(header: &'statemachine LineNumberProgramHeader<'input, Endian>,
           registers: &'statemachine StateMachineRegisters)
           -> LineNumberRow<'statemachine, 'input, Endian> {
        LineNumberRow {
            header: header,
            registers: registers,
        }
    }

    /// Get the header for this row's line number program.
    pub fn header(&self) -> &'statemachine LineNumberProgramHeader<'input, Endian> {
        self.header
    }

    /// "The program-counter value corresponding to a machine instruction
    /// generated by the compiler."
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
    pub fn op_index(&self) -> u64 {
        self.registers.op_index
    }

    /// "An unsigned integer indicating the identity of the source file
    /// corresponding to a machine instruction."
    pub fn file_index(&self) -> u64 {
        self.registers.file
    }

    /// The source file corresponding to the current machine instruction.
    pub fn file(&self) -> Option<&'statemachine FileEntry<'input>> {
        // NB: registers.file starts counting at 1.
        let file_idx = self.registers.file as usize - 1;
        if self.header.file_names.len() > file_idx {
            Some(&self.header.file_names[file_idx])
        } else {
            None
        }
    }

    /// "An unsigned integer indicating a source line number. Lines are numbered
    /// beginning at 1. The compiler may emit the value 0 in cases where an
    /// instruction cannot be attributed to any source line."
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
    pub fn is_stmt(&self) -> bool {
        self.registers.is_stmt
    }

    /// "A boolean indicating that the current instruction is the beginning of a
    /// basic block."
    pub fn basic_block(&self) -> bool {
        self.registers.basic_block
    }

    /// "A boolean indicating that the current address is that of the first byte
    /// after the end of a sequence of target machine instructions. end_sequence
    /// terminates a sequence of lines; therefore other information in the same
    /// row is not meaningful."
    pub fn end_sequence(&self) -> bool {
        self.registers.end_sequence
    }

    /// "A boolean indicating that the current address is one (of possibly many)
    /// where execution should be suspended for an entry breakpoint of a
    /// function."
    pub fn prologue_end(&self) -> bool {
        self.registers.prologue_end
    }

    /// "A boolean indicating that the current address is one (of possibly many)
    /// where execution should be suspended for an exit breakpoint of a
    /// function."
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
    pub fn isa(&self) -> u64 {
        self.registers.isa
    }

    /// "An unsigned integer identifying the block to which the current
    /// instruction belongs. Discriminator values are assigned arbitrarily by
    /// the DWARF producer and serve to distinguish among multiple blocks that
    /// may all be associated with the same source file, line, and column. Where
    /// only one block exists for a given source position, the discriminator
    /// value should be zero."
    pub fn discriminator(&self) -> u64 {
        self.registers.discriminator
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
    fn reset(&mut self, default_is_stmt: bool) {
        // "At the beginning of each sequence within a line number program, the
        // state of the registers is:" -- Section 6.2.2
        self.address = 0;
        self.op_index = 0;
        self.file = 1;
        self.line = 1;
        self.column = 0;
        // "determined by default_is_stmt in the line number program header"
        self.is_stmt = default_is_stmt;
        self.basic_block = false;
        self.end_sequence = false;
        self.prologue_end = false;
        self.epilogue_begin = false;
        // "The isa value 0 specifies that the instruction set is the
        // architecturally determined default instruction set. This may be fixed
        // by the ABI, or it may be specified by other means, for example, by
        // the object file description."
        self.isa = 0;
        self.discriminator = 0;
    }
}

/// A header for a line number program in the `.debug_line` section, as defined
/// in section 6.2.4 of the standard.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LineNumberProgramHeader<'input, Endian>
    where Endian: Endianity
{
    unit_length: u64,

    /// "A version number. This number is specific to the line number
    /// information and is independent of the DWARF version number."
    version: u16,

    header_length: u64,

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
    standard_opcode_lengths: &'input [u8],

    /// > Entries in this sequence describe each path that was searched for
    /// > included source files in this compilation. (The paths include those
    /// > directories specified explicitly by the user for the compiler to search
    /// > and those the compiler searches without explicit direction.) Each path
    /// > entry is either a full path name or is relative to the current directory
    /// > of the compilation.
    /// >
    /// > The last entry is followed by a single null byte.
    include_directories: Vec<&'input ffi::CStr>,

    /// "Entries in this sequence describe source files that contribute to the
    /// line number information for this compilation unit or is used in other
    /// contexts."
    file_names: Vec<FileEntry<'input>>,

    /// Whether this line program is encoded in the 32- or 64-bit DWARF format.
    format: parser::Format,

    /// The encoded line program instructions.
    program_buf: EndianBuf<'input, Endian>,

    /// The size of an address on the debuggee architecture, in bytes.
    address_size: u8,
}

impl<'input, Endian> LineNumberProgramHeader<'input, Endian>
    where Endian: Endianity
{
    /// Parse the line number program header at the given `offset` in the
    /// `.debug_line` section.
    ///
    /// ```rust,no_run
    /// use gimli::{DebugLine, DebugLineOffset, LineNumberProgramHeader, LittleEndian};
    ///
    /// # let buf = [];
    /// # let read_debug_line_section_somehow = || &buf;
    /// let debug_line = DebugLine::<LittleEndian>::new(read_debug_line_section_somehow());
    ///
    /// // In a real example, we'd grab the offset via a compilation unit
    /// // entry's `DW_AT_stmt_list` attribute, and the address size from that
    /// // unit directly.
    /// let offset = DebugLineOffset(0);
    /// let address_size = 8;
    ///
    /// let header = LineNumberProgramHeader::new(debug_line, offset, address_size)
    ///     .expect("should have found a header at that offset, and parsed it OK");
    /// ```
    pub fn new(debug_line: DebugLine<'input, Endian>,
               offset: DebugLineOffset,
               address_size: u8)
               -> parser::ParseResult<LineNumberProgramHeader<'input, Endian>> {
        let offset = offset.0 as usize;
        let (_, mut header) = try!(Self::parse(debug_line.debug_line_section.range_from(offset..)));
        header.address_size = address_size;
        Ok(header)
    }

    /// Return the length of the line number program and header, not including
    /// the length of the encoded length itself.
    pub fn unit_length(&self) -> u64 {
        self.unit_length
    }

    /// Get the version of this header's line program.
    pub fn version(&self) -> u16 {
        self.version
    }

    /// Get the length of the encoded line number program header, not including
    /// the length of the encoded length itself.
    pub fn header_length(&self) -> u64 {
        self.header_length
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
    pub fn standard_opcode_lengths(&self) -> &'input [u8] {
        &self.standard_opcode_lengths[..]
    }

    /// Get the set of include directories for this header's line program.
    ///
    /// The compilation's current directory is not included in the return value,
    /// but is implicitly considered to be in the set per spec.
    pub fn include_directories(&self) -> &[&ffi::CStr] {
        &self.include_directories[..]
    }

    /// Get the list of source files that appear in this header's line program.
    pub fn file_names(&self) -> &[FileEntry] {
        &self.file_names[..]
    }

    /// Iterate over the opcodes in this header's line number program, parsing
    /// them as we go.
    pub fn opcodes(&self) -> OpcodesIter<'input, Endian> {
        OpcodesIter {
            input: self.program_buf.0,
            endian: PhantomData,
        }
    }

    fn parse(input: EndianBuf<'input, Endian>)
             -> parser::ParseResult<(EndianBuf<'input, Endian>,
                                     LineNumberProgramHeader<'input, Endian>)> {
        let (rest, (unit_length, format)) = try!(parser::parse_unit_length(input));
        if (rest.len() as u64) < unit_length {
            return Err(parser::Error::UnexpectedEof);
        }
        let next_header_input = rest.range_from(unit_length as usize..);
        let rest = rest.range_to(..unit_length as usize);

        let (rest, version) = try!(parser::parse_u16(rest));
        if version < 2 || version > 4 {
            return Err(parser::Error::UnknownVersion);
        }

        let (rest, header_length) = try!(parser::parse_word(rest, format));

        if header_length as usize > rest.len() {
            return Err(parser::Error::UnitHeaderLengthTooShort);
        }
        let program_buf = rest.range_from(header_length as usize..);
        let rest = rest.range_to(..header_length as usize);

        let (rest, minimum_instruction_length) = try!(parser::parse_u8(rest.0));
        if minimum_instruction_length == 0 {
            return Err(parser::Error::MinimumInstructionLengthZero);
        }

        // This field did not exist before DWARF 4, but is specified to be 1 for
        // non-VLIW architectures, which makes it a no-op.
        let (rest, maximum_operations_per_instruction) = if version >= 4 {
            try!(parser::parse_u8(rest))
        } else {
            (rest, 1)
        };
        if maximum_operations_per_instruction == 0 {
            return Err(parser::Error::MaximumOperationsPerInstructionZero);
        }

        let (rest, default_is_stmt) = try!(parser::parse_u8(rest));
        let (rest, line_base) = try!(parser::parse_i8(rest));
        let (rest, line_range) = try!(parser::parse_u8(rest));
        if line_range == 0 {
            return Err(parser::Error::LineRangeZero);
        }

        let (rest, opcode_base) = try!(parser::parse_u8(rest));
        if opcode_base == 0 {
            return Err(parser::Error::OpcodeBaseZero);
        }

        let standard_opcode_count = opcode_base as usize - 1;
        if rest.len() < standard_opcode_count {
            return Err(parser::Error::UnexpectedEof);
        }
        let standard_opcode_lengths = &rest[..standard_opcode_count];
        let mut rest = EndianBuf::<Endian>::new(&rest[standard_opcode_count..]);

        let mut include_directories = Vec::new();
        loop {
            if rest.len() == 0 {
                return Err(parser::Error::UnexpectedEof);
            }

            if rest[0] == 0 {
                rest = rest.range_from(1..);
                break;
            }

            let (rest1, include_directory) = try!(parser::parse_null_terminated_string(rest.0));
            rest = EndianBuf::new(rest1);
            include_directories.push(include_directory);
        }

        let mut file_names = Vec::new();
        loop {
            if rest.len() == 0 {
                return Err(parser::Error::UnexpectedEof);
            }

            if rest[0] == 0 {
                let header = LineNumberProgramHeader {
                    unit_length: unit_length,
                    version: version,
                    header_length: header_length,
                    minimum_instruction_length: minimum_instruction_length,
                    maximum_operations_per_instruction: maximum_operations_per_instruction,
                    default_is_stmt: default_is_stmt != 0,
                    line_base: line_base,
                    line_range: line_range,
                    opcode_base: opcode_base,
                    standard_opcode_lengths: standard_opcode_lengths,
                    include_directories: include_directories,
                    file_names: file_names,
                    format: format,
                    program_buf: program_buf,
                    address_size: 0,
                };
                return Ok((next_header_input, header));
            }

            let (rest1, file_name) = try!(FileEntry::parse(rest.0));
            rest = EndianBuf::new(rest1);
            file_names.push(file_name);
        }
    }
}

/// An entry in the `LineNumberProgramHeader`'s `file_names` set.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FileEntry<'input> {
    path_name: &'input ffi::CStr,
    directory_index: u64,
    last_modification: u64,
    length: u64,
}

impl<'input> FileEntry<'input> {
    fn parse(input: &'input [u8]) -> parser::ParseResult<(&'input [u8], FileEntry<'input>)> {
        let (rest, path_name) = try!(parser::parse_null_terminated_string(input));
        let (rest, directory_index) = try!(parser::parse_unsigned_leb(rest));
        let (rest, last_modification) = try!(parser::parse_unsigned_leb(rest));
        let (rest, length) = try!(parser::parse_unsigned_leb(rest));

        let entry = FileEntry {
            path_name: path_name,
            directory_index: directory_index,
            last_modification: last_modification,
            length: length,
        };

        Ok((rest, entry))
    }

    /// > A null-terminated string containing the full or relative path name of
    /// > a source file. If the entry contains a file name or a relative path
    /// > name, the file is located relative to either the compilation directory
    /// > (as specified by the DW_AT_comp_dir attribute given in the compilation
    /// > unit) or one of the directories in the include_directories section.
    pub fn path_name(&self) -> &'input ffi::CStr {
        self.path_name
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
    /// If this file's directory index is 0, meaning that it was found in
    /// the current directory of compilation, return `None`.
    pub fn directory<Endian>(&self,
                             header: &LineNumberProgramHeader<'input, Endian>)
                             -> Option<&'input ffi::CStr>
        where Endian: Endianity
    {
        if self.directory_index == 0 {
            None
        } else {
            let idx = self.directory_index - 1;
            Some(&header.include_directories[idx as usize])
        }
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
    use super::StateMachineRegisters;
    use constants;
    use endianity::{EndianBuf, LittleEndian};
    use parser::{Error, Format};
    use std::ffi;
    use std::u8;

    #[test]
    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn test_parse_debug_line_32_ok() {
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

        let input = EndianBuf::<LittleEndian>::new(&buf);

        let (rest, header) = LineNumberProgramHeader::parse(input)
            .expect("should parse header ok");

        assert_eq!(rest, EndianBuf::new(&buf[buf.len() - 16..]));

        assert_eq!(header.version, 4);
        assert_eq!(header.minimum_instruction_length(), 1);
        assert_eq!(header.maximum_operations_per_instruction(), 1);
        assert_eq!(header.default_is_stmt(), true);
        assert_eq!(header.line_base(), 0);
        assert_eq!(header.line_range(), 1);
        assert_eq!(header.opcode_base(), 3);

        let expected_lengths = [1, 2];
        assert_eq!(header.standard_opcode_lengths(), &expected_lengths);

        let expected_include_directories = [
            ffi::CStr::from_bytes_with_nul(b"/inc\0").unwrap(),
            ffi::CStr::from_bytes_with_nul(b"/inc2\0").unwrap(),
        ];
        assert_eq!(header.include_directories(), &expected_include_directories);

        let expected_file_names = [
            FileEntry {
                path_name: ffi::CStr::from_bytes_with_nul(b"foo.rs\0").unwrap(),
                directory_index: 0,
                last_modification: 0,
                length: 0,
            },
            FileEntry {
                path_name: ffi::CStr::from_bytes_with_nul(b"bar.h\0").unwrap(),
                directory_index: 1,
                last_modification: 0,
                length: 0,
            },
        ];
        assert_eq!(&*header.file_names(), &expected_file_names);
    }

    #[test]
    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn test_parse_debug_line_header_length_too_short() {
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

        let input = EndianBuf::<LittleEndian>::new(&buf);

        match LineNumberProgramHeader::parse(input) {
            Err(Error::UnexpectedEof) => return,
            otherwise => panic!("Unexpected result: {:?}", otherwise),
        }
    }

    #[test]
    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn test_parse_debug_line_unit_length_too_short() {
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

        let input = EndianBuf::<LittleEndian>::new(&buf);

        match LineNumberProgramHeader::parse(input) {
            Err(Error::UnitHeaderLengthTooShort) => return,
            otherwise => panic!("Unexpected result: {:?}", otherwise),
        }
    }

    const OPCODE_BASE: u8 = 13;
    const STANDARD_OPCODE_LENGTHS: &'static [u8] = &[0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1];

    fn make_test_header(buf: &[u8]) -> LineNumberProgramHeader<LittleEndian> {
        LineNumberProgramHeader {
            opcode_base: OPCODE_BASE,
            address_size: 8,
            minimum_instruction_length: 1,
            maximum_operations_per_instruction: 1,
            default_is_stmt: true,
            program_buf: EndianBuf::new(buf),
            version: 4,
            header_length: 1,
            file_names: vec![],
            format: Format::Dwarf32,
            line_base: -3,
            unit_length: 1,
            standard_opcode_lengths: STANDARD_OPCODE_LENGTHS,
            include_directories: vec![],
            line_range: 12,
        }
    }

    #[test]
    fn test_parse_special_opcodes() {
        for i in OPCODE_BASE..u8::MAX {
            let input = [i, 0, 0, 0];
            let header = make_test_header(&input);

            let (rest, opcode) = Opcode::parse(&header, &input)
                .expect("Should parse the opcode OK");

            assert_eq!(rest, &input[1..]);
            assert_eq!(opcode, Opcode::Special(i));
        }
    }

    #[test]
    fn test_parse_standard_opcodes() {
        fn test<Operands>(raw: constants::DwLns, operands: Operands, expected: Opcode)
            where Operands: AsRef<[u8]>
        {
            let mut input = Vec::new();
            input.push(raw.0);
            input.extend_from_slice(operands.as_ref());

            let expected_rest = [0, 1, 2, 3, 4];
            input.extend_from_slice(&expected_rest);

            let header = make_test_header(&input);

            let (rest, opcode) = Opcode::parse(&header, &input)
                .expect("Should parse the opcode OK");

            assert_eq!(opcode, expected);
            assert_eq!(rest, &expected_rest);
        }

        test(constants::DW_LNS_copy, [], Opcode::Copy);
        test(constants::DW_LNS_advance_pc, [42], Opcode::AdvancePc(42));
        test(constants::DW_LNS_advance_line, [9], Opcode::AdvanceLine(9));
        test(constants::DW_LNS_set_file, [7], Opcode::SetFile(7));
        test(constants::DW_LNS_set_column, [1], Opcode::SetColumn(1));
        test(constants::DW_LNS_negate_stmt, [], Opcode::NegateStatement);
        test(constants::DW_LNS_set_basic_block, [], Opcode::SetBasicBlock);
        test(constants::DW_LNS_const_add_pc, [], Opcode::ConstAddPc);
        test(constants::DW_LNS_fixed_advance_pc,
             [42, 0],
             Opcode::FixedAddPc(42));
        test(constants::DW_LNS_set_prologue_end,
             [],
             Opcode::SetPrologueEnd);
        test(constants::DW_LNS_set_isa,
             [57 + 0x80, 100],
             Opcode::SetIsa(12857));
    }

    #[test]
    fn test_parse_unknown_standard_opcode_no_args() {
        let input = [OPCODE_BASE, 1, 2, 3];
        let mut standard_opcode_lengths = Vec::new();
        let mut header = make_test_header(&input);
        standard_opcode_lengths.extend(header.standard_opcode_lengths);
        standard_opcode_lengths.push(0);
        header.opcode_base += 1;
        header.standard_opcode_lengths = &standard_opcode_lengths;

        let (rest, opcode) = Opcode::parse(&header, &input).expect("Should parse the opcode OK");

        assert_eq!(opcode,
                   Opcode::UnknownStandard0(constants::DwLns(OPCODE_BASE)));
        assert_eq!(rest, &input[1..]);
    }

    #[test]
    fn test_parse_unknown_standard_opcode_one_arg() {
        let input = [OPCODE_BASE, 1, 2, 3];
        let mut standard_opcode_lengths = Vec::new();
        let mut header = make_test_header(&input);
        standard_opcode_lengths.extend(header.standard_opcode_lengths);
        standard_opcode_lengths.push(1);
        header.opcode_base += 1;
        header.standard_opcode_lengths = &standard_opcode_lengths;

        let (rest, opcode) = Opcode::parse(&header, &input).expect("Should parse the opcode OK");

        assert_eq!(opcode,
                   Opcode::UnknownStandard1(constants::DwLns(OPCODE_BASE), 1));
        assert_eq!(rest, &input[2..]);
    }

    #[test]
    fn test_parse_unknown_standard_opcode_many_args() {
        let input = [OPCODE_BASE, 1, 2, 3];
        let mut standard_opcode_lengths = Vec::new();
        let mut header = make_test_header(&input);
        standard_opcode_lengths.extend(header.standard_opcode_lengths);
        standard_opcode_lengths.push(3);
        header.opcode_base += 1;
        header.standard_opcode_lengths = &standard_opcode_lengths;

        let (rest, opcode) = Opcode::parse(&header, &input).expect("Should parse the opcode OK");

        assert_eq!(opcode,
                   Opcode::UnknownStandardN(constants::DwLns(OPCODE_BASE), vec![1, 2, 3]));
        assert_eq!(rest, &[]);
    }

    #[test]
    fn test_parse_extended_opcodes() {
        fn test<Operands>(raw: constants::DwLne, operands: Operands, expected: Opcode)
            where Operands: AsRef<[u8]>
        {
            let mut input = Vec::new();
            input.push(0);

            let operands = operands.as_ref();
            input.push(1 + operands.len() as u8);

            input.push(raw.0);
            input.extend_from_slice(operands);

            let expected_rest = [0, 1, 2, 3, 4];
            input.extend_from_slice(&expected_rest);

            let header = make_test_header(&input);

            let (rest, opcode) = Opcode::parse(&header, &input)
                .expect("Should parse the opcode OK");

            assert_eq!(opcode, expected);
            assert_eq!(rest, &expected_rest);
        }

        test(constants::DW_LNE_end_sequence, [], Opcode::EndSequence);
        test(constants::DW_LNE_set_address,
             [1, 2, 3, 4, 5, 6, 7, 8],
             Opcode::SetAddress(578437695752307201));
        test(constants::DW_LNE_set_discriminator,
             [42],
             Opcode::SetDiscriminator(42));

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

        test(constants::DW_LNE_define_file,
             file,
             Opcode::DefineFile(FileEntry {
                 path_name: ffi::CStr::from_bytes_with_nul(&path_name).unwrap(),
                 directory_index: 0,
                 last_modification: 1,
                 length: 2,
             }));

        // Unknown extended opcode.
        let operands = [1, 2, 3, 4, 5, 6];
        let opcode = constants::DwLne(99);
        test(opcode, operands, Opcode::UnknownExtended(opcode, &operands));
    }

    #[test]
    fn test_file_entry_directory() {
        let path_name = [b'f', b'o', b'o', b'.', b'r', b's', 0];

        let mut file = FileEntry {
            path_name: ffi::CStr::from_bytes_with_nul(&path_name).unwrap(),
            directory_index: 1,
            last_modification: 0,
            length: 0,
        };

        let buf = [b'd', b'i', b'r', 0];
        let mut header = make_test_header(&buf[..0]);

        let dir = ffi::CStr::from_bytes_with_nul(&buf).unwrap();
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

    fn assert_exec_opcode(header: LineNumberProgramHeader<LittleEndian>,
                          initial_registers: StateMachineRegisters,
                          opcode: Opcode,
                          expected_registers: StateMachineRegisters,
                          expect_new_row: bool) {
        let mut sm = StateMachine::new(header);
        sm.registers = initial_registers;

        let is_new_row = sm.execute(opcode);

        assert_eq!(is_new_row, expect_new_row);
        assert_eq!(sm.registers, expected_registers);
    }

    #[test]
    fn test_exec_special_noop() {
        let header = make_test_header(&[]);

        let initial_registers = new_registers();
        let opcode = Opcode::Special(16);
        let expected_registers = initial_registers.clone();

        assert_exec_opcode(header, initial_registers, opcode, expected_registers, true);
    }

    #[test]
    fn test_exec_special_negative_line_advance() {
        let header = make_test_header(&[]);

        let mut initial_registers = new_registers();
        initial_registers.line = 10;

        let opcode = Opcode::Special(13);

        let mut expected_registers = initial_registers.clone();
        expected_registers.line -= 3;

        assert_exec_opcode(header, initial_registers, opcode, expected_registers, true);
    }

    #[test]
    fn test_exec_special_positive_line_advance() {
        let header = make_test_header(&[]);

        let initial_registers = new_registers();

        let opcode = Opcode::Special(19);

        let mut expected_registers = initial_registers.clone();
        expected_registers.line += 3;

        assert_exec_opcode(header, initial_registers, opcode, expected_registers, true);
    }

    #[test]
    fn test_exec_special_positive_address_advance() {
        let header = make_test_header(&[]);

        let initial_registers = new_registers();

        let opcode = Opcode::Special(52);

        let mut expected_registers = initial_registers.clone();
        expected_registers.address += 3;

        assert_exec_opcode(header, initial_registers, opcode, expected_registers, true);
    }

    #[test]
    fn test_exec_special_positive_address_and_line_advance() {
        let header = make_test_header(&[]);

        let initial_registers = new_registers();

        let opcode = Opcode::Special(55);

        let mut expected_registers = initial_registers.clone();
        expected_registers.address += 3;
        expected_registers.line += 3;

        assert_exec_opcode(header, initial_registers, opcode, expected_registers, true);
    }

    #[test]
    fn test_exec_special_positive_address_and_negative_line_advance() {
        let header = make_test_header(&[]);

        let mut initial_registers = new_registers();
        initial_registers.line = 10;

        let opcode = Opcode::Special(49);

        let mut expected_registers = initial_registers.clone();
        expected_registers.address += 3;
        expected_registers.line -= 3;

        assert_exec_opcode(header, initial_registers, opcode, expected_registers, true);
    }

    #[test]
    fn test_exec_special_line_underflow() {
        let header = make_test_header(&[]);

        let mut initial_registers = new_registers();
        initial_registers.line = 2;

        // -3 line advance.
        let opcode = Opcode::Special(13);

        let mut expected_registers = initial_registers.clone();
        // Clamp at 0. No idea if this is the best way to handle this situation
        // or not...
        expected_registers.line = 0;

        assert_exec_opcode(header, initial_registers, opcode, expected_registers, true);
    }
}
