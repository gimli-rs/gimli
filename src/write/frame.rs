use crate::vec::Vec;

use crate::common::Register;
use crate::constants;
use crate::write::{Address, Error, Expression, Result, Writer};

/// A call frame instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallFrameInstruction {
    // 6.4.2.1 Row Creation Methods
    /// > 1. DW_CFA_set_loc
    /// >
    /// > The DW_CFA_set_loc instruction takes a single operand that represents
    /// > a target address. The required action is to create a new table row
    /// > using the specified address as the location. All other values in the
    /// > new row are initially identical to the current row. The new location
    /// > value is always greater than the current one. If the segment_size
    /// > field of this FDE's CIE is non- zero, the initial location is preceded
    /// > by a segment selector of the given length.
    SetLoc {
        /// The target address.
        address: Address,
    },

    /// The `AdvanceLoc` instruction is used for all of `DW_CFA_advance_loc` and
    /// `DW_CFA_advance_loc{1,2,4}`.
    ///
    /// > 2. DW_CFA_advance_loc
    /// >
    /// > The DW_CFA_advance instruction takes a single operand (encoded with
    /// > the opcode) that represents a constant delta. The required action is
    /// > to create a new table row with a location value that is computed by
    /// > taking the current entry’s location value and adding the value of
    /// > delta * code_alignment_factor. All other values in the new row are
    /// > initially identical to the current row.
    AdvanceLoc {
        /// The delta to be added to the current address.
        delta: u32,
    },

    // 6.4.2.2 CFA Definition Methods
    /// > 1. DW_CFA_def_cfa
    /// >
    /// > The DW_CFA_def_cfa instruction takes two unsigned LEB128 operands
    /// > representing a register number and a (non-factored) offset. The
    /// > required action is to define the current CFA rule to use the provided
    /// > register and offset.
    DefCfa {
        /// The target register's number.
        register: Register,
        /// The non-factored offset.
        offset: u64,
    },

    /// > 2. DW_CFA_def_cfa_sf
    /// >
    /// > The DW_CFA_def_cfa_sf instruction takes two operands: an unsigned
    /// > LEB128 value representing a register number and a signed LEB128
    /// > factored offset. This instruction is identical to DW_CFA_def_cfa
    /// > except that the second operand is signed and factored. The resulting
    /// > offset is factored_offset * data_alignment_factor.
    DefCfaSf {
        /// The target register's number.
        register: Register,
        /// The factored offset.
        factored_offset: i64,
    },

    /// > 3. DW_CFA_def_cfa_register
    /// >
    /// > The DW_CFA_def_cfa_register instruction takes a single unsigned LEB128
    /// > operand representing a register number. The required action is to
    /// > define the current CFA rule to use the provided register (but to keep
    /// > the old offset). This operation is valid only if the current CFA rule
    /// > is defined to use a register and offset.
    DefCfaRegister {
        /// The target register's number.
        register: Register,
    },

    /// > 4. DW_CFA_def_cfa_offset
    /// >
    /// > The DW_CFA_def_cfa_offset instruction takes a single unsigned LEB128
    /// > operand representing a (non-factored) offset. The required action is
    /// > to define the current CFA rule to use the provided offset (but to keep
    /// > the old register). This operation is valid only if the current CFA
    /// > rule is defined to use a register and offset.
    DefCfaOffset {
        /// The non-factored offset.
        offset: u64,
    },

    /// > 5. DW_CFA_def_cfa_offset_sf
    /// >
    /// > The DW_CFA_def_cfa_offset_sf instruction takes a signed LEB128 operand
    /// > representing a factored offset. This instruction is identical to
    /// > DW_CFA_def_cfa_offset except that the operand is signed and
    /// > factored. The resulting offset is factored_offset *
    /// > data_alignment_factor. This operation is valid only if the current CFA
    /// > rule is defined to use a register and offset.
    DefCfaOffsetSf {
        /// The factored offset.
        factored_offset: i64,
    },

    /// > 6. DW_CFA_def_cfa_expression
    /// >
    /// > The DW_CFA_def_cfa_expression instruction takes a single operand
    /// > encoded as a DW_FORM_exprloc value representing a DWARF
    /// > expression. The required action is to establish that expression as the
    /// > means by which the current CFA is computed.
    DefCfaExpression {
        /// The DWARF expression.
        expression: Expression,
    },

    // 6.4.2.3 Register Rule Instructions
    /// > 1. DW_CFA_undefined
    /// >
    /// > The DW_CFA_undefined instruction takes a single unsigned LEB128
    /// > operand that represents a register number. The required action is to
    /// > set the rule for the specified register to “undefined.”
    Undefined {
        /// The target register's number.
        register: Register,
    },

    /// > 2. DW_CFA_same_value
    /// >
    /// > The DW_CFA_same_value instruction takes a single unsigned LEB128
    /// > operand that represents a register number. The required action is to
    /// > set the rule for the specified register to “same value.”
    SameValue {
        /// The target register's number.
        register: Register,
    },

    /// The `Offset` instruction represents both `DW_CFA_offset` and
    /// `DW_CFA_offset_extended`.
    ///
    /// > 3. DW_CFA_offset
    /// >
    /// > The DW_CFA_offset instruction takes two operands: a register number
    /// > (encoded with the opcode) and an unsigned LEB128 constant representing
    /// > a factored offset. The required action is to change the rule for the
    /// > register indicated by the register number to be an offset(N) rule
    /// > where the value of N is factored offset * data_alignment_factor.
    Offset {
        /// The target register's number.
        register: Register,
        /// The factored offset.
        factored_offset: u64,
    },

    /// > 5. DW_CFA_offset_extended_sf
    /// >
    /// > The DW_CFA_offset_extended_sf instruction takes two operands: an
    /// > unsigned LEB128 value representing a register number and a signed
    /// > LEB128 factored offset. This instruction is identical to
    /// > DW_CFA_offset_extended except that the second operand is signed and
    /// > factored. The resulting offset is factored_offset *
    /// > data_alignment_factor.
    OffsetExtendedSf {
        /// The target register's number.
        register: Register,
        /// The factored offset.
        factored_offset: i64,
    },

    /// > 6. DW_CFA_val_offset
    /// >
    /// > The DW_CFA_val_offset instruction takes two unsigned LEB128 operands
    /// > representing a register number and a factored offset. The required
    /// > action is to change the rule for the register indicated by the
    /// > register number to be a val_offset(N) rule where the value of N is
    /// > factored_offset * data_alignment_factor.
    ValOffset {
        /// The target register's number.
        register: Register,
        /// The factored offset.
        factored_offset: u64,
    },

    /// > 7. DW_CFA_val_offset_sf
    /// >
    /// > The DW_CFA_val_offset_sf instruction takes two operands: an unsigned
    /// > LEB128 value representing a register number and a signed LEB128
    /// > factored offset. This instruction is identical to DW_CFA_val_offset
    /// > except that the second operand is signed and factored. The resulting
    /// > offset is factored_offset * data_alignment_factor.
    ValOffsetSf {
        /// The target register's number.
        register: Register,
        /// The factored offset.
        factored_offset: i64,
    },

    /// > 8. DW_CFA_register
    /// >
    /// > The DW_CFA_register instruction takes two unsigned LEB128 operands
    /// > representing register numbers. The required action is to set the rule
    /// > for the first register to be register(R) where R is the second
    /// > register.
    Register {
        /// The number of the register whose rule is being changed.
        dest_register: Register,
        /// The number of the register where the other register's value can be
        /// found.
        src_register: Register,
    },

    /// > 9. DW_CFA_expression
    /// >
    /// > The DW_CFA_expression instruction takes two operands: an unsigned
    /// > LEB128 value representing a register number, and a DW_FORM_block value
    /// > representing a DWARF expression. The required action is to change the
    /// > rule for the register indicated by the register number to be an
    /// > expression(E) rule where E is the DWARF expression. That is, the DWARF
    /// > expression computes the address. The value of the CFA is pushed on the
    /// > DWARF evaluation stack prior to execution of the DWARF expression.
    Expression {
        /// The target register's number.
        register: Register,
        /// The DWARF expression.
        expression: Expression,
    },

    /// > 10. DW_CFA_val_expression
    /// >
    /// > The DW_CFA_val_expression instruction takes two operands: an unsigned
    /// > LEB128 value representing a register number, and a DW_FORM_block value
    /// > representing a DWARF expression. The required action is to change the
    /// > rule for the register indicated by the register number to be a
    /// > val_expression(E) rule where E is the DWARF expression. That is, the
    /// > DWARF expression computes the value of the given register. The value
    /// > of the CFA is pushed on the DWARF evaluation stack prior to execution
    /// > of the DWARF expression.
    ValExpression {
        /// The target register's number.
        register: Register,
        /// The DWARF expression.
        expression: Expression,
    },

    /// The `Restore` instruction represents both `DW_CFA_restore` and
    /// `DW_CFA_restore_extended`.
    ///
    /// > 11. DW_CFA_restore
    /// >
    /// > The DW_CFA_restore instruction takes a single operand (encoded with
    /// > the opcode) that represents a register number. The required action is
    /// > to change the rule for the indicated register to the rule assigned it
    /// > by the initial_instructions in the CIE.
    Restore {
        /// The register to be reset.
        register: Register,
    },

    // 6.4.2.4 Row State Instructions
    /// > 1. DW_CFA_remember_state
    /// >
    /// > The DW_CFA_remember_state instruction takes no operands. The required
    /// > action is to push the set of rules for every register onto an implicit
    /// > stack.
    RememberState,

    /// > 2. DW_CFA_restore_state
    /// >
    /// > The DW_CFA_restore_state instruction takes no operands. The required
    /// > action is to pop the set of rules off the implicit stack and place
    /// > them in the current row.
    RestoreState,

    /// > DW_CFA_GNU_args_size
    /// >
    /// > GNU Extension
    /// >
    /// > The DW_CFA_GNU_args_size instruction takes an unsigned LEB128 operand
    /// > representing an argument size. This instruction specifies the total of
    /// > the size of the arguments which have been pushed onto the stack.
    ArgsSize {
        /// The size of the arguments which have been pushed onto the stack
        size: u64,
    },

    // 6.4.2.5 Padding Instruction
    /// > 1. DW_CFA_nop
    /// >
    /// > The DW_CFA_nop instruction has no operands and no required actions. It
    /// > is used as padding to make a CIE or FDE an appropriate size.
    Nop,
}

impl CallFrameInstruction {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<()> {
        match *self {
            CallFrameInstruction::AdvanceLoc { delta } => {
                assert!(delta < 0x40);
                writer.write_u8(constants::DW_CFA_advance_loc.0 | delta as u8)?;
            }
            CallFrameInstruction::DefCfa { register, offset } => {
                writer.write_u8(constants::DW_CFA_def_cfa.0)?;
                writer.write_uleb128(register.0 as u64)?;
                writer.write_uleb128(offset)?;
            }
            CallFrameInstruction::DefCfaRegister { register } => {
                writer.write_u8(constants::DW_CFA_def_cfa_register.0)?;
                writer.write_uleb128(register.0 as u64)?;
            }
            CallFrameInstruction::DefCfaOffset { offset } => {
                writer.write_u8(constants::DW_CFA_def_cfa_offset.0)?;
                writer.write_uleb128(offset)?;
            }
            CallFrameInstruction::Offset {
                register,
                factored_offset,
            } => {
                assert!(register.0 < 0x40);
                writer.write_u8(constants::DW_CFA_offset.0 | register.0 as u8)?;
                writer.write_uleb128(factored_offset)?;
            }
            _ => unimplemented!(),
        }
        Ok(())
    }
}

fn pad_with_nop<W: Writer>(writer: &mut W, len: usize, align: u8) -> Result<()> {
    let tail_len = (!len + 1) & (align as usize - 1);
    for _ in 0..tail_len {
        writer.write_u8(constants::DW_CFA_nop.0)?;
    }
    Ok(())
}

/// A `FrameDescriptionEntry` is a set of CFA instructions for an address range.
#[derive(Debug)]
pub struct FrameDescriptionEntry {
    /// > The address of the first location associated with this table entry.
    pub initial_location: Address,

    /// "The number of bytes of program instructions described by this entry."
    pub address_range: u64,

    instructions: Vec<CallFrameInstruction>,
}

impl FrameDescriptionEntry {
    /// Creates `FrameDescriptionEntry`.
    pub fn new() -> Self {
        FrameDescriptionEntry {
            initial_location: Address::Absolute(0),
            address_range: 0,
            instructions: Vec::new(),
        }
    }

    /// Appends `CallFrameInstruction` to the list of FDE instructions.
    pub fn add_instruction(&mut self, instr: CallFrameInstruction) {
        self.instructions.push(instr);
    }

    fn write<W: Writer>(&self, writer: &mut W, cie_ptr: u32, address_size: u8) -> Result<()> {
        // Write FDE, patch len at the end
        let pos = writer.len();
        writer.write_u32(0)?;

        writer.write_u32(cie_ptr)?;

        writer.write_address(self.initial_location, address_size)?;
        writer.write_word(self.address_range, address_size)?;

        for instr in self.instructions.iter() {
            instr.write(writer)?;
        }

        let entry_len = writer.len() - pos;
        pad_with_nop(writer, entry_len, address_size)?;

        let entry_len = (writer.len() - pos) as u32;
        writer.write_u32_at(pos, entry_len - ::std::mem::size_of::<u32>() as u32)?;

        Ok(())
    }
}

/// > A Common Information Entry holds information that is shared among many
/// > Frame Description Entries.
#[derive(Debug)]
pub struct CommonInformationEntry {
    /// > A version number (see Section 7.23). This number is specific to the
    /// > call frame information and is independent of the DWARF version number.
    pub version: u8,

    /// The parsed augmentation, if any.
    pub aug: &'static str,

    /// > The size of a target address in this CIE and any FDEs that use it, in
    /// > bytes. If a compilation unit exists for this frame, its address size
    /// > must match the address size here.
    pub address_size: u8,

    /// "The size of a segment selector in this CIE and any FDEs that use it, in
    /// bytes."
    pub segment_selector_size: u8,

    /// "A constant that is factored out of all advance location instructions
    /// (see Section 6.4.2.1)."
    pub code_alignment_factor: u64,

    /// > A constant that is factored out of certain offset instructions (see
    /// > below). The resulting value is (operand * data_alignment_factor).
    pub data_alignment_factor: i64,

    /// > Represents the return address of the function. Note that this
    /// > column might not correspond to an actual machine register.
    pub return_address_register: Register,

    aug_data: Vec<u8>,

    initial_instructions: Vec<CallFrameInstruction>,

    fde_entries: Vec<FrameDescriptionEntry>,
}

/// > A Common Information Entry holds information that is shared among many
/// > Frame Description Entries.
impl CommonInformationEntry {
    /// Creates `CommonInformationEntry`.
    pub fn new() -> Self {
        CommonInformationEntry {
            version: 4,
            aug: "",
            address_size: 0,
            segment_selector_size: 0,
            code_alignment_factor: 0,
            data_alignment_factor: 0,
            return_address_register: Register(0),
            aug_data: Vec::new(),
            initial_instructions: Vec::new(),
            fde_entries: Vec::new(),
        }
    }

    /// Appends `CallFrameInstruction` to the list of the initial instructions.
    pub fn add_initial_instruction(&mut self, instr: CallFrameInstruction) {
        self.initial_instructions.push(instr);
    }

    /// Appends `FrameDescriptionEntry` to the list of the FDEs that are
    /// associated with this CIE.
    pub fn add_fde_entry(&mut self, fde: FrameDescriptionEntry) {
        self.fde_entries.push(fde);
    }

    /// Write the CIE and its FDEs.
    pub fn write<W: Writer>(&self, writer: &mut W) -> Result<()> {
        // Write CIE, patch len at the end
        let pos = writer.len();
        writer.write_u32(0)?;

        const CIE_ID: u32 = 0xffff_ffff;
        writer.write_u32(CIE_ID)?;

        if self.version != 4 {
            return Err(Error::Unsupported("only version 4 of CIE supported"));
        }
        writer.write_u8(self.version)?;

        if self.aug.len() != 0 {
            return Err(Error::Unsupported("augumentation of CIE is unsupported"));
        }
        writer.write_u8(/* augumentation: utf8z = [0] */ 0x00)?;

        if self.address_size != 4 && self.address_size != 8 {
            return Err(Error::UnsupportedWordSize(self.address_size));
        }
        writer.write_u8(self.address_size)?;

        if self.segment_selector_size != 0 {
            return Err(Error::Unsupported(
                "segment_selector_size of CIE is unsupported",
            ));
        }
        writer.write_u8(self.segment_selector_size)?;

        writer.write_uleb128(self.code_alignment_factor)?;
        writer.write_sleb128(self.data_alignment_factor)?;
        writer.write_uleb128(self.return_address_register.0.into())?;

        if self.aug.len() > 0 {
            writer.write(&self.aug_data)?;
        }

        for instr in self.initial_instructions.iter() {
            instr.write(writer)?;
        }

        let entry_len = writer.len() - pos;
        pad_with_nop(writer, entry_len, self.address_size)?;

        let entry_len = (writer.len() - pos) as u32;
        writer.write_u32_at(pos, entry_len - ::std::mem::size_of::<u32>() as u32)?;

        let cie_ptr = pos as u32;
        for fde in self.fde_entries.iter() {
            fde.write(writer, cie_ptr, self.address_size)?;
        }
        Ok(())
    }
}
