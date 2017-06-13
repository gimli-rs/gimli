//! Functions for parsing and evaluating DWARF expressions.

use constants;
use parser::{Error, Format, parse_u8e, parse_i8e, parse_u16, parse_i16, parse_u32, parse_i32,
             parse_u64, parse_i64, parse_unsigned_lebe, parse_signed_lebe, parse_offset,
             parse_address, parse_length_uleb_value};
use endianity::{Endianity, EndianBuf};
use unit::{UnitOffset, DebugInfoOffset};
use std::marker::PhantomData;

/// A reference to a DIE, either relative to the current CU or
/// relative to the section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DieReference {
    /// A CU-relative reference.
    UnitRef(UnitOffset),
    /// A section-relative reference.
    DebugInfoRef(DebugInfoOffset),
}

/// A single decoded DWARF expression operation.
///
/// DWARF expression evaluation is done in two parts: first the raw
/// bytes of the next part of the expression are decoded; and then the
/// decoded operation is evaluated.  This approach lets other
/// consumers inspect the DWARF expression without reimplementing the
/// decoding operation.
///
/// Multiple DWARF opcodes may decode into a single `Operation`.  For
/// example, both `DW_OP_deref` and `DW_OP_xderef` are represented
/// using `Operation::Deref`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation<'input, Endian>
    where Endian: Endianity
{
    /// A dereference operation.
    Deref {
        /// The size of the data to dereference.
        size: u8,
        /// True if the dereference operation takes an address space
        /// argument; false otherwise.
        space: bool,
    },
    /// Drop an item from the stack.
    Drop,
    /// Pick an item from the stack and push it on top of the stack.
    /// This operation handles `DW_OP_pick`, `DW_OP_dup`, and
    /// `DW_OP_over`.
    Pick {
        /// The index, from the top of the stack, of the item to copy.
        index: u8,
    },
    /// Swap the top two stack items.
    Swap,
    /// Rotate the top three stack items.
    Rot,
    /// Take the absolute value of the top of the stack.
    Abs,
    /// Bitwise `and` of the top two values on the stack.
    And,
    /// Divide the top two values on the stack.
    Div,
    /// Subtract the top two values on the stack.
    Minus,
    /// Modulus of the top two values on the stack.
    Mod,
    /// Multiply the top two values on the stack.
    Mul,
    /// Negate the top of the stack.
    Neg,
    /// Bitwise `not` of the top of the stack.
    Not,
    /// Bitwise `or` of the top two values on the stack.
    Or,
    /// Add the top two values on the stack.
    Plus,
    /// Add a constant to the topmost value on the stack.
    PlusConstant {
        /// The value to add.
        value: u64,
    },
    /// Logical left shift of the 2nd value on the stack by the number
    /// of bits given by the topmost value on the stack.
    Shl,
    /// Right shift of the 2nd value on the stack by the number of
    /// bits given by the topmost value on the stack.
    Shr,
    /// Arithmetic left shift of the 2nd value on the stack by the
    /// number of bits given by the topmost value on the stack.
    Shra,
    /// Bitwise `xor` of the top two values on the stack.
    Xor,
    /// Branch to the target location if the top of stack is nonzero.
    Bra {
        /// The target bytecode.
        target: EndianBuf<'input, Endian>,
    },
    /// Compare the top two stack values for equality.
    Eq,
    /// Compare the top two stack values using `>=`.
    Ge,
    /// Compare the top two stack values using `>`.
    Gt,
    /// Compare the top two stack values using `<=`.
    Le,
    /// Compare the top two stack values using `<`.
    Lt,
    /// Compare the top two stack values using `!=`.
    Ne,
    /// Unconditional branch to the target location.
    Skip {
        /// The target bytecode.
        target: EndianBuf<'input, Endian>,
    },
    /// Push a constant value on the stack.  This handles multiple
    /// DWARF opcodes, including `DW_OP_addr`.
    Literal {
        /// The value to push.
        value: u64,
    },
    /// Indicate that this piece's location is in the given register.
    Register {
        /// The register number.
        register: u64,
    },
    /// Find the value of the given register, add the offset, and then
    /// push the resulting sum on the stack.
    RegisterOffset {
        /// The register number.
        register: u64,
        /// The offset to add.
        offset: i64,
    },
    /// Compute the frame base (using `DW_AT_frame_base`), add the
    /// given offset, and then push the resulting sum on the stack.
    FrameOffset {
        /// The offset to add.
        offset: i64,
    },
    /// No operation.
    Nop,
    /// Push the object address on the stack.
    PushObjectAddress,
    /// Evaluate a DWARF expression as a subroutine.  The expression
    /// comes from the `DW_AT_location` attribute of the indicated
    /// DIE.
    Call {
        /// The DIE to use.
        offset: DieReference,
    },
    /// Compute the address of a thread-local variable and push it on
    /// the stack.
    TLS,
    /// Compute the call frame CFA and push it on the stack.
    CallFrameCFA,
    /// Terminate a piece.
    Piece {
        /// The size of this piece in bits.
        size_in_bits: u64,
        /// The bit offset of this piece.  If `None`, then this piece
        /// was specified using `DW_OP_piece` and should start at the
        /// next byte boundary.
        bit_offset: Option<u64>,
    },
    /// Represents `DW_OP_implicit_value`.
    ImplicitValue {
        /// The implicit value to use.
        data: &'input [u8],
    },
    /// Represents `DW_OP_stack_value`.
    StackValue,
    /// Represents `DW_OP_implicit_pointer`. The object is a pointer to
    /// a value which has no actual location, such as an implicit value or
    /// a stack value.
    ImplicitPointer {
        /// The `.debug_info` offset of the value that this is an implicit pointer into.
        value: DebugInfoOffset,
        /// The byte offset into the value that the implicit pointer points to.
        byte_offset: i64,
    },
    /// Represents `DW_OP_entry_value`. Evaluate an expression at the entry to
    /// the current subprogram, and push it on the stack.
    EntryValue {
        /// The expression to be evaluated.
        expression: EndianBuf<'input, Endian>,
    },
}

#[derive(Debug)]
enum OperationEvaluationResult<'input, Endian>
    where Endian: Endianity
{
    Complete {
        terminated: bool,
        piece_end: bool,
        current_location: Location<'input>,
    },
    AwaitingMemory {
        address: u64,
        size: u8,
        space: Option<u64>,
    },
    AwaitingRegister { register: u64, offset: u64 },
    AwaitingFrameBase { offset: u64 },
    AwaitingTls { index: u64 },
    AwaitingCfa,
    AwaitingAtLocation { location: DieReference },
    AwaitingEntryValue { expression: EndianBuf<'input, Endian>, },
}

/// A single location of a piece of the result of a DWARF expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Location<'input> {
    /// The piece is empty.  Ordinarily this means the piece has been
    /// optimized away.
    Empty,
    /// The piece is found in a register.
    Register {
        /// The register number.
        register: u64,
    },
    /// The piece is found in memory.
    Address {
        /// The address.
        address: u64,
    },
    /// The piece is a scalar value.
    Scalar {
        /// The value.
        value: u64,
    },
    /// The piece is represented by some constant bytes.
    Bytes {
        /// The value.
        value: &'input [u8],
    },
    /// The piece is a pointer to a value which has no actual location.
    ImplicitPointer {
        /// The `.debug_info` offset of the value that this is an implicit pointer into.
        value: DebugInfoOffset,
        /// The byte offset into the value that the implicit pointer points to.
        byte_offset: i64,
    },
}

/// The description of a single piece of the result of a DWARF
/// expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Piece<'input> {
    /// If given, the size of the piece in bits.  If `None`, then the
    /// piece takes its size from the enclosed location.
    pub size_in_bits: Option<u64>,
    /// If given, the bit offset of the piece.  If `None`, then the
    /// piece starts at the next byte boundary.
    pub bit_offset: Option<u64>,
    /// Where this piece is to be found.
    pub location: Location<'input>,
}

// A helper function to handle branch offsets.
fn compute_pc<'input, Endian>(pc: EndianBuf<'input, Endian>,
                              bytecode: EndianBuf<'input, Endian>,
                              offset: i16)
                              -> Result<EndianBuf<'input, Endian>, Error>
    where Endian: Endianity + 'input
{
    let this_len = pc.len();
    let full_len = bytecode.len();
    let new_pc = (full_len - this_len).wrapping_add(offset as usize);
    if new_pc > full_len {
        Err(Error::BadBranchTarget(new_pc))
    } else {
        Ok(bytecode.range_from(new_pc..))
    }
}

impl<'input, Endian> Operation<'input, Endian>
    where Endian: Endianity + 'input
{
    /// Parse a single DWARF expression operation.
    ///
    /// This is useful when examining a DWARF expression for reasons other
    /// than direct evaluation.
    ///
    /// `bytes` points to a the operation to decode.  It should point into
    /// the same array as `bytecode`, which should be the entire
    /// expression.
    pub fn parse(bytes: EndianBuf<'input, Endian>,
                 bytecode: EndianBuf<'input, Endian>,
                 address_size: u8,
                 format: Format)
                 -> Result<(EndianBuf<'input, Endian>, Operation<'input, Endian>), Error>
        where Endian: Endianity
    {
        let (bytes, opcode) = try!(parse_u8e(bytes));
        let name = constants::DwOp(opcode);
        match name {
            constants::DW_OP_addr => {
                let (newbytes, value) = try!(parse_address(bytes, address_size));
                Ok((newbytes, Operation::Literal { value: value }))
            }
            constants::DW_OP_deref => {
                Ok((bytes,
                    Operation::Deref {
                        size: address_size,
                        space: false,
                    }))
            }
            constants::DW_OP_const1u => {
                let (newbytes, value) = try!(parse_u8e(bytes));
                Ok((newbytes, Operation::Literal { value: value as u64 }))
            }
            constants::DW_OP_const1s => {
                let (newbytes, value) = try!(parse_i8e(bytes));
                Ok((newbytes, Operation::Literal { value: value as u64 }))
            }
            constants::DW_OP_const2u => {
                let (newbytes, value) = try!(parse_u16(bytes));
                Ok((newbytes, Operation::Literal { value: value as u64 }))
            }
            constants::DW_OP_const2s => {
                let (newbytes, value) = try!(parse_i16(bytes));
                Ok((newbytes, Operation::Literal { value: value as u64 }))
            }
            constants::DW_OP_const4u => {
                let (newbytes, value) = try!(parse_u32(bytes));
                Ok((newbytes, Operation::Literal { value: value as u64 }))
            }
            constants::DW_OP_const4s => {
                let (newbytes, value) = try!(parse_i32(bytes));
                Ok((newbytes, Operation::Literal { value: value as u64 }))
            }
            constants::DW_OP_const8u => {
                let (newbytes, value) = try!(parse_u64(bytes));
                Ok((newbytes, Operation::Literal { value: value }))
            }
            constants::DW_OP_const8s => {
                let (newbytes, value) = try!(parse_i64(bytes));
                Ok((newbytes, Operation::Literal { value: value as u64 }))
            }
            constants::DW_OP_constu => {
                let (newbytes, value) = try!(parse_unsigned_lebe(bytes));
                Ok((newbytes, Operation::Literal { value: value }))
            }
            constants::DW_OP_consts => {
                let (newbytes, value) = try!(parse_signed_lebe(bytes));
                Ok((newbytes, Operation::Literal { value: value as u64 }))
            }
            constants::DW_OP_dup => Ok((bytes, Operation::Pick { index: 0 })),
            constants::DW_OP_drop => Ok((bytes, Operation::Drop)),
            constants::DW_OP_over => Ok((bytes, Operation::Pick { index: 1 })),
            constants::DW_OP_pick => {
                let (newbytes, value) = try!(parse_u8e(bytes));
                Ok((newbytes, Operation::Pick { index: value }))
            }
            constants::DW_OP_swap => Ok((bytes, Operation::Swap)),
            constants::DW_OP_rot => Ok((bytes, Operation::Rot)),
            constants::DW_OP_xderef => {
                Ok((bytes,
                    Operation::Deref {
                        size: address_size,
                        space: true,
                    }))
            }
            constants::DW_OP_abs => Ok((bytes, Operation::Abs)),
            constants::DW_OP_and => Ok((bytes, Operation::And)),
            constants::DW_OP_div => Ok((bytes, Operation::Div)),
            constants::DW_OP_minus => Ok((bytes, Operation::Minus)),
            constants::DW_OP_mod => Ok((bytes, Operation::Mod)),
            constants::DW_OP_mul => Ok((bytes, Operation::Mul)),
            constants::DW_OP_neg => Ok((bytes, Operation::Neg)),
            constants::DW_OP_not => Ok((bytes, Operation::Not)),
            constants::DW_OP_or => Ok((bytes, Operation::Or)),
            constants::DW_OP_plus => Ok((bytes, Operation::Plus)),
            constants::DW_OP_plus_uconst => {
                let (newbytes, value) = try!(parse_unsigned_lebe(bytes));
                Ok((newbytes, Operation::PlusConstant { value: value }))
            }
            constants::DW_OP_shl => Ok((bytes, Operation::Shl)),
            constants::DW_OP_shr => Ok((bytes, Operation::Shr)),
            constants::DW_OP_shra => Ok((bytes, Operation::Shra)),
            constants::DW_OP_xor => Ok((bytes, Operation::Xor)),
            constants::DW_OP_bra => {
                let (newbytes, value) = try!(parse_i16(bytes));
                Ok((newbytes,
                    Operation::Bra { target: try!(compute_pc(newbytes, bytecode, value)) }))
            }
            constants::DW_OP_eq => Ok((bytes, Operation::Eq)),
            constants::DW_OP_ge => Ok((bytes, Operation::Ge)),
            constants::DW_OP_gt => Ok((bytes, Operation::Gt)),
            constants::DW_OP_le => Ok((bytes, Operation::Le)),
            constants::DW_OP_lt => Ok((bytes, Operation::Lt)),
            constants::DW_OP_ne => Ok((bytes, Operation::Ne)),
            constants::DW_OP_skip => {
                let (newbytes, value) = try!(parse_i16(bytes));
                Ok((newbytes,
                    Operation::Skip { target: try!(compute_pc(newbytes, bytecode, value)) }))
            }
            constants::DW_OP_lit0 => Ok((bytes, Operation::Literal { value: 0 })),
            constants::DW_OP_lit1 => Ok((bytes, Operation::Literal { value: 1 })),
            constants::DW_OP_lit2 => Ok((bytes, Operation::Literal { value: 2 })),
            constants::DW_OP_lit3 => Ok((bytes, Operation::Literal { value: 3 })),
            constants::DW_OP_lit4 => Ok((bytes, Operation::Literal { value: 4 })),
            constants::DW_OP_lit5 => Ok((bytes, Operation::Literal { value: 5 })),
            constants::DW_OP_lit6 => Ok((bytes, Operation::Literal { value: 6 })),
            constants::DW_OP_lit7 => Ok((bytes, Operation::Literal { value: 7 })),
            constants::DW_OP_lit8 => Ok((bytes, Operation::Literal { value: 8 })),
            constants::DW_OP_lit9 => Ok((bytes, Operation::Literal { value: 9 })),
            constants::DW_OP_lit10 => Ok((bytes, Operation::Literal { value: 10 })),
            constants::DW_OP_lit11 => Ok((bytes, Operation::Literal { value: 11 })),
            constants::DW_OP_lit12 => Ok((bytes, Operation::Literal { value: 12 })),
            constants::DW_OP_lit13 => Ok((bytes, Operation::Literal { value: 13 })),
            constants::DW_OP_lit14 => Ok((bytes, Operation::Literal { value: 14 })),
            constants::DW_OP_lit15 => Ok((bytes, Operation::Literal { value: 15 })),
            constants::DW_OP_lit16 => Ok((bytes, Operation::Literal { value: 16 })),
            constants::DW_OP_lit17 => Ok((bytes, Operation::Literal { value: 17 })),
            constants::DW_OP_lit18 => Ok((bytes, Operation::Literal { value: 18 })),
            constants::DW_OP_lit19 => Ok((bytes, Operation::Literal { value: 19 })),
            constants::DW_OP_lit20 => Ok((bytes, Operation::Literal { value: 20 })),
            constants::DW_OP_lit21 => Ok((bytes, Operation::Literal { value: 21 })),
            constants::DW_OP_lit22 => Ok((bytes, Operation::Literal { value: 22 })),
            constants::DW_OP_lit23 => Ok((bytes, Operation::Literal { value: 23 })),
            constants::DW_OP_lit24 => Ok((bytes, Operation::Literal { value: 24 })),
            constants::DW_OP_lit25 => Ok((bytes, Operation::Literal { value: 25 })),
            constants::DW_OP_lit26 => Ok((bytes, Operation::Literal { value: 26 })),
            constants::DW_OP_lit27 => Ok((bytes, Operation::Literal { value: 27 })),
            constants::DW_OP_lit28 => Ok((bytes, Operation::Literal { value: 28 })),
            constants::DW_OP_lit29 => Ok((bytes, Operation::Literal { value: 29 })),
            constants::DW_OP_lit30 => Ok((bytes, Operation::Literal { value: 30 })),
            constants::DW_OP_lit31 => Ok((bytes, Operation::Literal { value: 31 })),
            constants::DW_OP_reg0 => Ok((bytes, Operation::Register { register: 0 })),
            constants::DW_OP_reg1 => Ok((bytes, Operation::Register { register: 1 })),
            constants::DW_OP_reg2 => Ok((bytes, Operation::Register { register: 2 })),
            constants::DW_OP_reg3 => Ok((bytes, Operation::Register { register: 3 })),
            constants::DW_OP_reg4 => Ok((bytes, Operation::Register { register: 4 })),
            constants::DW_OP_reg5 => Ok((bytes, Operation::Register { register: 5 })),
            constants::DW_OP_reg6 => Ok((bytes, Operation::Register { register: 6 })),
            constants::DW_OP_reg7 => Ok((bytes, Operation::Register { register: 7 })),
            constants::DW_OP_reg8 => Ok((bytes, Operation::Register { register: 8 })),
            constants::DW_OP_reg9 => Ok((bytes, Operation::Register { register: 9 })),
            constants::DW_OP_reg10 => Ok((bytes, Operation::Register { register: 10 })),
            constants::DW_OP_reg11 => Ok((bytes, Operation::Register { register: 11 })),
            constants::DW_OP_reg12 => Ok((bytes, Operation::Register { register: 12 })),
            constants::DW_OP_reg13 => Ok((bytes, Operation::Register { register: 13 })),
            constants::DW_OP_reg14 => Ok((bytes, Operation::Register { register: 14 })),
            constants::DW_OP_reg15 => Ok((bytes, Operation::Register { register: 15 })),
            constants::DW_OP_reg16 => Ok((bytes, Operation::Register { register: 16 })),
            constants::DW_OP_reg17 => Ok((bytes, Operation::Register { register: 17 })),
            constants::DW_OP_reg18 => Ok((bytes, Operation::Register { register: 18 })),
            constants::DW_OP_reg19 => Ok((bytes, Operation::Register { register: 19 })),
            constants::DW_OP_reg20 => Ok((bytes, Operation::Register { register: 20 })),
            constants::DW_OP_reg21 => Ok((bytes, Operation::Register { register: 21 })),
            constants::DW_OP_reg22 => Ok((bytes, Operation::Register { register: 22 })),
            constants::DW_OP_reg23 => Ok((bytes, Operation::Register { register: 23 })),
            constants::DW_OP_reg24 => Ok((bytes, Operation::Register { register: 24 })),
            constants::DW_OP_reg25 => Ok((bytes, Operation::Register { register: 25 })),
            constants::DW_OP_reg26 => Ok((bytes, Operation::Register { register: 26 })),
            constants::DW_OP_reg27 => Ok((bytes, Operation::Register { register: 27 })),
            constants::DW_OP_reg28 => Ok((bytes, Operation::Register { register: 28 })),
            constants::DW_OP_reg29 => Ok((bytes, Operation::Register { register: 29 })),
            constants::DW_OP_reg30 => Ok((bytes, Operation::Register { register: 30 })),
            constants::DW_OP_reg31 => Ok((bytes, Operation::Register { register: 31 })),
            constants::DW_OP_breg0 => {
                let (newbytes, value) = try!(parse_signed_lebe(bytes));
                Ok((newbytes,
                    Operation::RegisterOffset {
                        register: 0,
                        offset: value,
                    }))
            }
            constants::DW_OP_breg1 => {
                let (newbytes, value) = try!(parse_signed_lebe(bytes));
                Ok((newbytes,
                    Operation::RegisterOffset {
                        register: 1,
                        offset: value,
                    }))
            }
            constants::DW_OP_breg2 => {
                let (newbytes, value) = try!(parse_signed_lebe(bytes));
                Ok((newbytes,
                    Operation::RegisterOffset {
                        register: 2,
                        offset: value,
                    }))
            }
            constants::DW_OP_breg3 => {
                let (newbytes, value) = try!(parse_signed_lebe(bytes));
                Ok((newbytes,
                    Operation::RegisterOffset {
                        register: 3,
                        offset: value,
                    }))
            }
            constants::DW_OP_breg4 => {
                let (newbytes, value) = try!(parse_signed_lebe(bytes));
                Ok((newbytes,
                    Operation::RegisterOffset {
                        register: 4,
                        offset: value,
                    }))
            }
            constants::DW_OP_breg5 => {
                let (newbytes, value) = try!(parse_signed_lebe(bytes));
                Ok((newbytes,
                    Operation::RegisterOffset {
                        register: 5,
                        offset: value,
                    }))
            }
            constants::DW_OP_breg6 => {
                let (newbytes, value) = try!(parse_signed_lebe(bytes));
                Ok((newbytes,
                    Operation::RegisterOffset {
                        register: 6,
                        offset: value,
                    }))
            }
            constants::DW_OP_breg7 => {
                let (newbytes, value) = try!(parse_signed_lebe(bytes));
                Ok((newbytes,
                    Operation::RegisterOffset {
                        register: 7,
                        offset: value,
                    }))
            }
            constants::DW_OP_breg8 => {
                let (newbytes, value) = try!(parse_signed_lebe(bytes));
                Ok((newbytes,
                    Operation::RegisterOffset {
                        register: 8,
                        offset: value,
                    }))
            }
            constants::DW_OP_breg9 => {
                let (newbytes, value) = try!(parse_signed_lebe(bytes));
                Ok((newbytes,
                    Operation::RegisterOffset {
                        register: 9,
                        offset: value,
                    }))
            }
            constants::DW_OP_breg10 => {
                let (newbytes, value) = try!(parse_signed_lebe(bytes));
                Ok((newbytes,
                    Operation::RegisterOffset {
                        register: 10,
                        offset: value,
                    }))
            }
            constants::DW_OP_breg11 => {
                let (newbytes, value) = try!(parse_signed_lebe(bytes));
                Ok((newbytes,
                    Operation::RegisterOffset {
                        register: 11,
                        offset: value,
                    }))
            }
            constants::DW_OP_breg12 => {
                let (newbytes, value) = try!(parse_signed_lebe(bytes));
                Ok((newbytes,
                    Operation::RegisterOffset {
                        register: 12,
                        offset: value,
                    }))
            }
            constants::DW_OP_breg13 => {
                let (newbytes, value) = try!(parse_signed_lebe(bytes));
                Ok((newbytes,
                    Operation::RegisterOffset {
                        register: 13,
                        offset: value,
                    }))
            }
            constants::DW_OP_breg14 => {
                let (newbytes, value) = try!(parse_signed_lebe(bytes));
                Ok((newbytes,
                    Operation::RegisterOffset {
                        register: 14,
                        offset: value,
                    }))
            }
            constants::DW_OP_breg15 => {
                let (newbytes, value) = try!(parse_signed_lebe(bytes));
                Ok((newbytes,
                    Operation::RegisterOffset {
                        register: 15,
                        offset: value,
                    }))
            }
            constants::DW_OP_breg16 => {
                let (newbytes, value) = try!(parse_signed_lebe(bytes));
                Ok((newbytes,
                    Operation::RegisterOffset {
                        register: 16,
                        offset: value,
                    }))
            }
            constants::DW_OP_breg17 => {
                let (newbytes, value) = try!(parse_signed_lebe(bytes));
                Ok((newbytes,
                    Operation::RegisterOffset {
                        register: 17,
                        offset: value,
                    }))
            }
            constants::DW_OP_breg18 => {
                let (newbytes, value) = try!(parse_signed_lebe(bytes));
                Ok((newbytes,
                    Operation::RegisterOffset {
                        register: 18,
                        offset: value,
                    }))
            }
            constants::DW_OP_breg19 => {
                let (newbytes, value) = try!(parse_signed_lebe(bytes));
                Ok((newbytes,
                    Operation::RegisterOffset {
                        register: 19,
                        offset: value,
                    }))
            }
            constants::DW_OP_breg20 => {
                let (newbytes, value) = try!(parse_signed_lebe(bytes));
                Ok((newbytes,
                    Operation::RegisterOffset {
                        register: 20,
                        offset: value,
                    }))
            }
            constants::DW_OP_breg21 => {
                let (newbytes, value) = try!(parse_signed_lebe(bytes));
                Ok((newbytes,
                    Operation::RegisterOffset {
                        register: 21,
                        offset: value,
                    }))
            }
            constants::DW_OP_breg22 => {
                let (newbytes, value) = try!(parse_signed_lebe(bytes));
                Ok((newbytes,
                    Operation::RegisterOffset {
                        register: 22,
                        offset: value,
                    }))
            }
            constants::DW_OP_breg23 => {
                let (newbytes, value) = try!(parse_signed_lebe(bytes));
                Ok((newbytes,
                    Operation::RegisterOffset {
                        register: 23,
                        offset: value,
                    }))
            }
            constants::DW_OP_breg24 => {
                let (newbytes, value) = try!(parse_signed_lebe(bytes));
                Ok((newbytes,
                    Operation::RegisterOffset {
                        register: 24,
                        offset: value,
                    }))
            }
            constants::DW_OP_breg25 => {
                let (newbytes, value) = try!(parse_signed_lebe(bytes));
                Ok((newbytes,
                    Operation::RegisterOffset {
                        register: 25,
                        offset: value,
                    }))
            }
            constants::DW_OP_breg26 => {
                let (newbytes, value) = try!(parse_signed_lebe(bytes));
                Ok((newbytes,
                    Operation::RegisterOffset {
                        register: 26,
                        offset: value,
                    }))
            }
            constants::DW_OP_breg27 => {
                let (newbytes, value) = try!(parse_signed_lebe(bytes));
                Ok((newbytes,
                    Operation::RegisterOffset {
                        register: 27,
                        offset: value,
                    }))
            }
            constants::DW_OP_breg28 => {
                let (newbytes, value) = try!(parse_signed_lebe(bytes));
                Ok((newbytes,
                    Operation::RegisterOffset {
                        register: 28,
                        offset: value,
                    }))
            }
            constants::DW_OP_breg29 => {
                let (newbytes, value) = try!(parse_signed_lebe(bytes));
                Ok((newbytes,
                    Operation::RegisterOffset {
                        register: 29,
                        offset: value,
                    }))
            }
            constants::DW_OP_breg30 => {
                let (newbytes, value) = try!(parse_signed_lebe(bytes));
                Ok((newbytes,
                    Operation::RegisterOffset {
                        register: 30,
                        offset: value,
                    }))
            }
            constants::DW_OP_breg31 => {
                let (newbytes, value) = try!(parse_signed_lebe(bytes));
                Ok((newbytes,
                    Operation::RegisterOffset {
                        register: 31,
                        offset: value,
                    }))
            }
            constants::DW_OP_regx => {
                let (newbytes, value) = try!(parse_unsigned_lebe(bytes));
                Ok((newbytes, Operation::Register { register: value }))
            }
            constants::DW_OP_fbreg => {
                let (newbytes, value) = try!(parse_signed_lebe(bytes));
                Ok((newbytes, Operation::FrameOffset { offset: value }))
            }
            constants::DW_OP_bregx => {
                let (newbytes, regno) = try!(parse_unsigned_lebe(bytes));
                let (newbytes, offset) = try!(parse_signed_lebe(newbytes));
                Ok((newbytes,
                    Operation::RegisterOffset {
                        register: regno,
                        offset: offset,
                    }))
            }
            constants::DW_OP_piece => {
                let (newbytes, size) = try!(parse_unsigned_lebe(bytes));
                Ok((newbytes,
                    Operation::Piece {
                        size_in_bits: 8 * size,
                        bit_offset: None,
                    }))
            }
            constants::DW_OP_deref_size => {
                let (newbytes, size) = try!(parse_u8e(bytes));
                Ok((newbytes,
                    Operation::Deref {
                        size: size,
                        space: false,
                    }))
            }
            constants::DW_OP_xderef_size => {
                let (newbytes, size) = try!(parse_u8e(bytes));
                Ok((newbytes,
                    Operation::Deref {
                        size: size,
                        space: true,
                    }))
            }
            constants::DW_OP_nop => Ok((bytes, Operation::Nop)),
            constants::DW_OP_push_object_address => Ok((bytes, Operation::PushObjectAddress)),
            constants::DW_OP_call2 => {
                let (newbytes, value) = try!(parse_u16(bytes));
                Ok((newbytes,
                    Operation::Call { offset: DieReference::UnitRef(UnitOffset(value as usize)) }))
            }
            constants::DW_OP_call4 => {
                let (newbytes, value) = try!(parse_u32(bytes));
                Ok((newbytes,
                    Operation::Call { offset: DieReference::UnitRef(UnitOffset(value as usize)) }))
            }
            constants::DW_OP_call_ref => {
                let (newbytes, value) = try!(parse_offset(bytes, format));
                Ok((newbytes,
                    Operation::Call { offset: DieReference::DebugInfoRef(DebugInfoOffset(value)) }))
            }
            constants::DW_OP_form_tls_address |
            constants::DW_OP_GNU_push_tls_address => Ok((bytes, Operation::TLS)),
            constants::DW_OP_call_frame_cfa => Ok((bytes, Operation::CallFrameCFA)),
            constants::DW_OP_bit_piece => {
                let (newbytes, size) = try!(parse_unsigned_lebe(bytes));
                let (newbytes, offset) = try!(parse_unsigned_lebe(newbytes));
                Ok((newbytes,
                    Operation::Piece {
                        size_in_bits: size,
                        bit_offset: Some(offset),
                    }))
            }
            constants::DW_OP_implicit_value => {
                let (newbytes, data) = try!(parse_length_uleb_value(bytes));
                Ok((newbytes, Operation::ImplicitValue { data: data.into() }))
            }
            constants::DW_OP_stack_value => Ok((bytes, Operation::StackValue)),
            constants::DW_OP_implicit_pointer |
            constants::DW_OP_GNU_implicit_pointer => {
                let (newbytes, value) = try!(parse_offset(bytes, format));
                let (newbytes, byte_offset) = try!(parse_signed_lebe(newbytes));
                Ok((newbytes,
                    Operation::ImplicitPointer {
                        value: DebugInfoOffset(value),
                        byte_offset: byte_offset,
                    }))
            }
            constants::DW_OP_entry_value |
            constants::DW_OP_GNU_entry_value => {
                let (newbytes, expression) = try!(parse_length_uleb_value(bytes));
                Ok((newbytes, Operation::EntryValue { expression: expression }))
            }

            _ => Err(Error::InvalidExpression(name)),
        }
    }
}

#[derive(Debug)]
enum EvaluationState<'input, Endian>
    where Endian: Endianity
{
    Start(Option<u64>),
    Ready,
    Error(Error),
    Complete,
    Waiting(OperationEvaluationResult<'input, Endian>),
}

/// The state of an `Evaluation` after evaluating a DWARF expression.
/// The evaluation is either `Complete`, or it requires more data
/// to continue, as described by the variant.
#[derive(Debug, PartialEq)]
pub enum EvaluationResult<'input, Endian>
    where Endian: Endianity
{
    /// The `Evaluation` is complete, and `Evaluation::result()` can be called.
    Complete,
    /// The `Evaluation` needs a value from memory to proceed further.  Once the
    /// caller determines what value to provide it should resume the `Evaluation`
    /// by calling `Evaluation::resume_with_memory`.
    RequiresMemory {
        /// The address of the value required.
        address: u64,
        /// The size of the value required. This is guaranteed to be at most the
        /// word size of the target architecture.
        size: u8,
        /// If not `None`, a target-specific address space value.
        space: Option<u64>,
    },
    /// The `Evaluation` needs a value from a register to proceed further.  Once
    /// the caller determines what value to provide it should resume the
    /// `Evaluation` by calling `Evaluation::resume_with_register`.
    RequiresRegister(u64),
    /// The `Evaluation` needs the frame base address to proceed further.  Once
    /// the caller determines what value to provide it should resume the
    /// `Evaluation` by calling `Evaluation::resume_with_frame_base`.  The frame
    /// base address is the address produced by the location description in the
    /// `DW_AT_frame_base` attribute of the current function.
    RequiresFrameBase,
    /// The `Evaluation` needs a value from TLS to proceed further.  Once the
    /// caller determines what value to provide it should resume the
    /// `Evaluation` by calling `Evaluation::resume_with_tls`.
    RequiresTls(u64),
    /// The `Evaluation` needs the CFA to proceed further.  Once the caller
    /// determines what value to provide it should resume the `Evaluation` by
    /// calling `Evaluation::resume_with_call_frame_cfa`.
    RequiresCallFrameCfa,
    /// The `Evaluation` needs the DWARF expression at the given location to
    /// proceed further.  Once the caller determines what value to provide it
    /// should resume the `Evaluation` by calling
    /// `Evaluation::resume_with_at_location`.
    RequiresAtLocation(DieReference),
    /// The `Evaluation` needs the value produced by evaluating a DWARF
    /// expression at the entry point of the current subprogram.  Once the
    /// caller determines what value to provide it should resume the
    /// `Evaluation` by calling `Evaluation::resume_with_entry_value`.
    RequiresEntryValue(EndianBuf<'input, Endian>),
}

/// A DWARF expression evaluator.
///
/// # Usage
/// A DWARF expression may require additional data to produce a final result,
/// such as the value of a register or a memory location.  Once initial setup
/// is complete (i.e. `set_initial_value()`, `set_object_address()`) the
/// consumer calls the `evaluate()` method.  That returns an `EvaluationResult`,
/// which is either `EvaluationResult::Complete` or a value indicating what
/// data is needed to resume the `Evaluation`.  The consumer is responsible for
/// producing that data and resuming the computation with the correct method,
/// as documented for `EvaluationResult`.  Only once an `EvaluationResult::Complete`
/// is returned can the consumer call `result()`.
///
/// This design allows the consumer of `Evaluation` to decide how and when to
/// produce the required data and resume the computation.  The `Evaluation` can
/// be driven synchronously (as shown below) or by some asynchronous mechanism
/// such as futures.
///
/// # Examples
/// ```rust,no_run
/// use gimli::{EndianBuf, Evaluation, EvaluationResult, Format, LittleEndian};
/// # let bytecode = EndianBuf::<LittleEndian>::new(&[]);
/// # let address_size = 8;
/// # let format = Format::Dwarf64;
/// # let get_register_value = |_| 42;
/// # let get_frame_base = || 0xdeadbeef;
///
/// let mut eval = Evaluation::<LittleEndian>::new(bytecode, address_size, format);
/// let mut result = eval.evaluate().unwrap();
/// while result != EvaluationResult::Complete {
///   match result {
///     EvaluationResult::RequiresRegister(regno) => {
///       let value = get_register_value(regno);
///       result = eval.resume_with_register(value).unwrap();
///     },
///     EvaluationResult::RequiresFrameBase => {
///       let frame_base = get_frame_base();
///       result = eval.resume_with_frame_base(frame_base).unwrap();
///     },
///     _ => unimplemented!(),
///   };
/// }
///
/// let result = eval.result();
/// println!("{:?}", result);
/// ```
#[derive(Debug)]
pub struct Evaluation<'input, Endian>
    where Endian: Endianity + 'input
{
    bytecode: EndianBuf<'input, Endian>,
    address_size: u8,
    format: Format,
    object_address: Option<u64>,
    max_iterations: Option<u32>,
    iteration: u32,
    state: EvaluationState<'input, Endian>,

    // Stack operations are done on word-sized values.  We do all
    // operations on 64-bit values, and then mask the results
    // appropriately when popping.
    addr_mask: u64,

    // The stack.
    stack: Vec<u64>,

    // The next operation to decode and evaluate.
    pc: EndianBuf<'input, Endian>,

    // If we see a DW_OP_call* operation, the previous PC and bytecode
    // is stored here while evaluating the subroutine.
    expression_stack: Vec<(EndianBuf<'input, Endian>, EndianBuf<'input, Endian>)>,

    result: Vec<Piece<'input>>,

    phantom: PhantomData<Endian>,
}

impl<'input, Endian> Evaluation<'input, Endian>
    where Endian: Endianity
{
    /// Create a new DWARF expression evaluator.
    ///
    /// The new evaluator is created without an initial value, without
    /// an object address, and without a maximum number of iterations.
    pub fn new(bytecode: EndianBuf<'input, Endian>,
               address_size: u8,
               format: Format)
               -> Evaluation<'input, Endian> {
        Evaluation::<'input, Endian> {
            bytecode: bytecode,
            address_size: address_size,
            format: format,
            object_address: None,
            max_iterations: None,
            iteration: 0,
            state: EvaluationState::Start(None),
            addr_mask: if address_size == 8 {
                !0u64
            } else {
                (1 << (8 * address_size as u64)) - 1
            },
            stack: Vec::new(),
            expression_stack: Vec::new(),
            pc: bytecode,
            result: Vec::new(),
            phantom: PhantomData,
        }
    }

    /// Set an initial value to be pushed on the DWARF expression
    /// evaluator's stack.  This can be used in cases like
    /// `DW_AT_vtable_elem_location`, which require a value on the
    /// stack before evaluation commences.  If no initial value is
    /// set, and the expression uses an opcode requiring the initial
    /// value, then evaluation will fail with an error.
    ///
    /// # Panics
    /// Panics if `set_initial_value()` has already been called, or if
    /// `evaluate()` has already been called.
    pub fn set_initial_value(&mut self, value: u64) {
        match self.state {
            EvaluationState::Start(None) => {
                self.state = EvaluationState::Start(Some(value));
            }
            _ => {
                panic!("`Evaluation::set_initial_value` was called twice, or after evaluation began.")
            }
        };
    }

    /// Set the enclosing object's address, as used by
    /// `DW_OP_push_object_address`.  If no object address is set, and
    /// the expression uses an opcode requiring the object address,
    /// then evaluation will fail with an error.
    pub fn set_object_address(&mut self, value: u64) {
        self.object_address = Some(value);
    }

    /// Set the maximum number of iterations to be allowed by the
    /// expression evaluator.
    ///
    /// An iteration corresponds approximately to the evaluation of a
    /// single operation in an expression ("approximately" because the
    /// implementation may allow two such operations in some cases).
    /// The default is not to have a maximum; once set, it's not
    /// possible to go back to this default state.  This value can be
    /// set to avoid denial of service attacks by bad DWARF bytecode.
    pub fn set_max_iterations(&mut self, value: u32) {
        self.max_iterations = Some(value);
    }

    fn pop(&mut self) -> Result<u64, Error> {
        match self.stack.pop() {
            Some(value) => Ok(value & self.addr_mask),
            None => Err(Error::NotEnoughStackItems),
        }
    }

    fn pop_signed(&mut self) -> Result<i64, Error> {
        match self.stack.pop() {
            Some(value) => {
                let mut value = value & self.addr_mask;
                if self.address_size < 8 && (value & (1u64 << (8 * self.address_size - 1))) != 0 {
                    // Sign extend.
                    value |= !self.addr_mask;
                }
                Ok(value as i64)
            }
            None => Err(Error::NotEnoughStackItems),
        }
    }

    fn push(&mut self, value: u64) {
        self.stack.push(value);
    }

    fn evaluate_one_operation(&mut self,
                              operation: &Operation<'input, Endian>)
                              -> Result<OperationEvaluationResult<'input, Endian>, Error> {
        let mut terminated = false;
        let mut piece_end = false;
        let mut current_location = Location::Empty;

        match *operation {
            Operation::Deref { size, space } => {
                let addr = try!(self.pop());
                let addr_space = if space { Some(try!(self.pop())) } else { None };
                return Ok(OperationEvaluationResult::AwaitingMemory {
                              address: addr,
                              size: size,
                              space: addr_space,
                          });
            }

            Operation::Drop => {
                try!(self.pop());
            }
            Operation::Pick { index } => {
                let len = self.stack.len();
                let index = index as usize;
                if index >= len {
                    return Err(Error::NotEnoughStackItems.into());
                }
                let value = self.stack[len - index - 1];
                self.push(value);
            }
            Operation::Swap => {
                let top = try!(self.pop());
                let next = try!(self.pop());
                self.push(top);
                self.push(next);
            }
            Operation::Rot => {
                let one = try!(self.pop());
                let two = try!(self.pop());
                let three = try!(self.pop());
                self.push(one);
                self.push(three);
                self.push(two);
            }

            Operation::Abs => {
                let value = try!(self.pop_signed());
                self.push(value.abs() as u64);
            }
            Operation::And => {
                let v1 = try!(self.pop());
                let v2 = try!(self.pop());
                self.push(v2 & v1);
            }
            Operation::Div => {
                let v1 = try!(self.pop_signed());
                let v2 = try!(self.pop_signed());
                if v1 == 0 {
                    return Err(Error::DivisionByZero.into());
                }
                self.push(v2.wrapping_div(v1) as u64);
            }
            Operation::Minus => {
                let v1 = try!(self.pop());
                let v2 = try!(self.pop());
                self.push(v2.wrapping_sub(v1));
            }
            Operation::Mod => {
                let v1 = try!(self.pop());
                let v2 = try!(self.pop());
                if v1 == 0 {
                    return Err(Error::DivisionByZero.into());
                }
                self.push(v2.wrapping_rem(v1));
            }
            Operation::Mul => {
                let v1 = try!(self.pop());
                let v2 = try!(self.pop());
                self.push(v2.wrapping_mul(v1));
            }
            Operation::Neg => {
                let v = try!(self.pop());
                self.push(v.wrapping_neg());
            }
            Operation::Not => {
                let value = try!(self.pop());
                self.push(!value);
            }
            Operation::Or => {
                let v1 = try!(self.pop());
                let v2 = try!(self.pop());
                self.push(v2 | v1);
            }
            Operation::Plus => {
                let v1 = try!(self.pop());
                let v2 = try!(self.pop());
                self.push(v2.wrapping_add(v1));
            }
            Operation::PlusConstant { value } => {
                let v = try!(self.pop());
                self.push(v.wrapping_add(value));
            }
            Operation::Shl => {
                let v1 = try!(self.pop());
                let v2 = try!(self.pop());
                // Because wrapping_shl takes a u32, not a u64, we do
                // the check by hand.
                if v1 >= 64 {
                    self.push(0);
                } else {
                    self.push(v2 << v1)
                }
            }
            Operation::Shr => {
                let v1 = try!(self.pop());
                let v2 = try!(self.pop());
                // Because wrapping_shr takes a u32, not a u64, we do
                // the check by hand.
                if v1 >= 64 {
                    self.push(0);
                } else {
                    self.push(v2 >> v1)
                }
            }
            Operation::Shra => {
                let v1 = try!(self.pop());
                let v2 = try!(self.pop_signed());
                // Because wrapping_shr takes a u32, not a u64, we do
                // the check by hand.
                if v1 >= 64 {
                    if v2 < 0 {
                        self.push(!0u64);
                    } else {
                        self.push(0);
                    }
                } else {
                    self.push((v2 >> v1) as u64);
                }
            }
            Operation::Xor => {
                let v1 = try!(self.pop());
                let v2 = try!(self.pop());
                self.push(v2 ^ v1);
            }

            Operation::Bra { target } => {
                let v = try!(self.pop());
                if v != 0 {
                    self.pc = target;
                }
            }

            Operation::Eq => {
                let v1 = try!(self.pop_signed());
                let v2 = try!(self.pop_signed());
                self.push(if v2 == v1 { 1 } else { 0 });
            }
            Operation::Ge => {
                let v1 = try!(self.pop_signed());
                let v2 = try!(self.pop_signed());
                self.push(if v2 >= v1 { 1 } else { 0 });
            }
            Operation::Gt => {
                let v1 = try!(self.pop_signed());
                let v2 = try!(self.pop_signed());
                self.push(if v2 > v1 { 1 } else { 0 });
            }
            Operation::Le => {
                let v1 = try!(self.pop_signed());
                let v2 = try!(self.pop_signed());
                self.push(if v2 <= v1 { 1 } else { 0 });
            }
            Operation::Lt => {
                let v1 = try!(self.pop_signed());
                let v2 = try!(self.pop_signed());
                self.push(if v2 < v1 { 1 } else { 0 });
            }
            Operation::Ne => {
                let v1 = try!(self.pop_signed());
                let v2 = try!(self.pop_signed());
                self.push(if v2 != v1 { 1 } else { 0 });
            }

            Operation::Skip { target } => {
                self.pc = target;
            }

            Operation::Literal { value } => {
                self.push(value);
            }

            Operation::RegisterOffset { register, offset } => {
                return Ok(OperationEvaluationResult::AwaitingRegister {
                              register: register,
                              offset: offset as u64,
                          });
            }

            Operation::FrameOffset { offset } => {
                return Ok(OperationEvaluationResult::AwaitingFrameBase { offset: offset as u64 });
            }

            Operation::Nop => {}

            Operation::PushObjectAddress => {
                if let Some(value) = self.object_address {
                    self.push(value);
                } else {
                    return Err(Error::InvalidPushObjectAddress.into());
                }
            }

            Operation::Call { offset } => {
                return Ok(OperationEvaluationResult::AwaitingAtLocation { location: offset });
            }

            Operation::TLS => {
                let value = try!(self.pop());
                return Ok(OperationEvaluationResult::AwaitingTls { index: value });
            }

            Operation::CallFrameCFA => {
                return Ok(OperationEvaluationResult::AwaitingCfa);
            }

            Operation::Register { register } => {
                terminated = true;
                current_location = Location::Register { register: register };
            }

            Operation::ImplicitValue { data } => {
                terminated = true;
                current_location = Location::Bytes { value: data };
            }

            Operation::StackValue => {
                terminated = true;
                current_location = Location::Scalar { value: try!(self.pop()) };
            }

            Operation::ImplicitPointer { value, byte_offset } => {
                terminated = true;
                current_location = Location::ImplicitPointer {
                    value: value,
                    byte_offset: byte_offset,
                };
            }

            Operation::EntryValue { expression } => {
                return Ok(OperationEvaluationResult::AwaitingEntryValue {
                              expression: expression.into(),
                          });
            }

            Operation::Piece { .. } => {
                piece_end = true;
            }
        }

        Ok(OperationEvaluationResult::Complete {
               terminated: terminated,
               piece_end: piece_end,
               current_location: current_location,
           })
    }

    /// Get the result of this `Evaluation`.
    ///
    /// # Panics
    /// Panics if this `Evaluation` has not been driven to completion.
    pub fn result(self) -> Vec<Piece<'input>> {
        match self.state {
            EvaluationState::Complete => self.result,
            _ => {
                panic!("Called `Evaluation::result` on an `Evaluation` that has not been completed")
            }
        }
    }

    /// Evaluate a DWARF expression.  This method should only ever be called
    /// once.  If the returned `EvaluationResult` is not
    /// `EvaluationResult::Complete`, the caller should provide the required
    /// value and resume the evaluation by calling the appropriate resume_with
    /// method on `Evaluation`.
    pub fn evaluate(&mut self) -> Result<EvaluationResult<'input, Endian>, Error>
        where Endian: Endianity
    {
        match self.state {
            EvaluationState::Start(initial_value) => {
                if let Some(value) = initial_value {
                    self.push(value);
                }
                self.state = EvaluationState::Ready;
            }
            EvaluationState::Ready => {}
            EvaluationState::Error(err) => return Err(err),
            EvaluationState::Complete => return Ok(EvaluationResult::Complete),
            EvaluationState::Waiting(_) => panic!(),
        };

        match self.evaluate_internal() {
            Ok(r) => Ok(r),
            Err(e) => {
                self.state = EvaluationState::Error(e);
                Err(e)
            }
        }
    }

    /// Resume the `Evaluation` with the provided memory `value`.  This will apply
    /// the provided memory value to the evaluation and continue evaluating
    /// opcodes until the evaluation is completed, reaches an error, or needs
    /// more information again.
    ///
    /// # Panics
    /// Panics if this `Evaluation` did not previously stop with `EvaluationResult::RequiresMemory`.
    pub fn resume_with_memory(&mut self,
                              value: u64)
                              -> Result<EvaluationResult<'input, Endian>, Error>
        where Endian: Endianity
    {
        match self.state {
            EvaluationState::Error(err) => return Err(err),
            EvaluationState::Waiting(OperationEvaluationResult::AwaitingMemory { .. }) => {
                self.push(value);
            }
            _ => {
                panic!("Called `Evaluation::resume_with_memory` without a preceding `EvaluationResult::RequiresMemory`")
            }
        };

        self.evaluate_internal()
    }

    /// Resume the `Evaluation` with the provided `register` value.  This will apply
    /// the provided register value to the evaluation and continue evaluating
    /// opcodes until the evaluation is completed, reaches an error, or needs
    /// more information again.
    ///
    /// # Panics
    /// Panics if this `Evaluation` did not previously stop with `EvaluationResult::RequiresRegister`.
    pub fn resume_with_register(&mut self,
                                register: u64)
                                -> Result<EvaluationResult<'input, Endian>, Error>
        where Endian: Endianity
    {
        match self.state {
            EvaluationState::Error(err) => return Err(err),
            EvaluationState::Waiting(OperationEvaluationResult::AwaitingRegister {
                                         offset, ..
                                     }) => {
                self.push(register.wrapping_add(offset));
            }
            _ => {
                panic!("Called `Evaluation::resume_with_register` without a preceding `EvaluationResult::RequiresRegister`")
            }
        };

        self.evaluate_internal()
    }

    /// Resume the `Evaluation` with the provided `frame_base`.  This will
    /// apply the provided frame base value to the evaluation and continue
    /// evaluating opcodes until the evaluation is completed, reaches an error,
    /// or needs more information again.
    ///
    /// # Panics
    /// Panics if this `Evaluation` did not previously stop with `EvaluationResult::RequiresFrameBase`.
    pub fn resume_with_frame_base(&mut self,
                                  frame_base: u64)
                                  -> Result<EvaluationResult<'input, Endian>, Error>
        where Endian: Endianity
    {
        match self.state {
            EvaluationState::Error(err) => return Err(err),
            EvaluationState::Waiting(OperationEvaluationResult::AwaitingFrameBase { offset }) => {
                self.push(frame_base.wrapping_add(offset));
            }
            _ => {
                panic!("Called `Evaluation::resume_with_frame_base` without a preceding `EvaluationResult::RequiresFrameBase`")
            }
        };

        self.evaluate_internal()
    }

    /// Resume the `Evaluation` with the provided `value`.  This will apply
    /// the provided TLS value to the evaluation and continue evaluating
    /// opcodes until the evaluation is completed, reaches an error, or needs
    /// more information again.
    ///
    /// # Panics
    /// Panics if this `Evaluation` did not previously stop with `EvaluationResult::RequiresTls`.
    pub fn resume_with_tls(&mut self, value: u64) -> Result<EvaluationResult<'input, Endian>, Error>
        where Endian: Endianity
    {
        match self.state {
            EvaluationState::Error(err) => return Err(err),
            EvaluationState::Waiting(OperationEvaluationResult::AwaitingTls { .. }) => {
                self.push(value);
            }
            _ => {
                panic!("Called `Evaluation::resume_with_tls` without a preceding `EvaluationResult::RequiresTls`")
            }
        };

        self.evaluate_internal()
    }

    /// Resume the `Evaluation` with the provided `cfa`.  This will
    /// apply the provided CFA value to the evaluation and continue evaluating
    /// opcodes until the evaluation is completed, reaches an error, or needs
    /// more information again.
    ///
    /// # Panics
    /// Panics if this `Evaluation` did not previously stop with `EvaluationResult::RequiresCallFrameCfa`.
    pub fn resume_with_call_frame_cfa(&mut self,
                                      cfa: u64)
                                      -> Result<EvaluationResult<'input, Endian>, Error>
        where Endian: Endianity
    {
        match self.state {
            EvaluationState::Error(err) => return Err(err),
            EvaluationState::Waiting(OperationEvaluationResult::AwaitingCfa) => {
                self.push(cfa);
            }
            _ => {
                panic!("Called `Evaluation::resume_with_call_frame_cfa` without a preceding `EvaluationResult::RequiresCallFrameCfa`")
            }
        };

        self.evaluate_internal()
    }

    /// Resume the `Evaluation` with the provided `bytes`.  This will
    /// continue processing the evaluation with the new expression provided
    /// until the evaluation is completed, reaches an error, or needs more
    /// information again.
    ///
    /// # Panics
    /// Panics if this `Evaluation` did not previously stop with `EvaluationResult::RequiresAtLocation`.
    pub fn resume_with_at_location(&mut self,
                                   bytes: EndianBuf<'input, Endian>)
                                   -> Result<EvaluationResult<'input, Endian>, Error>
        where Endian: Endianity
    {
        match self.state {
            EvaluationState::Error(err) => return Err(err),
            EvaluationState::Waiting(OperationEvaluationResult::AwaitingAtLocation { .. }) => {
                if bytes.len() > 0 {
                    self.expression_stack.push((self.pc, self.bytecode));
                    self.pc = bytes;
                    self.bytecode = bytes;
                }
            }
            _ => {
                panic!("Called `Evaluation::resume_with_at_location` without a precedeing `EvaluationResult::RequiresAtLocation`")
            }
        };

        self.evaluate_internal()
    }

    /// Resume the `Evaluation` with the provided `entry_value`.  This will
    /// apply the provided entry value to the evaluation and continue evaluating
    /// opcodes until the evaluation is completed, reaches an error, or needs
    /// more information again.
    ///
    /// # Panics
    /// Panics if this `Evaluation` did not previously stop with `EvaluationResult::RequiresEntryValue`.
    pub fn resume_with_entry_value(&mut self,
                                   entry_value: u64)
                                   -> Result<EvaluationResult<'input, Endian>, Error>
        where Endian: Endianity
    {
        match self.state {
            EvaluationState::Error(err) => return Err(err),
            EvaluationState::Waiting(OperationEvaluationResult::AwaitingEntryValue { .. }) => {
                self.push(entry_value);
            }
            _ => {
                panic!("Called `Evaluation::resume_with_entry_value` without a preceding `EvaluationResult::RequiresEntryValue`")
            }
        };

        self.evaluate_internal()
    }

    fn evaluate_internal(&mut self) -> Result<EvaluationResult<'input, Endian>, Error>
        where Endian: Endianity
    {
        'eval: loop {
            while self.pc.len() == 0 {
                match self.expression_stack.pop() {
                    Some((newpc, newbytes)) => {
                        self.pc = newpc;
                        self.bytecode = newbytes;
                    }
                    None => break 'eval,
                }
            }

            self.iteration += 1;
            if let Some(max_iterations) = self.max_iterations {
                if self.iteration > max_iterations {
                    return Err(Error::TooManyIterations.into());
                }
            }

            let (newpc, operation) =
                try!(Operation::parse(self.pc, self.bytecode, self.address_size, self.format));
            self.pc = newpc;

            let op_result = try!(self.evaluate_one_operation(&operation));
            match op_result {
                OperationEvaluationResult::Complete {
                    terminated,
                    piece_end,
                    mut current_location,
                } => {
                    if piece_end || terminated {
                        // If we saw a piece end, like Piece, then we want to use
                        // the operation we already decoded to see what to do.
                        // Otherwise, we saw something like Register, so we want
                        // to decode the next operation.
                        let eof = !piece_end && self.pc.len() == 0;
                        let mut pieceop = operation;
                        if !terminated {
                            // We saw a piece operation without something
                            // terminating the expression.  This means the
                            // result is the address on the stack.
                            assert_eq!(current_location, Location::Empty);
                            if !self.stack.is_empty() {
                                current_location = Location::Address { address: try!(self.pop()) };
                            }
                        } else if !eof {
                            let (newpc, operation) = try!(Operation::parse(self.pc,
                                                                           self.bytecode,
                                                                           self.address_size,
                                                                           self.format));
                            self.pc = newpc;
                            pieceop = operation;
                        }
                        match pieceop {
                            _ if eof => {
                                if !self.result.is_empty() {
                                    // We saw a piece earlier and then some
                                    // unterminated piece.  It's not clear this is
                                    // well-defined.
                                    return Err(Error::InvalidPiece.into());
                                }
                                self.result.push(Piece {
                                                     size_in_bits: None,
                                                     bit_offset: None,
                                                     location: current_location,
                                                 });
                            }

                            Operation::Piece {
                                size_in_bits,
                                bit_offset,
                            } => {
                                self.result.push(Piece {
                                                     size_in_bits: Some(size_in_bits),
                                                     bit_offset: bit_offset,
                                                     location: current_location,
                                                 });
                            }

                            _ => {
                                let value = self.bytecode.len() - self.pc.len() - 1;
                                return Err(Error::InvalidExpressionTerminator(value).into());
                            }
                        }
                    }
                }
                OperationEvaluationResult::AwaitingMemory {
                    address,
                    size,
                    space,
                } => {
                    self.state = EvaluationState::Waiting(op_result);
                    return Ok(EvaluationResult::RequiresMemory {
                                  address: address,
                                  size: size,
                                  space: space,
                              });
                }
                OperationEvaluationResult::AwaitingRegister { register, .. } => {
                    self.state = EvaluationState::Waiting(op_result);
                    return Ok(EvaluationResult::RequiresRegister(register));
                }
                OperationEvaluationResult::AwaitingFrameBase { .. } => {
                    self.state = EvaluationState::Waiting(op_result);
                    return Ok(EvaluationResult::RequiresFrameBase);
                }
                OperationEvaluationResult::AwaitingTls { index } => {
                    self.state = EvaluationState::Waiting(op_result);
                    return Ok(EvaluationResult::RequiresTls(index));
                }
                OperationEvaluationResult::AwaitingCfa => {
                    self.state = EvaluationState::Waiting(op_result);
                    return Ok(EvaluationResult::RequiresCallFrameCfa);
                }
                OperationEvaluationResult::AwaitingAtLocation { location } => {
                    self.state = EvaluationState::Waiting(op_result);
                    return Ok(EvaluationResult::RequiresAtLocation(location));
                }
                OperationEvaluationResult::AwaitingEntryValue { expression } => {
                    self.state = EvaluationState::Waiting(op_result);
                    return Ok(EvaluationResult::RequiresEntryValue(expression));
                }
            };
        }

        // If no pieces have been seen, use the stack top as the
        // result.
        if self.result.is_empty() {
            let addr = try!(self.pop());
            self.result.push(Piece {
                                 size_in_bits: None,
                                 bit_offset: None,
                                 location: Location::Address { address: addr },
                             });
        }

        self.state = EvaluationState::Complete;
        Ok(EvaluationResult::Complete)
    }
}

#[cfg(test)]
mod tests {
    extern crate test_assembler;

    use super::*;
    use super::compute_pc;
    use constants;
    use endianity::{EndianBuf, LittleEndian};
    use leb128;
    use parser::{Error, Format, Result, parse_u64};
    use self::test_assembler::{Endian, Section};
    use unit::{DebugInfoOffset, UnitOffset};
    use test_util::GimliSectionMethods;

    #[test]
    fn test_compute_pc() {
        // Contents don't matter for this test, just length.
        let bytes = [0, 1, 2, 3, 4];
        let bytecode = &bytes[..];
        let ebuf = EndianBuf::<LittleEndian>::new(bytecode);

        assert_eq!(compute_pc(ebuf, ebuf, 0), Ok(ebuf));
        assert_eq!(compute_pc(ebuf, ebuf, -1),
                   Err(Error::BadBranchTarget(-1isize as usize)));
        assert_eq!(compute_pc(ebuf, ebuf, 5), Ok(ebuf.range_from(5..)));
        assert_eq!(compute_pc(ebuf.range_from(3..), ebuf, -2),
                   Ok(ebuf.range_from(1..)));
        assert_eq!(compute_pc(ebuf.range_from(2..), ebuf, 2),
                   Ok(ebuf.range_from(4..)));
    }

    fn check_op_parse_simple(input: &[u8],
                             expect: &Operation<LittleEndian>,
                             address_size: u8,
                             format: Format) {
        let buf = EndianBuf::<LittleEndian>::new(input);
        let value = Operation::parse(buf, buf, address_size, format);
        match value {
            Ok((pc, val)) => {
                assert_eq!(val, *expect);
                assert_eq!(pc.len(), 0);
            }
            _ => panic!("Unexpected result"),
        }
    }

    fn check_op_parse_failure(input: &[u8], expect: Error, address_size: u8, format: Format) {
        let buf = EndianBuf::<LittleEndian>::new(input);
        match Operation::parse(buf, buf, address_size, format) {
            Err(x) => {
                assert_eq!(x, expect);
            }

            _ => panic!("Unexpected result"),
        }
    }

    fn check_op_parse<F>(input: F,
                         expect: &Operation<LittleEndian>,
                         address_size: u8,
                         format: Format)
        where F: Fn(Section) -> Section
    {
        let input = input(Section::with_endian(Endian::Little))
            .get_contents()
            .unwrap();
        for i in 1..input.len() {
            check_op_parse_failure(&input[..i], Error::UnexpectedEof, address_size, format);
        }
        check_op_parse_simple(&input, expect, address_size, format);
    }

    #[test]
    fn test_op_parse_onebyte() {
        // Doesn't matter for this test.
        let address_size = 4;
        let format = Format::Dwarf32;

        // Test all single-byte opcodes.
        let inputs = [(constants::DW_OP_deref,
                       Operation::Deref {
                           size: address_size,
                           space: false,
                       }),
                      (constants::DW_OP_dup, Operation::Pick { index: 0 }),
                      (constants::DW_OP_drop, Operation::Drop),
                      (constants::DW_OP_over, Operation::Pick { index: 1 }),
                      (constants::DW_OP_swap, Operation::Swap),
                      (constants::DW_OP_rot, Operation::Rot),
                      (constants::DW_OP_xderef,
                       Operation::Deref {
                           size: address_size,
                           space: true,
                       }),
                      (constants::DW_OP_abs, Operation::Abs),
                      (constants::DW_OP_and, Operation::And),
                      (constants::DW_OP_div, Operation::Div),
                      (constants::DW_OP_minus, Operation::Minus),
                      (constants::DW_OP_mod, Operation::Mod),
                      (constants::DW_OP_mul, Operation::Mul),
                      (constants::DW_OP_neg, Operation::Neg),
                      (constants::DW_OP_not, Operation::Not),
                      (constants::DW_OP_or, Operation::Or),
                      (constants::DW_OP_plus, Operation::Plus),
                      (constants::DW_OP_shl, Operation::Shl),
                      (constants::DW_OP_shr, Operation::Shr),
                      (constants::DW_OP_shra, Operation::Shra),
                      (constants::DW_OP_xor, Operation::Xor),
                      (constants::DW_OP_eq, Operation::Eq),
                      (constants::DW_OP_ge, Operation::Ge),
                      (constants::DW_OP_gt, Operation::Gt),
                      (constants::DW_OP_le, Operation::Le),
                      (constants::DW_OP_lt, Operation::Lt),
                      (constants::DW_OP_ne, Operation::Ne),
                      (constants::DW_OP_lit0, Operation::Literal { value: 0 }),
                      (constants::DW_OP_lit1, Operation::Literal { value: 1 }),
                      (constants::DW_OP_lit2, Operation::Literal { value: 2 }),
                      (constants::DW_OP_lit3, Operation::Literal { value: 3 }),
                      (constants::DW_OP_lit4, Operation::Literal { value: 4 }),
                      (constants::DW_OP_lit5, Operation::Literal { value: 5 }),
                      (constants::DW_OP_lit6, Operation::Literal { value: 6 }),
                      (constants::DW_OP_lit7, Operation::Literal { value: 7 }),
                      (constants::DW_OP_lit8, Operation::Literal { value: 8 }),
                      (constants::DW_OP_lit9, Operation::Literal { value: 9 }),
                      (constants::DW_OP_lit10, Operation::Literal { value: 10 }),
                      (constants::DW_OP_lit11, Operation::Literal { value: 11 }),
                      (constants::DW_OP_lit12, Operation::Literal { value: 12 }),
                      (constants::DW_OP_lit13, Operation::Literal { value: 13 }),
                      (constants::DW_OP_lit14, Operation::Literal { value: 14 }),
                      (constants::DW_OP_lit15, Operation::Literal { value: 15 }),
                      (constants::DW_OP_lit16, Operation::Literal { value: 16 }),
                      (constants::DW_OP_lit17, Operation::Literal { value: 17 }),
                      (constants::DW_OP_lit18, Operation::Literal { value: 18 }),
                      (constants::DW_OP_lit19, Operation::Literal { value: 19 }),
                      (constants::DW_OP_lit20, Operation::Literal { value: 20 }),
                      (constants::DW_OP_lit21, Operation::Literal { value: 21 }),
                      (constants::DW_OP_lit22, Operation::Literal { value: 22 }),
                      (constants::DW_OP_lit23, Operation::Literal { value: 23 }),
                      (constants::DW_OP_lit24, Operation::Literal { value: 24 }),
                      (constants::DW_OP_lit25, Operation::Literal { value: 25 }),
                      (constants::DW_OP_lit26, Operation::Literal { value: 26 }),
                      (constants::DW_OP_lit27, Operation::Literal { value: 27 }),
                      (constants::DW_OP_lit28, Operation::Literal { value: 28 }),
                      (constants::DW_OP_lit29, Operation::Literal { value: 29 }),
                      (constants::DW_OP_lit30, Operation::Literal { value: 30 }),
                      (constants::DW_OP_lit31, Operation::Literal { value: 31 }),
                      (constants::DW_OP_reg0, Operation::Register { register: 0 }),
                      (constants::DW_OP_reg1, Operation::Register { register: 1 }),
                      (constants::DW_OP_reg2, Operation::Register { register: 2 }),
                      (constants::DW_OP_reg3, Operation::Register { register: 3 }),
                      (constants::DW_OP_reg4, Operation::Register { register: 4 }),
                      (constants::DW_OP_reg5, Operation::Register { register: 5 }),
                      (constants::DW_OP_reg6, Operation::Register { register: 6 }),
                      (constants::DW_OP_reg7, Operation::Register { register: 7 }),
                      (constants::DW_OP_reg8, Operation::Register { register: 8 }),
                      (constants::DW_OP_reg9, Operation::Register { register: 9 }),
                      (constants::DW_OP_reg10, Operation::Register { register: 10 }),
                      (constants::DW_OP_reg11, Operation::Register { register: 11 }),
                      (constants::DW_OP_reg12, Operation::Register { register: 12 }),
                      (constants::DW_OP_reg13, Operation::Register { register: 13 }),
                      (constants::DW_OP_reg14, Operation::Register { register: 14 }),
                      (constants::DW_OP_reg15, Operation::Register { register: 15 }),
                      (constants::DW_OP_reg16, Operation::Register { register: 16 }),
                      (constants::DW_OP_reg17, Operation::Register { register: 17 }),
                      (constants::DW_OP_reg18, Operation::Register { register: 18 }),
                      (constants::DW_OP_reg19, Operation::Register { register: 19 }),
                      (constants::DW_OP_reg20, Operation::Register { register: 20 }),
                      (constants::DW_OP_reg21, Operation::Register { register: 21 }),
                      (constants::DW_OP_reg22, Operation::Register { register: 22 }),
                      (constants::DW_OP_reg23, Operation::Register { register: 23 }),
                      (constants::DW_OP_reg24, Operation::Register { register: 24 }),
                      (constants::DW_OP_reg25, Operation::Register { register: 25 }),
                      (constants::DW_OP_reg26, Operation::Register { register: 26 }),
                      (constants::DW_OP_reg27, Operation::Register { register: 27 }),
                      (constants::DW_OP_reg28, Operation::Register { register: 28 }),
                      (constants::DW_OP_reg29, Operation::Register { register: 29 }),
                      (constants::DW_OP_reg30, Operation::Register { register: 30 }),
                      (constants::DW_OP_reg31, Operation::Register { register: 31 }),
                      (constants::DW_OP_nop, Operation::Nop),
                      (constants::DW_OP_push_object_address, Operation::PushObjectAddress),
                      (constants::DW_OP_form_tls_address, Operation::TLS),
                      (constants::DW_OP_GNU_push_tls_address, Operation::TLS),
                      (constants::DW_OP_call_frame_cfa, Operation::CallFrameCFA),
                      (constants::DW_OP_stack_value, Operation::StackValue)];

        let input = [];
        check_op_parse_failure(&input[..], Error::UnexpectedEof, address_size, format);

        for item in inputs.iter() {
            let (opcode, ref result) = *item;
            check_op_parse(|s| s.D8(opcode.0), result, address_size, format);
        }
    }

    #[test]
    fn test_op_parse_twobyte() {
        // Doesn't matter for this test.
        let address_size = 4;
        let format = Format::Dwarf32;

        let inputs = [(constants::DW_OP_const1u, 23, Operation::Literal { value: 23 }),
                      (constants::DW_OP_const1s,
                       (-23i8) as u8,
                       Operation::Literal { value: (-23i64) as u64 }),
                      (constants::DW_OP_pick, 7, Operation::Pick { index: 7 }),
                      (constants::DW_OP_deref_size,
                       19,
                       Operation::Deref {
                           size: 19,
                           space: false,
                       }),
                      (constants::DW_OP_xderef_size,
                       19,
                       Operation::Deref {
                           size: 19,
                           space: true,
                       })];

        for item in inputs.iter() {
            let (opcode, arg, ref result) = *item;
            check_op_parse(|s| s.D8(opcode.0).D8(arg), result, address_size, format);
        }
    }

    #[test]
    fn test_op_parse_threebyte() {
        // Doesn't matter for this test.
        let address_size = 4;
        let format = Format::Dwarf32;

        // While bra and skip are 3-byte opcodes, they aren't tested here,
        // but rather specially in their own function.
        let inputs = [(constants::DW_OP_const2u, 23, Operation::Literal { value: 23 }),
                      (constants::DW_OP_const2s,
                       (-23i16) as u16,
                       Operation::Literal { value: (-23i64) as u64 }),
                      (constants::DW_OP_call2,
                       1138,
                       Operation::Call { offset: DieReference::UnitRef(UnitOffset(1138)) })];

        for item in inputs.iter() {
            let (opcode, arg, ref result) = *item;
            check_op_parse(|s| s.D8(opcode.0).L16(arg), result, address_size, format);
        }
    }

    #[test]
    fn test_op_parse_branches() {
        // Doesn't matter for this test.
        const ADDRESS_SIZE: u8 = 4;
        const FORMAT: Format = Format::Dwarf32;

        let inputs = [constants::DW_OP_bra, constants::DW_OP_skip];

        fn check_one_branch(input: &[u8], target: &[u8]) {
            // Test sanity checking.
            assert!(input.len() >= 3);

            let expect = if input[0] == constants::DW_OP_bra.0 {
                Operation::Bra { target: EndianBuf::<LittleEndian>::new(target) }
            } else {
                assert!(input[0] == constants::DW_OP_skip.0);
                Operation::Skip { target: EndianBuf::<LittleEndian>::new(target) }
            };

            check_op_parse(|s| s.append_bytes(input), &expect, ADDRESS_SIZE, FORMAT);
        }

        for opcode in inputs.iter() {
            // Branch to start.
            let input = [opcode.0, 0xfd, 0xff];
            check_one_branch(&input[..], &input[..]);

            // Branch to middle of an instruction -- ok as far as DWARF is
            // concerned.
            let input = [opcode.0, 0xfe, 0xff];
            check_one_branch(&input[..], &input[1..]);

            // Branch to end.  DWARF is silent on this but it seems valid
            // to branch to just after the last operation.
            let input = [opcode.0, 0, 0];
            check_one_branch(&input[..], &input[3..]);

            // Invalid branches.
            let input = [opcode.0, 2, 0];
            check_op_parse_failure(&input[..], Error::BadBranchTarget(5), ADDRESS_SIZE, FORMAT);
            let input = [opcode.0, 0xfc, 0xff];
            check_op_parse_failure(&input[..],
                                   Error::BadBranchTarget(!0usize),
                                   ADDRESS_SIZE,
                                   FORMAT);
        }
    }

    #[test]
    fn test_op_parse_fivebyte() {
        // There are some tests here that depend on address size.
        let address_size = 4;
        let format = Format::Dwarf32;

        let inputs =
            [(constants::DW_OP_addr, 0x12345678, Operation::Literal { value: 0x12345678 }),
             (constants::DW_OP_const4u, 0x12345678, Operation::Literal { value: 0x12345678 }),
             (constants::DW_OP_const4s,
              (-23i32) as u32,
              Operation::Literal { value: (-23i32) as u64 }),
             (constants::DW_OP_call4,
              0x12345678,
              Operation::Call { offset: DieReference::UnitRef(UnitOffset(0x12345678)) }),
             (constants::DW_OP_call_ref,
              0x12345678,
              Operation::Call { offset: DieReference::DebugInfoRef(DebugInfoOffset(0x12345678)) })];

        for item in inputs.iter() {
            let (op, arg, ref expect) = *item;
            check_op_parse(|s| s.D8(op.0).L32(arg), expect, address_size, format);
        }
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn test_op_parse_ninebyte() {
        // There are some tests here that depend on address size.
        let address_size = 8;
        let format = Format::Dwarf64;

        let inputs = [(constants::DW_OP_addr,
                       0x1234567812345678,
                       Operation::Literal { value: 0x1234567812345678 }),
                      (constants::DW_OP_const8u,
                       0x1234567812345678,
                       Operation::Literal { value: 0x1234567812345678 }),
                      (constants::DW_OP_const8s,
                       (-23i32) as u64,
                       Operation::Literal { value: (-23i32) as u64 }),
                      (constants::DW_OP_call_ref,
                       0x1234567812345678,
                       Operation::Call {
                           offset: DieReference::DebugInfoRef(DebugInfoOffset(0x1234567812345678)),
                       })];

        for item in inputs.iter() {
            let (op, arg, ref expect) = *item;
            check_op_parse(|s| s.D8(op.0).L64(arg), expect, address_size, format);
        }
    }

    #[test]
    fn test_op_parse_sleb() {
        // Doesn't matter for this test.
        let address_size = 4;
        let format = Format::Dwarf32;

        let values = [-1i64,
                      0,
                      1,
                      0x100,
                      0x1eeeeeee,
                      0x7fffffffffffffff,
                      -0x100,
                      -0x1eeeeeee,
                      -0x7fffffffffffffff];
        for value in values.iter() {
            let mut inputs =
                vec![(constants::DW_OP_consts.0, Operation::Literal { value: *value as u64 }),
                     (constants::DW_OP_fbreg.0, Operation::FrameOffset { offset: *value })];

            for i in 0..32 {
                inputs.push((constants::DW_OP_breg0.0 + i,
                             Operation::RegisterOffset {
                                 register: i as u64,
                                 offset: *value,
                             }));
            }

            for item in inputs.iter() {
                let (op, ref expect) = *item;
                check_op_parse(|s| s.D8(op).sleb(*value), expect, address_size, format);
            }
        }
    }

    #[test]
    fn test_op_parse_uleb() {
        // Doesn't matter for this test.
        let address_size = 4;
        let format = Format::Dwarf32;

        let values = [0, 1, 0x100, 0x1eeeeeee, 0x7fffffffffffffff, !0u64];
        for value in values.iter() {
            let mut inputs =
                vec![(constants::DW_OP_constu, Operation::Literal { value: *value }),
                     (constants::DW_OP_plus_uconst, Operation::PlusConstant { value: *value }),
                     (constants::DW_OP_regx, Operation::Register { register: *value })];

            // FIXME
            if *value < !0u64 / 8 {
                inputs.push((constants::DW_OP_piece,
                             Operation::Piece {
                                 size_in_bits: 8 * value,
                                 bit_offset: None,
                             }));
            }

            for item in inputs.iter() {
                let (op, ref expect) = *item;
                let input = Section::with_endian(Endian::Little)
                    .D8(op.0)
                    .uleb(*value)
                    .get_contents()
                    .unwrap();
                check_op_parse_simple(&input, expect, address_size, format);
            }
        }
    }

    #[test]
    fn test_op_parse_bregx() {
        // Doesn't matter for this test.
        let address_size = 4;
        let format = Format::Dwarf32;

        let uvalues = [0, 1, 0x100, 0x1eeeeeee, 0x7fffffffffffffff, !0u64];
        let svalues = [-1i64,
                       0,
                       1,
                       0x100,
                       0x1eeeeeee,
                       0x7fffffffffffffff,
                       -0x100,
                       -0x1eeeeeee,
                       -0x7fffffffffffffff];

        for v1 in uvalues.iter() {
            for v2 in svalues.iter() {
                check_op_parse(|s| s.D8(constants::DW_OP_bregx.0).uleb(*v1).sleb(*v2),
                               &Operation::RegisterOffset {
                                   register: *v1,
                                   offset: *v2,
                               },
                               address_size,
                               format);
            }
        }
    }

    #[test]
    fn test_op_parse_bit_piece() {
        // Doesn't matter for this test.
        let address_size = 4;
        let format = Format::Dwarf32;

        let values = [0, 1, 0x100, 0x1eeeeeee, 0x7fffffffffffffff, !0u64];

        for v1 in values.iter() {
            for v2 in values.iter() {
                let input = Section::with_endian(Endian::Little)
                    .D8(constants::DW_OP_bit_piece.0)
                    .uleb(*v1)
                    .uleb(*v2)
                    .get_contents()
                    .unwrap();
                check_op_parse_simple(&input,
                                      &Operation::Piece {
                                          size_in_bits: *v1,
                                          bit_offset: Some(*v2),
                                      },
                                      address_size,
                                      format);
            }
        }
    }

    #[test]
    fn test_op_parse_implicit_value() {
        // Doesn't matter for this test.
        let address_size = 4;
        let format = Format::Dwarf32;

        let data = b"hello";

        check_op_parse(|s| {
                           s.D8(constants::DW_OP_implicit_value.0)
                               .uleb(data.len() as u64)
                               .append_bytes(&data[..])
                       },
                       &Operation::ImplicitValue { data: &data[..] },
                       address_size,
                       format);
    }

    #[test]
    fn test_op_parse_implicit_pointer() {
        for op in &[constants::DW_OP_implicit_pointer,
                    constants::DW_OP_GNU_implicit_pointer] {
            check_op_parse(|s| s.D8(op.0).D32(0x12345678).sleb(0x123),
                           &Operation::ImplicitPointer {
                               value: DebugInfoOffset(0x12345678),
                               byte_offset: 0x123,
                           },
                           4,
                           Format::Dwarf32);

            check_op_parse(|s| s.D8(op.0).D64(0x12345678).sleb(0x123),
                           &Operation::ImplicitPointer {
                               value: DebugInfoOffset(0x12345678),
                               byte_offset: 0x123,
                           },
                           8,
                           Format::Dwarf64);
        }
    }

    #[test]
    fn test_op_parse_entry_value() {
        for op in &[constants::DW_OP_entry_value,
                    constants::DW_OP_GNU_entry_value] {
            let data = b"hello";
            check_op_parse(|s| s.D8(op.0).uleb(data.len() as u64).append_bytes(&data[..]),
                           &Operation::EntryValue { expression: EndianBuf::new(&data[..]) },
                           4,
                           Format::Dwarf32);
        }
    }

    enum AssemblerEntry {
        Op(constants::DwOp),
        Mark(u8),
        Branch(u8),
        U8(u8),
        U16(u16),
        U32(u32),
        U64(u64),
        Uleb(u64),
        Sleb(u64),
    }

    fn assemble(entries: &[AssemblerEntry]) -> Vec<u8> {
        let mut result = Vec::new();

        struct Marker(Option<usize>, Vec<usize>);

        let mut markers = Vec::new();
        for _ in 0..256 {
            markers.push(Marker(None, Vec::new()));
        }

        fn write(stack: &mut Vec<u8>, index: usize, mut num: u64, nbytes: u8) {
            for i in 0..nbytes as usize {
                stack[index + i] = (num & 0xff) as u8;
                num >>= 8;
            }
        }

        fn push(stack: &mut Vec<u8>, num: u64, nbytes: u8) {
            let index = stack.len();
            for _ in 0..nbytes {
                stack.push(0);
            }
            write(stack, index, num, nbytes);
        }

        for item in entries {
            match *item {
                AssemblerEntry::Op(op) => result.push(op.0),
                AssemblerEntry::Mark(num) => {
                    assert!(markers[num as usize].0.is_none());
                    markers[num as usize].0 = Some(result.len());
                }
                AssemblerEntry::Branch(num) => {
                    markers[num as usize].1.push(result.len());
                    push(&mut result, 0, 2);
                }
                AssemblerEntry::U8(num) => result.push(num),
                AssemblerEntry::U16(num) => push(&mut result, num as u64, 2),
                AssemblerEntry::U32(num) => push(&mut result, num as u64, 4),
                AssemblerEntry::U64(num) => push(&mut result, num, 8),
                AssemblerEntry::Uleb(num) => {
                    leb128::write::unsigned(&mut result, num).unwrap();
                }
                AssemblerEntry::Sleb(num) => {
                    leb128::write::signed(&mut result, num as i64).unwrap();
                }
            }
        }

        // Update all the branches.
        for marker in markers {
            if let Some(offset) = marker.0 {
                for branch_offset in marker.1 {
                    let delta = offset.wrapping_sub(branch_offset + 2) as u64;
                    write(&mut result, branch_offset, delta, 2);
                }
            }
        }

        result
    }

    fn check_eval_with_args<F>(program: &[AssemblerEntry],
                               expect: Result<&[Piece]>,
                               address_size: u8,
                               format: Format,
                               object_address: Option<u64>,
                               initial_value: Option<u64>,
                               max_iterations: Option<u32>,
                               f: F)
        where for<'a> F: Fn(&mut Evaluation<'a, LittleEndian>,
                            EvaluationResult<'a, LittleEndian>)
                            -> Result<EvaluationResult<'a, LittleEndian>>
    {
        let bytes = assemble(program);
        let bytes = EndianBuf::<LittleEndian>::new(&bytes);

        let mut eval = Evaluation::<LittleEndian>::new(bytes, address_size, format);

        if let Some(val) = object_address {
            eval.set_object_address(val);
        }
        if let Some(val) = initial_value {
            eval.set_initial_value(val);
        }
        if let Some(val) = max_iterations {
            eval.set_max_iterations(val);
        }

        let result = match eval.evaluate() {
            Err(e) => Err(e),
            Ok(r) => f(&mut eval, r),
        };

        match (result, expect) {
            (Ok(EvaluationResult::Complete), Ok(pieces)) => {
                let vec = eval.result();
                assert_eq!(vec.len(), pieces.len());
                for i in 0..pieces.len() {
                    assert_eq!(vec[i], pieces[i]);
                }
            }
            (Err(f1), Err(f2)) => {
                assert_eq!(f1, f2);
            }
            otherwise => panic!("Unexpected result: {:?}", otherwise),
        }
    }

    fn check_eval(program: &[AssemblerEntry],
                  expect: Result<&[Piece]>,
                  address_size: u8,
                  format: Format) {

        check_eval_with_args(program,
                             expect,
                             address_size,
                             format,
                             None,
                             None,
                             None,
                             |_, result| Ok(result));
    }

    #[test]
    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn test_eval_arith() {
        // It's nice if an operation and its arguments can fit on a single
        // line in the test program.
        use constants::*;
        use self::AssemblerEntry::*;

        // Indices of marks in the assembly.
        let done = 0;
        let fail = 1;

        let program = [
            Op(DW_OP_const1u), U8(23),
            Op(DW_OP_const1s), U8((-23i8) as u8),
            Op(DW_OP_plus),
            Op(DW_OP_bra), Branch(fail),

            Op(DW_OP_const2u), U16(23),
            Op(DW_OP_const2s), U16((-23i16) as u16),
            Op(DW_OP_plus),
            Op(DW_OP_bra), Branch(fail),

            Op(DW_OP_const4u), U32(0x11112222),
            Op(DW_OP_const4s), U32((-0x11112222i32) as u32),
            Op(DW_OP_plus),
            Op(DW_OP_bra), Branch(fail),

            // Plus should overflow.
            Op(DW_OP_const1s), U8(0xff),
            Op(DW_OP_const1u), U8(1),
            Op(DW_OP_plus),
            Op(DW_OP_bra), Branch(fail),

            Op(DW_OP_const1s), U8(0xff),
            Op(DW_OP_plus_uconst), Uleb(1),
            Op(DW_OP_bra), Branch(fail),

            // Minus should underflow.
            Op(DW_OP_const1s), U8(0),
            Op(DW_OP_const1u), U8(1),
            Op(DW_OP_minus),
            Op(DW_OP_const1s), U8(0xff),
            Op(DW_OP_ne),
            Op(DW_OP_bra), Branch(fail),

            Op(DW_OP_const1s), U8(0xff),
            Op(DW_OP_abs),
            Op(DW_OP_const1u), U8(1),
            Op(DW_OP_minus),
            Op(DW_OP_bra), Branch(fail),

            Op(DW_OP_const4u), U32(0xf078fffe),
            Op(DW_OP_const4u), U32(0x0f870001),
            Op(DW_OP_and),
            Op(DW_OP_bra), Branch(fail),

            Op(DW_OP_const4u), U32(0xf078fffe),
            Op(DW_OP_const4u), U32(0xf00000fe),
            Op(DW_OP_and),
            Op(DW_OP_const4u), U32(0xf00000fe),
            Op(DW_OP_ne),
            Op(DW_OP_bra), Branch(fail),

            // Division is signed.
            Op(DW_OP_const1s), U8(0xfe),
            Op(DW_OP_const1s), U8(2),
            Op(DW_OP_div),
            Op(DW_OP_plus_uconst), Uleb(1),
            Op(DW_OP_bra), Branch(fail),

            // Mod is unsigned.
            Op(DW_OP_const1s), U8(0xfd),
            Op(DW_OP_const1s), U8(2),
            Op(DW_OP_mod),
            Op(DW_OP_neg),
            Op(DW_OP_plus_uconst), Uleb(1),
            Op(DW_OP_bra), Branch(fail),

            // Overflow is defined for multiplication.
            Op(DW_OP_const4u), U32(0x80000001),
            Op(DW_OP_lit2),
            Op(DW_OP_mul),
            Op(DW_OP_lit2),
            Op(DW_OP_ne),
            Op(DW_OP_bra), Branch(fail),

            Op(DW_OP_const4u), U32(0xf0f0f0f0),
            Op(DW_OP_const4u), U32(0xf0f0f0f0),
            Op(DW_OP_xor),
            Op(DW_OP_bra), Branch(fail),

            Op(DW_OP_const4u), U32(0xf0f0f0f0),
            Op(DW_OP_const4u), U32(0x0f0f0f0f),
            Op(DW_OP_or),
            Op(DW_OP_not),
            Op(DW_OP_bra), Branch(fail),

            // In 32 bit mode, values are truncated.
            Op(DW_OP_const8u), U64(0xffffffff00000000),
            Op(DW_OP_lit2),
            Op(DW_OP_div),
            Op(DW_OP_bra), Branch(fail),

            Op(DW_OP_const1u), U8(0xff),
            Op(DW_OP_lit1),
            Op(DW_OP_shl),
            Op(DW_OP_const2u), U16(0x1fe),
            Op(DW_OP_ne),
            Op(DW_OP_bra), Branch(fail),

            Op(DW_OP_const1u), U8(0xff),
            Op(DW_OP_const1u), U8(50),
            Op(DW_OP_shl),
            Op(DW_OP_bra), Branch(fail),

            // Absurd shift.
            Op(DW_OP_const1u), U8(0xff),
            Op(DW_OP_const1s), U8(0xff),
            Op(DW_OP_shl),
            Op(DW_OP_bra), Branch(fail),

            Op(DW_OP_const1s), U8(0xff),
            Op(DW_OP_lit1),
            Op(DW_OP_shr),
            Op(DW_OP_const4u), U32(0x7fffffff),
            Op(DW_OP_ne),
            Op(DW_OP_bra), Branch(fail),

            Op(DW_OP_const1s), U8(0xff),
            Op(DW_OP_const1u), U8(0xff),
            Op(DW_OP_shr),
            Op(DW_OP_bra), Branch(fail),

            Op(DW_OP_const1s), U8(0xff),
            Op(DW_OP_lit1),
            Op(DW_OP_shra),
            Op(DW_OP_const1s), U8(0xff),
            Op(DW_OP_ne),
            Op(DW_OP_bra), Branch(fail),

            Op(DW_OP_const1s), U8(0xff),
            Op(DW_OP_const1u), U8(0xff),
            Op(DW_OP_shra),
            Op(DW_OP_const1s), U8(0xff),
            Op(DW_OP_ne),
            Op(DW_OP_bra), Branch(fail),

            // Success.
            Op(DW_OP_lit0),
            Op(DW_OP_nop),
            Op(DW_OP_skip), Branch(done),

            Mark(fail),
            Op(DW_OP_lit1),

            Mark(done),
            Op(DW_OP_stack_value),
        ];

        let result = [
            Piece { size_in_bits: None,
                    bit_offset: None,
                    location: Location::Scalar{value: 0},
            },
        ];

        check_eval(&program, Ok(&result), 4, Format::Dwarf32);
    }

    #[test]
    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn test_eval_arith64() {
        // It's nice if an operation and its arguments can fit on a single
        // line in the test program.
        use constants::*;
        use self::AssemblerEntry::*;

        // Indices of marks in the assembly.
        let done = 0;
        let fail = 1;

        let program = [
            Op(DW_OP_const8u), U64(0x1111222233334444),
            Op(DW_OP_const8s), U64((-0x1111222233334444i64) as u64),
            Op(DW_OP_plus),
            Op(DW_OP_bra), Branch(fail),

            Op(DW_OP_constu), Uleb(0x1111222233334444),
            Op(DW_OP_consts), Sleb((-0x1111222233334444i64) as u64),
            Op(DW_OP_plus),
            Op(DW_OP_bra), Branch(fail),

            Op(DW_OP_lit1),
            Op(DW_OP_plus_uconst), Uleb(!0u64),
            Op(DW_OP_bra), Branch(fail),

            Op(DW_OP_lit1),
            Op(DW_OP_neg),
            Op(DW_OP_not),
            Op(DW_OP_bra), Branch(fail),

            Op(DW_OP_const8u), U64(0x8000000000000000),
            Op(DW_OP_const1u), U8(63),
            Op(DW_OP_shr),
            Op(DW_OP_lit1),
            Op(DW_OP_ne),
            Op(DW_OP_bra), Branch(fail),

            Op(DW_OP_const8u), U64(0x8000000000000000),
            Op(DW_OP_const1u), U8(62),
            Op(DW_OP_shra),
            Op(DW_OP_plus_uconst), Uleb(2),
            Op(DW_OP_bra), Branch(fail),

            Op(DW_OP_lit1),
            Op(DW_OP_const1u), U8(63),
            Op(DW_OP_shl),
            Op(DW_OP_const8u), U64(0x8000000000000000),
            Op(DW_OP_ne),
            Op(DW_OP_bra), Branch(fail),

            // Success.
            Op(DW_OP_lit0),
            Op(DW_OP_nop),
            Op(DW_OP_skip), Branch(done),

            Mark(fail),
            Op(DW_OP_lit1),

            Mark(done),
            Op(DW_OP_stack_value),
        ];

        let result = [
            Piece { size_in_bits: None,
                    bit_offset: None,
                    location: Location::Scalar{value: 0},
            },
        ];

        check_eval(&program, Ok(&result), 8, Format::Dwarf64);
    }

    #[test]
    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn test_eval_compare() {
        // It's nice if an operation and its arguments can fit on a single
        // line in the test program.
        use constants::*;
        use self::AssemblerEntry::*;

        // Indices of marks in the assembly.
        let done = 0;
        let fail = 1;

        let program = [
            // Comparisons are signed.
            Op(DW_OP_const1s), U8(1),
            Op(DW_OP_const1s), U8(0xff),
            Op(DW_OP_lt),
            Op(DW_OP_bra), Branch(fail),

            Op(DW_OP_const1s), U8(0xff),
            Op(DW_OP_const1s), U8(1),
            Op(DW_OP_gt),
            Op(DW_OP_bra), Branch(fail),

            Op(DW_OP_const1s), U8(1),
            Op(DW_OP_const1s), U8(0xff),
            Op(DW_OP_le),
            Op(DW_OP_bra), Branch(fail),

            Op(DW_OP_const1s), U8(0xff),
            Op(DW_OP_const1s), U8(1),
            Op(DW_OP_ge),
            Op(DW_OP_bra), Branch(fail),

            Op(DW_OP_const1s), U8(0xff),
            Op(DW_OP_const1s), U8(1),
            Op(DW_OP_eq),
            Op(DW_OP_bra), Branch(fail),

            Op(DW_OP_const4s), U32(1),
            Op(DW_OP_const1s), U8(1),
            Op(DW_OP_ne),
            Op(DW_OP_bra), Branch(fail),

            // Success.
            Op(DW_OP_lit0),
            Op(DW_OP_nop),
            Op(DW_OP_skip), Branch(done),

            Mark(fail),
            Op(DW_OP_lit1),

            Mark(done),
            Op(DW_OP_stack_value),
        ];

        let result = [
            Piece { size_in_bits: None,
                    bit_offset: None,
                    location: Location::Scalar{value: 0},
            },
        ];

        check_eval(&program, Ok(&result), 4, Format::Dwarf32);
    }

    #[test]
    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn test_eval_stack() {
        // It's nice if an operation and its arguments can fit on a single
        // line in the test program.
        use constants::*;
        use self::AssemblerEntry::*;

        let program = [
            Op(DW_OP_lit17),                // -- 17
            Op(DW_OP_dup),                  // -- 17 17
            Op(DW_OP_over),                 // -- 17 17 17
            Op(DW_OP_minus),                // -- 17 0
            Op(DW_OP_swap),                 // -- 0 17
            Op(DW_OP_dup),                  // -- 0 17 17
            Op(DW_OP_plus_uconst), Uleb(1), // -- 0 17 18
            Op(DW_OP_rot),                  // -- 18 0 17
            Op(DW_OP_pick), U8(2),          // -- 18 0 17 18
            Op(DW_OP_pick), U8(3),          // -- 18 0 17 18 18
            Op(DW_OP_minus),                // -- 18 0 17 0
            Op(DW_OP_drop),                 // -- 18 0 17
            Op(DW_OP_swap),                 // -- 18 17 0
            Op(DW_OP_drop),                 // -- 18 17
            Op(DW_OP_minus),                // -- 1
            Op(DW_OP_stack_value),
        ];

        let result = [
            Piece { size_in_bits: None,
                    bit_offset: None,
                    location: Location::Scalar{value: 1},
            },
        ];

        check_eval(&program, Ok(&result), 4, Format::Dwarf32);
    }

    #[test]
    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn test_eval_lit_and_reg() {
        // It's nice if an operation and its arguments can fit on a single
        // line in the test program.
        use constants::*;
        use self::AssemblerEntry::*;

        let mut program = Vec::new();
        program.push(Op(DW_OP_lit0));
        for i in 0..32 {
            program.push(Op(DwOp(DW_OP_lit0.0 + i)));
            program.push(Op(DwOp(DW_OP_breg0.0 + i)));
            program.push(Sleb(i as u64));
            program.push(Op(DW_OP_plus));
            program.push(Op(DW_OP_plus));
        }

        program.push(Op(DW_OP_bregx));
        program.push(Uleb(0x123456));
        program.push(Sleb(0x123456));
        program.push(Op(DW_OP_plus));

        program.push(Op(DW_OP_stack_value));

        let result = [
            Piece { size_in_bits: None,
                    bit_offset: None,
                    location: Location::Scalar{value: 496},
            },
        ];

        check_eval_with_args(&program, Ok(&result), 4, Format::Dwarf32, None, None, None,
                             |eval, mut result| {
                                 while result != EvaluationResult::Complete {
                                     result = eval.resume_with_register(match result {
                                         EvaluationResult::RequiresRegister(regno) => {
                                             regno.wrapping_neg()
                                         },
                                         _ => panic!(),
                                     })?;
                                 }
                                 Ok(result)
                             });
    }

    #[test]
    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn test_eval_memory() {
        // It's nice if an operation and its arguments can fit on a single
        // line in the test program.
        use constants::*;
        use self::AssemblerEntry::*;

        // Indices of marks in the assembly.
        let done = 0;
        let fail = 1;

        let program = [
            Op(DW_OP_addr), U32(0x7fffffff),
            Op(DW_OP_deref),
            Op(DW_OP_const4u), U32(0xfffffffc),
            Op(DW_OP_ne),
            Op(DW_OP_bra), Branch(fail),

            Op(DW_OP_addr), U32(0x7fffffff),
            Op(DW_OP_deref_size), U8(2),
            Op(DW_OP_const4u), U32(0xfffc),
            Op(DW_OP_ne),
            Op(DW_OP_bra), Branch(fail),

            Op(DW_OP_lit1),
            Op(DW_OP_addr), U32(0x7fffffff),
            Op(DW_OP_xderef),
            Op(DW_OP_const4u), U32(0xfffffffd),
            Op(DW_OP_ne),
            Op(DW_OP_bra), Branch(fail),

            Op(DW_OP_lit1),
            Op(DW_OP_addr), U32(0x7fffffff),
            Op(DW_OP_xderef_size), U8(2),
            Op(DW_OP_const4u), U32(0xfffd),
            Op(DW_OP_ne),
            Op(DW_OP_bra), Branch(fail),

            Op(DW_OP_lit17),
            Op(DW_OP_form_tls_address),
            Op(DW_OP_constu), Uleb(!17),
            Op(DW_OP_ne),
            Op(DW_OP_bra), Branch(fail),

            Op(DW_OP_lit17),
            Op(DW_OP_GNU_push_tls_address),
            Op(DW_OP_constu), Uleb(!17),
            Op(DW_OP_ne),
            Op(DW_OP_bra), Branch(fail),

            // Success.
            Op(DW_OP_lit0),
            Op(DW_OP_nop),
            Op(DW_OP_skip), Branch(done),

            Mark(fail),
            Op(DW_OP_lit1),

            Mark(done),
            Op(DW_OP_stack_value),
        ];

        let result = [
            Piece { size_in_bits: None,
                    bit_offset: None,
                    location: Location::Scalar{value: 0},
            },
        ];

        check_eval_with_args(&program, Ok(&result), 4, Format::Dwarf32, None, None, None,
                             |eval, mut result| {
                                 while result != EvaluationResult::Complete {
                                     result = match result {
                                         EvaluationResult::RequiresMemory { address, size, space } => {
                                             let mut v = address << 2;
                                             if let Some(value) = space {
                                                 v += value;
                                             }
                                             eval.resume_with_memory(v & ((1u64 << 8 * size) - 1))?
                                         }
                                         EvaluationResult::RequiresTls(slot) => {
                                             eval.resume_with_tls(!slot)?
                                         }
                                         _ => panic!(),
                                     };
                                 }

                                 Ok(result)
                             });
    }

    #[test]
    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn test_eval_register() {
        // It's nice if an operation and its arguments can fit on a single
        // line in the test program.
        use constants::*;
        use self::AssemblerEntry::*;

        for i in 0..32 {
            let program = [
                Op(DwOp(DW_OP_reg0.0 + i)),
                // Included only in the "bad" run.
                Op(DW_OP_lit23),
            ];
            let ok_result = [
                Piece { size_in_bits: None,
                        bit_offset: None,
                        location: Location::Register{register: i as u64},
                },
            ];

            check_eval(&program[..1], Ok(&ok_result), 4, Format::Dwarf32);

            check_eval(&program, Err(Error::InvalidExpressionTerminator(1)),
                       4, Format::Dwarf32);
        }

        let program = [
            Op(DW_OP_regx), Uleb(0x11223344)
        ];

        let result = [
            Piece { size_in_bits: None,
                    bit_offset: None,
                    location: Location::Register{register: 0x11223344},
            },
        ];

        check_eval(&program, Ok(&result), 4, Format::Dwarf32);
    }

    #[test]
    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn test_eval_context() {
        // It's nice if an operation and its arguments can fit on a single
        // line in the test program.
        use constants::*;
        use self::AssemblerEntry::*;

        // Test `frame_base` and `call_frame_cfa` callbacks.
        let program = [
            Op(DW_OP_fbreg), Sleb((-8i8) as u64),
            Op(DW_OP_call_frame_cfa),
            Op(DW_OP_plus),
            Op(DW_OP_neg),
            Op(DW_OP_stack_value)
        ];

        let result = [
            Piece { size_in_bits: None,
                    bit_offset: None,
                    location: Location::Scalar{value: 9},
            },
        ];

        check_eval_with_args(&program, Ok(&result), 8, Format::Dwarf64,
                             None, None, None, |eval, result| {
                                 match result {
                                     EvaluationResult::RequiresFrameBase => {},
                                     _ => panic!(),
                                 };
                                 match eval.resume_with_frame_base(0x0123456789abcdef)? {
                                     EvaluationResult::RequiresCallFrameCfa => {},
                                     _ => panic!(),
                                 };
                                 eval.resume_with_call_frame_cfa(0xfedcba9876543210)
                             });

        // Test `evaluate_entry_value` callback.
        let program = [
            Op(DW_OP_entry_value), Uleb(8), U64(0x12345678),
            Op(DW_OP_stack_value)
        ];

        let result = [
            Piece { size_in_bits: None,
                    bit_offset: None,
                    location: Location::Scalar{value: 0x12345678},
            },
        ];

        check_eval_with_args(&program, Ok(&result), 8, Format::Dwarf64,
                             None, None, None, |eval, result| {
                                 let entry_value = match result {
                                     EvaluationResult::RequiresEntryValue(expression) => {
                                         parse_u64(expression).map(|(_, value)| value)?
                                     },
                                     _ => panic!(),
                                 };
                                 eval.resume_with_entry_value(entry_value)
                             });

        // Test missing `object_address` field.
        let program = [
            Op(DW_OP_push_object_address),
        ];

        check_eval_with_args(&program, Err(Error::InvalidPushObjectAddress),
                             4, Format::Dwarf32, None, None, None, |_, _| panic!());

        // Test `object_address` field.
        let program = [
            Op(DW_OP_push_object_address),
            Op(DW_OP_stack_value),
        ];

        let result = [
            Piece { size_in_bits: None,
                    bit_offset: None,
                    location: Location::Scalar{value: 0xff},
            },
        ];

        check_eval_with_args(&program, Ok(&result), 8, Format::Dwarf64,
                             Some(0xff), None, None, |_, result| Ok(result));

        // Test `initial_value` field.
        let program = [
        ];

        let result = [
            Piece { size_in_bits: None,
                    bit_offset: None,
                    location: Location::Address{address: 0x12345678},
            },
        ];

        check_eval_with_args(&program, Ok(&result), 8, Format::Dwarf64,
                             None, Some(0x12345678), None, |_, result| Ok(result));
    }

    #[test]
    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn test_eval_empty_stack() {
        // It's nice if an operation and its arguments can fit on a single
        // line in the test program.
        use constants::*;
        use self::AssemblerEntry::*;

        let program = [
            Op(DW_OP_stack_value)
        ];

        check_eval(&program, Err(Error::NotEnoughStackItems), 4, Format::Dwarf32);
    }

    #[test]
    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn test_eval_call() {
        // It's nice if an operation and its arguments can fit on a single
        // line in the test program.
        use constants::*;
        use self::AssemblerEntry::*;

        let program = [
            Op(DW_OP_lit23),
            Op(DW_OP_call2), U16(0x7755),
            Op(DW_OP_call4), U32(0x7755aaee),
            Op(DW_OP_call_ref), U32(0x7755aaee),
            Op(DW_OP_stack_value)
        ];

        let result = [
            Piece { size_in_bits: None,
                    bit_offset: None,
                    location: Location::Scalar{value: 23},
            },
        ];

        check_eval_with_args(&program, Ok(&result), 4, Format::Dwarf32,
                             None, None, None, |eval, result| {
                                 let buf = EndianBuf::<LittleEndian>::new(&[]);
                                 match result {
                                     EvaluationResult::RequiresAtLocation(_) => {},
                                     _ => panic!(),
                                 };

                                 eval.resume_with_at_location(buf)?;

                                 match result {
                                     EvaluationResult::RequiresAtLocation(_) => {},
                                     _ => panic!(),
                                 };

                                 eval.resume_with_at_location(buf)?;

                                 match result {
                                     EvaluationResult::RequiresAtLocation(_) => {},
                                     _ => panic!(),
                                 };

                                 eval.resume_with_at_location(buf)
                             });

        // DW_OP_lit2 DW_OP_mul
        const SUBR: &'static [u8] = &[0x32, 0x1e];

        let result = [
            Piece { size_in_bits: None,
                    bit_offset: None,
                    location: Location::Scalar{value: 184},
            },
        ];

        check_eval_with_args(&program, Ok(&result), 4, Format::Dwarf32,
                             None, None, None, |eval, result| {
                                 let buf = EndianBuf::<LittleEndian>::new(SUBR);
                                 match result {
                                     EvaluationResult::RequiresAtLocation(_) => {},
                                     _ => panic!(),
                                 };

                                 eval.resume_with_at_location(buf)?;

                                 match result {
                                     EvaluationResult::RequiresAtLocation(_) => {},
                                     _ => panic!(),
                                 };

                                 eval.resume_with_at_location(buf)?;

                                 match result {
                                     EvaluationResult::RequiresAtLocation(_) => {},
                                     _ => panic!(),
                                 };

                                 eval.resume_with_at_location(buf)
                             });
    }

    #[test]
    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn test_eval_pieces() {
        // It's nice if an operation and its arguments can fit on a single
        // line in the test program.
        use constants::*;
        use self::AssemblerEntry::*;

        // Example from DWARF 2.6.1.3.
        let program = [
            Op(DW_OP_reg3),
            Op(DW_OP_piece), Uleb(4),
            Op(DW_OP_reg4),
            Op(DW_OP_piece), Uleb(2),
        ];

        let result = [
            Piece { size_in_bits: Some(32), bit_offset: None,
                    location: Location::Register { register: 3 } },
            Piece { size_in_bits: Some(16), bit_offset: None,
                    location: Location::Register { register: 4 } },
        ];

        check_eval(&program, Ok(&result), 4, Format::Dwarf32);

        // Example from DWARF 2.6.1.3 (but hacked since dealing with fbreg
        // in the tests is a pain).
        let program = [
            Op(DW_OP_reg0),
            Op(DW_OP_piece), Uleb(4),
            Op(DW_OP_piece), Uleb(4),
            Op(DW_OP_addr), U32(0x7fffffff),
            Op(DW_OP_piece), Uleb(4),
        ];

        let result = [
            Piece { size_in_bits: Some(32), bit_offset: None,
                    location: Location::Register { register: 0 } },
            Piece { size_in_bits: Some(32), bit_offset: None,
                    location: Location::Empty },
            Piece { size_in_bits: Some(32), bit_offset: None,
                    location: Location::Address { address: 0x7fffffff } },
        ];

        check_eval(&program, Ok(&result), 4, Format::Dwarf32);

        let program = [
            Op(DW_OP_implicit_value), Uleb(5),
            U8(23), U8(24), U8(25), U8(26), U8(0),
        ];

        const BYTES: &'static [u8] = &[23, 24, 25, 26, 0];

        let result = [
            Piece { size_in_bits: None, bit_offset: None,
                    location: Location::Bytes { value: BYTES } },
        ];

        check_eval(&program, Ok(&result), 4, Format::Dwarf32);

        let program = [
            Op(DW_OP_lit7),
            Op(DW_OP_stack_value),
            Op(DW_OP_bit_piece), Uleb(5), Uleb(0),
            Op(DW_OP_bit_piece), Uleb(3), Uleb(0),
        ];

        let result = [
            Piece { size_in_bits: Some(5), bit_offset: Some(0),
                    location: Location::Scalar { value: 7 } },
            Piece { size_in_bits: Some(3), bit_offset: Some(0),
                    location: Location::Empty },
        ];

        check_eval(&program, Ok(&result), 4, Format::Dwarf32);

        let program = [
            Op(DW_OP_lit7),
        ];

        let result = [
            Piece { size_in_bits: None, bit_offset: None,
                    location: Location::Address { address: 7 } },
        ];

        check_eval(&program, Ok(&result), 4, Format::Dwarf32);

        let program = [
            Op(DW_OP_implicit_pointer), U32(0x12345678), Sleb(0x123),
        ];

        let result = [
            Piece { size_in_bits: None, bit_offset: None,
                    location: Location::ImplicitPointer {
                        value: DebugInfoOffset(0x12345678),
                        byte_offset: 0x123,
                    },
            },
        ];

        check_eval(&program, Ok(&result), 4, Format::Dwarf32);
    }

    #[test]
    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn test_eval_max_iterations() {
        // It's nice if an operation and its arguments can fit on a single
        // line in the test program.
        use constants::*;
        use self::AssemblerEntry::*;

        let program = [
            Mark(1),
            Op(DW_OP_skip), Branch(1),
        ];

        check_eval_with_args(&program, Err(Error::TooManyIterations),
                             4, Format::Dwarf32, None, None, Some(150),
                             |_, _| panic!());
    }
}
