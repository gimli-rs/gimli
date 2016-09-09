//! Functions for parsing and evaluating DWARF expressions.

use constants;
use parser::{Error, ParseResult, Format, parse_u8e, parse_i8e, parse_u16, parse_i16, parse_u32,
             parse_i32, parse_u64, parse_i64, parse_unsigned_lebe, parse_signed_lebe, parse_word,
             parse_address, parse_length_uleb_value};
use endianity::{Endianity, EndianBuf};
use unit::{UnitOffset, DebugInfoOffset};
use std::marker::PhantomData;
#[cfg(test)]
use endianity::LittleEndian;
#[cfg(test)]
use leb128;
#[cfg(test)]
use std::io::Write;

/// A reference to a DIE, either relative to the current CU or
/// relative to the section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DieReference {
    /// A CU-relative reference.
    UnitRef(UnitOffset),
    /// A section-relative reference.
    DebugInfoRef(DebugInfoOffset),
}

/// Supply information to a DWARF expression evaluation.
pub trait EvaluationContext<'input> {
    /// Read the indicated number of bytes from memory at the
    /// indicated address.  The number of bytes is guaranteed to be
    /// less than the word size of the target architecture.
    ///
    /// If not `None`, the "space" argument is a target-specific
    /// address space value.
    fn read_memory(&self, address: u64, size: u8, space: Option<u64>) -> ParseResult<u64>;
    /// Read the indicated register and return its value.
    fn read_register(&self, register: u64) -> ParseResult<u64>;
    /// Compute the frame base using `DW_AT_frame_base`.
    fn frame_base(&self) -> ParseResult<u64>;
    /// Compute the address of a thread-local variable.
    fn read_tls(&self, index: u64) -> ParseResult<u64>;
    /// Compute the call frame CFA.
    fn call_frame_cfa(&self) -> ParseResult<u64>;
    /// Find the `DW_AT_location` attribute of the given DIE and
    /// return the corresponding DWARF expression.  If no expression
    /// can be found, this should return an empty slice.
    fn get_at_location(&self, die: DieReference) -> ParseResult<&'input [u8]>;
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
#[derive(Debug, PartialEq, Eq)]
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
}

/// A single location of a piece of the result of a DWARF expression.
#[derive(Debug, PartialEq, Eq)]
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
}

/// The description of a single piece of the result of a DWARF
/// expression.
#[derive(Debug, PartialEq, Eq)]
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
                              bytecode: &'input [u8],
                              offset: i16)
                              -> ParseResult<EndianBuf<'input, Endian>>
    where Endian: Endianity
{
    let pcbytes: &[u8] = pc.into();
    let this_len = pcbytes.len();
    let full_len = bytecode.len();
    let new_pc = (full_len - this_len).wrapping_add(offset as usize);
    if new_pc > full_len {
        Err(Error::BadBranchTarget(new_pc))
    } else {
        Ok(EndianBuf::new(&bytecode[new_pc..]))
    }
}

#[test]
fn test_compute_pc() {
    // Contents don't matter for this test, just length.
    let bytes = [0, 1, 2, 3, 4];
    let bytecode = &bytes[..];
    let ebuf = EndianBuf::<LittleEndian>::new(bytecode);

    match compute_pc(ebuf, bytecode, 0) {
        Ok(val) => {
            let valbytes: &[u8] = val.into();
            assert_eq!(valbytes.len(), bytecode.len());
        }
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    }

    match compute_pc(ebuf, bytecode, -1) {
        Err(Error::BadBranchTarget(_)) => {}
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    }

    match compute_pc(ebuf, bytecode, 5) {
        Ok(val) => {
            let valbytes: &[u8] = val.into();
            assert_eq!(valbytes.len(), 0);
        }
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    }

    match compute_pc(EndianBuf::<LittleEndian>::new(&bytes[3..]), bytecode, -2) {
        Ok(val) => {
            let valbytes: &[u8] = val.into();
            assert_eq!(valbytes.len(), bytecode.len() - 1);
        }
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    }

    match compute_pc(EndianBuf::<LittleEndian>::new(&bytes[2..]), bytecode, 2) {
        Ok(val) => {
            let valbytes: &[u8] = val.into();
            assert_eq!(valbytes.len(), bytecode.len() - 4);
        }
        otherwise => panic!("Unexpected result: {:?}", otherwise),
    }
}

impl<'input, Endian> Operation<'input, Endian>
    where Endian: Endianity
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
                 bytecode: &'input [u8],
                 address_size: u8,
                 format: Format)
                 -> ParseResult<(EndianBuf<'input, Endian>, Operation<'input, Endian>)>
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
                    Operation::Call { offset: DieReference::UnitRef(UnitOffset(value as u64)) }))
            }
            constants::DW_OP_call4 => {
                let (newbytes, value) = try!(parse_u32(bytes));
                Ok((newbytes,
                    Operation::Call { offset: DieReference::UnitRef(UnitOffset(value as u64)) }))
            }
            constants::DW_OP_call_ref => {
                let (newbytes, value) = try!(parse_word(bytes, format));
                Ok((newbytes,
                    Operation::Call { offset: DieReference::DebugInfoRef(DebugInfoOffset(value)) }))
            }
            constants::DW_OP_form_tls_address => Ok((bytes, Operation::TLS)),
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

            _ => return Err(Error::InvalidExpression(name)),
        }
    }
}

#[cfg(test)]
fn check_op_parse_simple(input: &[u8],
                         expect: &Operation<LittleEndian>,
                         address_size: u8,
                         format: Format) {
    let value = Operation::parse(EndianBuf::<LittleEndian>::new(input),
                                 input,
                                 address_size,
                                 format);
    match value {
        Ok((pc, val)) => {
            assert_eq!(val, *expect);
            let pcbytes: &[u8] = pc.into();
            assert_eq!(pcbytes.len(), 0);
        }
        _ => panic!("Unexpected result"),
    }
}

#[cfg(test)]
fn check_op_parse_failure(input: &[u8], expect: Error, address_size: u8, format: Format) {
    match Operation::parse(EndianBuf::<LittleEndian>::new(input),
                           input,
                           address_size,
                           format) {
        Err(x) => {
            assert_eq!(x, expect);
        }

        _ => panic!("Unexpected result"),
    }
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
        let input = [opcode.0];
        check_op_parse_simple(&input[..], result, address_size, format);
    }
}

#[test]
fn test_op_parse_twobyte() {
    // Doesn't matter for this test.
    let address_size = 4;
    let format = Format::Dwarf32;

    let inputs =
        [(constants::DW_OP_const1u, 23, Operation::Literal { value: 23 }),
         (constants::DW_OP_const1s, (-23i8) as u8, Operation::Literal { value: (-23i64) as u64 }),
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
        let input = [opcode.0, arg];

        // Too short.
        check_op_parse_failure(&input[..1], Error::UnexpectedEof, address_size, format);
        check_op_parse_simple(&input[..], result, address_size, format);
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

        let arglow = (arg & 0xff) as u8;
        let arghigh = (arg >> 8) as u8;

        let input = [opcode.0, arglow, arghigh];

        // Too short.
        check_op_parse_failure(&input[..1], Error::UnexpectedEof, address_size, format);
        check_op_parse_failure(&input[..2], Error::UnexpectedEof, address_size, format);

        check_op_parse_simple(&input[..], result, address_size, Format::Dwarf32);
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

        // Too short.
        check_op_parse_failure(&input[..1], Error::UnexpectedEof, ADDRESS_SIZE, FORMAT);
        check_op_parse_failure(&input[..2], Error::UnexpectedEof, ADDRESS_SIZE, FORMAT);

        let expect = if input[0] == constants::DW_OP_bra.0 {
            Operation::Bra { target: EndianBuf::<LittleEndian>::new(target) }
        } else {
            assert!(input[0] == constants::DW_OP_skip.0);
            Operation::Skip { target: EndianBuf::<LittleEndian>::new(target) }
        };

        check_op_parse_simple(input, &expect, ADDRESS_SIZE, FORMAT);
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
        let (op, mut val, ref expect) = *item;

        let mut contents = [op.0, 0, 0, 0, 0];
        for i in 1..5 {
            contents[i] = (val & 0xff) as u8;
            val >>= 8;
        }

        // Too short.
        let input = &contents;
        check_op_parse_failure(&input[..1], Error::UnexpectedEof, address_size, format);
        check_op_parse_failure(&input[..2], Error::UnexpectedEof, address_size, format);
        check_op_parse_failure(&input[..3], Error::UnexpectedEof, address_size, format);

        check_op_parse_simple(input, expect, address_size, format);
    }
}

#[test]
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
        let (op, mut val, ref expect) = *item;

        let mut contents = [op.0, 0, 0, 0, 0, 0, 0, 0, 0];
        for i in 1..9 {
            contents[i] = (val & 0xff) as u8;
            val >>= 8;
        }

        // Too short.
        let input = &contents;
        for i in 1..8 {
            check_op_parse_failure(&input[..i], Error::UnexpectedEof, address_size, format);
        }

        check_op_parse_simple(input, expect, address_size, format);
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
        let mut inputs = vec!(
            (constants::DW_OP_consts.0, Operation::Literal { value: *value as u64}),
            (constants::DW_OP_fbreg.0, Operation::FrameOffset { offset: *value }),
        );

        for i in 0..32 {
            inputs.push((constants::DW_OP_breg0.0 + i,
                         Operation::RegisterOffset {
                register: i as u64,
                offset: *value,
            }));
        }

        for item in inputs.iter() {
            let (op, ref expect) = *item;

            let mut buffer = Vec::new();
            buffer.push(op);
            leb128::write::signed(&mut buffer, *value).unwrap();

            // Too short.
            for i in 1..buffer.len() - 1 {
                check_op_parse_failure(&buffer[..i], Error::UnexpectedEof, address_size, format)
            }

            check_op_parse_simple(&buffer[..], expect, address_size, format);
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
        let mut inputs = vec!(
            (constants::DW_OP_constu, Operation::Literal { value: *value}),
            (constants::DW_OP_plus_uconst, Operation::PlusConstant { value: *value }),
            (constants::DW_OP_regx, Operation::Register { register: *value }),
        );

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

            let mut buffer = Vec::new();
            buffer.push(op.0);
            leb128::write::unsigned(&mut buffer, *value).unwrap();

            // Too short.
            for i in 1..buffer.len() - 1 {
                check_op_parse_failure(&buffer[..i], Error::UnexpectedEof, address_size, format)
            }

            check_op_parse_simple(&buffer[..], expect, address_size, format);
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
            let mut buffer = vec![constants::DW_OP_bregx.0];
            leb128::write::unsigned(&mut buffer, *v1).unwrap();
            leb128::write::signed(&mut buffer, *v2).unwrap();

            // Too short.
            for i in 1..buffer.len() - 1 {
                check_op_parse_failure(&buffer[..i], Error::UnexpectedEof, address_size, format)
            }

            check_op_parse_simple(&buffer[..],
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
            let mut buffer = vec![constants::DW_OP_bit_piece.0];
            leb128::write::unsigned(&mut buffer, *v1).unwrap();
            leb128::write::unsigned(&mut buffer, *v2).unwrap();

            // Too short.
            for i in 1..buffer.len() - 1 {
                check_op_parse_failure(&buffer[..i], Error::UnexpectedEof, address_size, format)
            }

            check_op_parse_simple(&buffer[..],
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
    let mut buffer = vec![constants::DW_OP_implicit_value.0];
    leb128::write::unsigned(&mut buffer, data.len() as u64).unwrap();
    buffer.write_all(data).unwrap();

    // Too short.
    for i in 1..buffer.len() - 1 {
        check_op_parse_failure(&buffer[..i], Error::UnexpectedEof, address_size, format)
    }

    check_op_parse_simple(&buffer[..],
                          &Operation::ImplicitValue { data: &data[..] },
                          address_size,
                          format);
}

/// A DWARF expression evaluation.
pub struct Evaluation<'context, 'input, Endian>
    where Endian: 'context + Endianity,
          'input: 'context
{
    bytecode: &'input [u8],
    address_size: u8,
    format: Format,
    initial_value: Option<u64>,
    object_address: Option<u64>,
    callbacks: &'context mut EvaluationContext<'input>,
    max_iterations: Option<u32>,

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
    expression_stack: Vec<(EndianBuf<'input, Endian>, &'input [u8])>,

    phantom: PhantomData<Endian>,
}

impl<'context, 'input, Endian> Evaluation<'context, 'input, Endian>
    where Endian: 'context + Endianity,
          'input: 'context
{
    /// Create a new DWARF expression evaluator.
    pub fn new(bytecode: &'input [u8],
               address_size: u8,
               format: Format,
               callbacks: &'context mut EvaluationContext<'input>)
               -> Evaluation<'context, 'input, Endian> {
        Evaluation::<'context, 'input, Endian> {
            bytecode: bytecode,
            address_size: address_size,
            format: format,
            initial_value: None,
            object_address: None,
            callbacks: callbacks,
            max_iterations: None,
            addr_mask: if address_size == 8 {
                !0u64
            } else {
                (1 << 8 * address_size as u64) - 1
            },
            stack: Vec::new(),
            expression_stack: Vec::new(),
            pc: EndianBuf::<Endian>::new(bytecode),
            phantom: PhantomData,
        }
    }

    /// Set an initial value to be pushed on the DWARF expression
    /// evaluator's stack.  This can be used in cases like
    /// `DW_AT_vtable_elem_location`, which require a value on the
    /// stack before evaluation commences.
    pub fn set_initial_value(&mut self, value: u64) {
        self.initial_value = Some(value);
    }

    /// Set the enclosing object's address, as used by
    /// `DW_OP_push_object_address`
    pub fn set_object_address(&mut self, value: u64) {
        self.object_address = Some(value);
    }

    /// Set the maximum number of iterations to be allowed by the
    /// expression evaluator.  The default is `None`.  This value can
    /// be set to avoid denial of service attacks by bad DWARF
    /// bytecode.
    pub fn set_max_iterations(&mut self, value: u32) {
        self.max_iterations = Some(value);
    }

    fn pop(&mut self) -> ParseResult<u64> {
        match self.stack.pop() {
            Some(value) => Ok(value & self.addr_mask),
            None => Err(Error::NotEnoughStackItems),
        }
    }

    fn pop_signed(&mut self) -> ParseResult<i64> {
        match self.stack.pop() {
            Some(value) => {
                let mut value = value & self.addr_mask;
                if self.address_size < 8 && (value & (1u64 << (8 * self.address_size - 1))) != 0 {
                    // Sign extend.
                    value = value | !self.addr_mask;
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
                              -> ParseResult<(bool, bool, Location<'input>)> {
        let mut terminated = false;
        let mut piece_end = false;
        let mut current_location = Location::Empty;

        match *operation {
            Operation::Deref { size, space } => {
                let addr = try!(self.pop());
                let addr_space = if space { Some(try!(self.pop())) } else { None };
                let addr = try!(self.callbacks.read_memory(addr, size, addr_space));
                self.push(addr);
            }

            Operation::Drop => {
                try!(self.pop());
            }
            Operation::Pick { index } => {
                let len = self.stack.len();
                let index = index as usize;
                if index >= len {
                    return Err(Error::NotEnoughStackItems);
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
                if v2 == 0 {
                    return Err(Error::DivisionByZero);
                }
                self.push((v2 / v1) as u64);
            }
            Operation::Minus => {
                let v1 = try!(self.pop());
                let v2 = try!(self.pop());
                self.push(v2.wrapping_sub(v1));
            }
            Operation::Mod => {
                let v1 = try!(self.pop());
                let v2 = try!(self.pop());
                if v2 == 0 {
                    return Err(Error::DivisionByZero);
                }
                self.push(v2 % v1);
            }
            Operation::Mul => {
                let v1 = try!(self.pop());
                let v2 = try!(self.pop());
                self.push(v2 * v1);
            }
            Operation::Neg => {
                let v = try!(self.pop_signed());
                self.push(-v as u64);
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
                self.push(v2 << v1);
            }
            Operation::Shr => {
                let v1 = try!(self.pop());
                let v2 = try!(self.pop());
                self.push(v2 >> v1);
            }
            Operation::Shra => {
                let v1 = try!(self.pop_signed());
                let v2 = try!(self.pop());
                self.push((v2 >> v1) as u64);
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
                let value = try!(self.callbacks.read_register(register));
                self.push(value.wrapping_add(offset as u64));
            }

            Operation::FrameOffset { offset } => {
                let value = try!(self.callbacks.frame_base());
                self.push(value + offset as u64);
            }

            Operation::Nop => {}

            Operation::PushObjectAddress => {
                if let Some(value) = self.object_address {
                    self.push(value);
                } else {
                    return Err(Error::InvalidPushObjectAddress);
                }
            }

            Operation::Call { offset } => {
                let newbytes = try!(self.callbacks.get_at_location(offset));
                if newbytes.len() > 0 {
                    self.expression_stack.push((self.pc, self.bytecode));
                    self.pc = EndianBuf::new(newbytes);
                    self.bytecode = newbytes;
                }
            }

            Operation::TLS => {
                let value = try!(self.pop());
                let addr = try!(self.callbacks.read_tls(value));
                self.push(addr);
            }

            Operation::CallFrameCFA => {
                let cfa = try!(self.callbacks.call_frame_cfa());
                self.push(cfa);
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

            Operation::Piece { size_in_bits: _, bit_offset: _ } => {
                piece_end = true;
            }
        }

        Ok((piece_end, terminated, current_location))
    }

    /// Evaluate a DWARF expression.
    pub fn evaluate(&mut self) -> ParseResult<Vec<Piece<'input>>>
        where Endian: Endianity
    {
        if let Some(value) = self.initial_value {
            self.push(value);
        }

        // The number of instructions we've processed.
        let mut iteration = 0;

        // The results.
        let mut result = Vec::new();

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

            iteration += 1;
            if let Some(max_iterations) = self.max_iterations {
                if iteration > max_iterations {
                    return Err(Error::TooManyIterations);
                }
            }

            let (newpc, operation) =
                try!(Operation::parse(self.pc, self.bytecode, self.address_size, self.format));
            self.pc = newpc;

            let (piece_end, terminated, mut current_location) =
                try!(self.evaluate_one_operation(&operation));

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
                        if !result.is_empty() {
                            // We saw a piece earlier and then some
                            // unterminated piece.  It's not clear this is
                            // well-defined.
                            return Err(Error::InvalidPiece);
                        }
                        result.push(Piece {
                            size_in_bits: None,
                            bit_offset: None,
                            location: current_location,
                        });
                    }

                    Operation::Piece { size_in_bits, bit_offset } => {
                        result.push(Piece {
                            size_in_bits: Some(size_in_bits),
                            bit_offset: bit_offset,
                            location: current_location,
                        });
                    }

                    _ => {
                        let pcbytes: &[u8] = self.pc.into();
                        let value = self.bytecode.len() - pcbytes.len() - 1;
                        return Err(Error::InvalidExpressionTerminator(value));
                    }
                }
            }
        }

        // If no pieces have been seen, use the stack top as the
        // result.
        if result.is_empty() {
            result.push(Piece {
                size_in_bits: None,
                bit_offset: None,
                location: Location::Address { address: try!(self.pop()) },
            });
        }

        Ok(result)
    }
}

#[cfg(test)]
#[derive(Clone, Copy)]
struct TestEvaluationContext {
    base: ParseResult<u64>,
    cfa: ParseResult<u64>,
    at_location: ParseResult<&'static [u8]>,

    object_address: Option<u64>,
    initial_value: Option<u64>,
    max_iterations: Option<u32>,
}

#[cfg(test)]
impl<'input> EvaluationContext<'input> for TestEvaluationContext {
    fn read_memory(&self, addr: u64, nbytes: u8, space: Option<u64>) -> ParseResult<u64> {
        let mut result = addr << 2;
        if let Some(value) = space {
            result += value;
        }
        Ok(result & ((1u64 << 8 * nbytes) - 1))
    }
    fn read_register(&self, regno: u64) -> ParseResult<u64> {
        Ok(regno.wrapping_neg())
    }
    fn frame_base(&self) -> ParseResult<u64> {
        self.base
    }
    fn read_tls(&self, slot: u64) -> ParseResult<u64> {
        Ok(!slot)
    }
    fn call_frame_cfa(&self) -> ParseResult<u64> {
        self.cfa
    }
    fn get_at_location(&self, _: DieReference) -> ParseResult<&'input [u8]> {
        self.at_location
    }
}

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
fn check_eval_with_context(program: &[AssemblerEntry],
                           expect: ParseResult<&[Piece]>,
                           address_size: u8,
                           format: Format,
                           context: TestEvaluationContext) {
    let bytes = assemble(program);

    let mut eval_context = context.clone();
    let mut eval = Evaluation::<LittleEndian>::new(&bytes, address_size, format, &mut eval_context);

    if let Some(val) = context.object_address {
        eval.set_object_address(val);
    }
    if let Some(val) = context.initial_value {
        eval.set_initial_value(val);
    }
    if let Some(val) = context.max_iterations {
        eval.set_max_iterations(val);
    }

    match (eval.evaluate(), expect) {
        (Ok(vec), Ok(pieces)) => {
            assert_eq!(vec.len(), pieces.len());
            for i in 0..pieces.len() {
                assert_eq!(vec[i], pieces[i]);
            }
        }
        (Err(f1), Err(f2)) => {
            assert_eq!(f1, f2);
        }
        _ => panic!("Unexpected result"),
    }
}

#[cfg(test)]
fn check_eval(program: &[AssemblerEntry],
              expect: ParseResult<&[Piece]>,
              address_size: u8,
              format: Format) {
    let context = TestEvaluationContext {
        base: Ok(0),
        cfa: Ok(0),
        at_location: Ok(&[]),
        initial_value: None,
        object_address: None,
        max_iterations: None,
    };

    check_eval_with_context(program, expect, address_size, format, context);
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
        Op(DW_OP_skip), Branch(done),

        // Mod is unsigned.
        Op(DW_OP_const1s), U8(0xfe),
        Op(DW_OP_const1s), U8(2),
        Op(DW_OP_mod),
        Op(DW_OP_neg),
        Op(DW_OP_plus_uconst), Uleb(1),
        Op(DW_OP_skip), Branch(done),

        // Overflow is defined for multiplication.
        Op(DW_OP_const4u), U32(0x80000001),
        Op(DW_OP_lit2),
        Op(DW_OP_mul),
        Op(DW_OP_lit2),
        Op(DW_OP_eq),
        Op(DW_OP_skip), Branch(done),

        Op(DW_OP_const4u), U32(0xf0f0f0f0),
        Op(DW_OP_const4u), U32(0xf0f0f0f0),
        Op(DW_OP_xor),
        Op(DW_OP_skip), Branch(done),

        Op(DW_OP_const4u), U32(0xf0f0f0f0),
        Op(DW_OP_const4u), U32(0xf0f0f0f0),
        Op(DW_OP_or),
        Op(DW_OP_not),
        Op(DW_OP_skip), Branch(done),

        // In 32 bit mode, values are truncated.
        Op(DW_OP_const8u), U64(0xffffffff00000000),
        Op(DW_OP_lit2),
        Op(DW_OP_div),
        Op(DW_OP_skip), Branch(done),

        Op(DW_OP_const1u), U8(0xff),
        Op(DW_OP_lit1),
        Op(DW_OP_shl),
        Op(DW_OP_const2u), U16(0x1fe),
        Op(DW_OP_eq),
        Op(DW_OP_skip), Branch(done),

        Op(DW_OP_const1u), U8(0xff),
        Op(DW_OP_const1u), U8(50),
        Op(DW_OP_shl),
        Op(DW_OP_skip), Branch(done),

        // Absurd shift.
        Op(DW_OP_const1u), U8(0xff),
        Op(DW_OP_const1s), U8(0xff),
        Op(DW_OP_shl),
        Op(DW_OP_skip), Branch(done),

        Op(DW_OP_const1s), U8(0xff),
        Op(DW_OP_lit1),
        Op(DW_OP_shr),
        Op(DW_OP_const4u), U32(0x7fffffff),
        Op(DW_OP_eq),
        Op(DW_OP_skip), Branch(done),

        Op(DW_OP_const1s), U8(0xff),
        Op(DW_OP_const1u), U8(0xff),
        Op(DW_OP_shr),
        Op(DW_OP_skip), Branch(done),

        Op(DW_OP_const1s), U8(0xff),
        Op(DW_OP_lit1),
        Op(DW_OP_shra),
        Op(DW_OP_not),
        Op(DW_OP_skip), Branch(done),

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

    check_eval(&program, Ok(&result), 4, Format::Dwarf32);
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

    check_eval(&program, Ok(&result), 4, Format::Dwarf32);
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

    let mut context = TestEvaluationContext {
        base: Ok(0x0123456789abcdef),
        cfa: Ok(0xfedcba9876543210),
        at_location: Ok(&[]),
        initial_value: None,
        object_address: None,
        max_iterations: None,
    };

    let program = [
        Op(DW_OP_fbreg), Sleb(0),
        Op(DW_OP_call_frame_cfa),
        Op(DW_OP_plus),
        Op(DW_OP_neg),
        Op(DW_OP_stack_value)
    ];

    let result = [
        Piece { size_in_bits: None,
                bit_offset: None,
                location: Location::Scalar{value: 1},
        },
    ];

    check_eval_with_context(&program, Ok(&result), 8, Format::Dwarf64, context);

    let program = [
        Op(DW_OP_push_object_address),
    ];

    check_eval_with_context(&program, Err(Error::InvalidPushObjectAddress),
                            4, Format::Dwarf32, context);

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

    context.object_address = Some(0xff);
    check_eval_with_context(&program, Ok(&result), 8, Format::Dwarf64, context);

    let program = [
    ];

    let result = [
        Piece { size_in_bits: None,
                bit_offset: None,
                location: Location::Address{address: 0x12345678},
        },
    ];

    context.initial_value = Some(0x12345678);
    check_eval_with_context(&program, Ok(&result), 8, Format::Dwarf64, context);
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

    let mut context = TestEvaluationContext {
        base: Ok(0x0123456789abcdef),
        cfa: Ok(0xfedcba9876543210),
        at_location: Ok(&[]),
        initial_value: None,
        object_address: None,
        max_iterations: None,
    };

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

    check_eval_with_context(&program, Ok(&result), 4, Format::Dwarf32, context);

    // DW_OP_lit2 DW_OP_mul
    const SUBR: &'static [u8] = &[0x32, 0x1e];
    context.at_location = Ok(SUBR);

    let result = [
        Piece { size_in_bits: None,
                bit_offset: None,
                location: Location::Scalar{value: 184},
        },
    ];

    check_eval_with_context(&program, Ok(&result), 4, Format::Dwarf32, context);
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
}

#[test]
#[cfg_attr(rustfmt, rustfmt_skip)]
fn test_eval_max_iterations() {
    // It's nice if an operation and its arguments can fit on a single
    // line in the test program.
    use constants::*;
    use self::AssemblerEntry::*;

    let context = TestEvaluationContext {
        base: Ok(0),
        cfa: Ok(0),
        at_location: Ok(&[]),
        initial_value: None,
        object_address: None,
        max_iterations: Some(150),
    };

    let program = [
        Mark(1),
        Op(DW_OP_skip), Branch(1),
    ];

    check_eval_with_context(&program, Err(Error::TooManyIterations),
                            4, Format::Dwarf32, context);
}
