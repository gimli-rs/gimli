use std::borrow::Cow;
use std::fmt::Debug;

use endianity::Endianity;
use leb128;
use parser::{Error, Result, Format, u64_to_offset};

/// A trait for reading the data from a DWARF section.
///
/// All read operations advance the section offset of the reader
/// unless specified otherwise.
///
pub trait Reader: Debug + Clone {
    /// The endianity of bytes that are read.
    type Endian: Endianity;

    /// Return the number of bytes remaining.
    fn len(&self) -> usize;

    /// Return true if the number of bytes remaining is zero.
    fn is_empty(&self) -> bool;

    /// Set the number of bytes remaining to zero.
    fn empty(&mut self);

    /// Set the number of bytes remaining to the specified length.
    fn truncate(&mut self, len: usize) -> Result<()>;

    /// Return the offset of this reader's data relative to the start of
    /// the given base reader's data.
    ///
    /// May panic if this reader's data is not contained within the given
    /// base reader's data.
    fn offset_from(&self, base: &Self) -> usize;

    /// Find the index of the first occurence of the given byte.
    /// The offset of the reader is not changed.
    fn find(&self, byte: u8) -> Option<usize>;

    /// Discard the specified number of bytes.
    fn skip(&mut self, len: usize) -> Result<()>;

    /// Split a reader in two.
    ///
    /// A new reader is returned that can be used to read the next
    /// `len` bytes, and `self` is advanced so that it reads the remainder.
    fn split(&mut self, len: usize) -> Result<Self>;

    /// Return all remaining data as a clone-on-write slice.
    ///
    /// The slice will be borrowed where possible, but some readers may
    /// always return an owned vector.
    ///
    /// Does not advance the reader.
    fn to_slice(&self) -> Cow<[u8]>;

    /// Convert all remaining data to a clone-on-write string.
    ///
    /// The string will be borrowed where possible, but some readers may
    /// always return an owned string.
    ///
    /// Does not advance the reader.
    ///
    /// Returns an error if the data contains invalid characters.
    fn to_string(&self) -> Result<Cow<str>>;

    /// Convert all remaining data to a clone-on-write string, including invalid characters.
    ///
    /// The string will be borrowed where possible, but some readers may
    /// always return an owned string.
    ///
    /// Does not advance the reader.
    fn to_string_lossy(&self) -> Cow<str>;

    /// Read a u8 array.
    fn read_u8_array<A>(&mut self) -> Result<A> where A: Sized + Default + AsMut<[u8]>;

    /// Read a u8.
    fn read_u8(&mut self) -> Result<u8>;

    /// Read an i8.
    fn read_i8(&mut self) -> Result<i8>;

    /// Read a u16.
    fn read_u16(&mut self) -> Result<u16>;

    /// Read an i16.
    fn read_i16(&mut self) -> Result<i16>;

    /// Read a u32.
    fn read_u32(&mut self) -> Result<u32>;

    /// Read an i32.
    fn read_i32(&mut self) -> Result<i32>;

    /// Read a u64.
    fn read_u64(&mut self) -> Result<u64>;

    /// Read an i64.
    fn read_i64(&mut self) -> Result<i64>;

    /// Read a null-terminated slice, and return it (excluding the null).
    fn read_null_terminated_slice(&mut self) -> Result<Self> {
        if let Some(idx) = self.find(0) {
            let val = self.split(idx)?;
            self.skip(1)?;
            Ok(val)
        } else {
            Err(Error::UnexpectedEof)
        }
    }

    /// Read an unsigned LEB128 encoded integer.
    fn read_uleb128(&mut self) -> Result<u64> {
        leb128::read::unsigned(self)
    }

    /// Read a signed LEB128 encoded integer.
    fn read_sleb128(&mut self) -> Result<i64> {
        leb128::read::signed(self)
    }

    /// Read an address-sized integer, and return it as a `u64`.
    fn read_address(&mut self, address_size: u8) -> Result<u64> {
        match address_size {
            1 => self.read_u8().map(|v| v as u64),
            2 => self.read_u16().map(|v| v as u64),
            4 => self.read_u32().map(|v| v as u64),
            8 => self.read_u64(),
            otherwise => Err(Error::UnsupportedAddressSize(otherwise)),
        }
    }

    /// Parse a word-sized integer according to the DWARF format, and return it as a `u64`.
    fn read_word(&mut self, format: Format) -> Result<u64> {
        match format {
            Format::Dwarf32 => self.read_u32().map(|v| v as u64),
            Format::Dwarf64 => self.read_u64(),
        }
    }

    /// Parse a word-sized integer according to the DWARF format, and return it as a `usize`.
    fn read_offset(&mut self, format: Format) -> Result<usize> {
        self.read_word(format).and_then(u64_to_offset)
    }
}
