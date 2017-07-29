//! Types for compile-time and run-time endianity.

use byteorder;
use byteorder::ByteOrder;
use std::borrow::Cow;
use std::fmt::Debug;
use std::mem;
use std::ops::{Deref, Index, Range, RangeFrom, RangeTo};
use std::str;
use parser::{Error, Result};
use reader::Reader;

/// A trait describing the endianity of some buffer.
pub trait Endianity: Debug + Default + Clone + Copy + PartialEq + Eq {
    /// Return true for big endian byte order.
    fn is_big_endian(self) -> bool;

    /// Return true for little endian byte order.
    #[inline]
    fn is_little_endian(self) -> bool {
        !self.is_big_endian()
    }

    /// Reads an unsigned 16 bit integer from `buf`.
    ///
    /// # Panics
    ///
    /// Panics when `buf.len() < 2`.
    #[inline]
    fn read_u16(self, buf: &[u8]) -> u16 {
        if self.is_big_endian() {
            byteorder::BigEndian::read_u16(buf)
        } else {
            byteorder::LittleEndian::read_u16(buf)
        }
    }

    /// Reads an unsigned 32 bit integer from `buf`.
    ///
    /// # Panics
    ///
    /// Panics when `buf.len() < 4`.
    #[inline]
    fn read_u32(self, buf: &[u8]) -> u32 {
        if self.is_big_endian() {
            byteorder::BigEndian::read_u32(buf)
        } else {
            byteorder::LittleEndian::read_u32(buf)
        }
    }

    /// Reads an unsigned 64 bit integer from `buf`.
    ///
    /// # Panics
    ///
    /// Panics when `buf.len() < 8`.
    #[inline]
    fn read_u64(self, buf: &[u8]) -> u64 {
        if self.is_big_endian() {
            byteorder::BigEndian::read_u64(buf)
        } else {
            byteorder::LittleEndian::read_u64(buf)
        }
    }

    /// Reads a signed 16 bit integer from `buf`.
    ///
    /// # Panics
    ///
    /// Panics when `buf.len() < 2`.
    #[inline]
    fn read_i16(self, buf: &[u8]) -> i16 {
        self.read_u16(buf) as i16
    }

    /// Reads a signed 32 bit integer from `buf`.
    ///
    /// # Panics
    ///
    /// Panics when `buf.len() < 4`.
    #[inline]
    fn read_i32(self, buf: &[u8]) -> i32 {
        self.read_u32(buf) as i32
    }

    /// Reads a signed 64 bit integer from `buf`.
    ///
    /// # Panics
    ///
    /// Panics when `buf.len() < 8`.
    #[inline]
    fn read_i64(self, buf: &[u8]) -> i64 {
        self.read_u64(buf) as i64
    }

    /// Writes an unsigned 64 bit integer `n` to `buf`.
    ///
    /// # Panics
    ///
    /// Panics when `buf.len() < 8`.
    #[inline]
    fn write_u64(self, buf: &mut [u8], n: u64) {
        if self.is_big_endian() {
            byteorder::BigEndian::write_u64(buf, n)
        } else {
            byteorder::LittleEndian::write_u64(buf, n)
        }
    }
}

/// Byte order that is selectable at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RunTimeEndian {
    /// Little endian byte order.
    Little,
    /// Big endian byte order.
    Big,
}

impl Default for RunTimeEndian {
    #[cfg(target_endian = "little")]
    #[inline]
    fn default() -> RunTimeEndian {
        RunTimeEndian::Little
    }

    #[cfg(target_endian = "big")]
    #[inline]
    fn default() -> RunTimeEndian {
        RunTimeEndian::Big
    }
}

impl Endianity for RunTimeEndian {
    #[inline]
    fn is_big_endian(self) -> bool {
        self != RunTimeEndian::Little
    }
}

/// Little endian byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LittleEndian;

impl Default for LittleEndian {
    #[inline]
    fn default() -> LittleEndian {
        LittleEndian
    }
}

impl Endianity for LittleEndian {
    #[inline]
    fn is_big_endian(self) -> bool {
        false
    }
}

/// Big endian byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BigEndian;

impl Default for BigEndian {
    #[inline]
    fn default() -> BigEndian {
        BigEndian
    }
}

impl Endianity for BigEndian {
    #[inline]
    fn is_big_endian(self) -> bool {
        true
    }
}

/// The native endianity for the target platform.
#[cfg(target_endian = "little")]
pub type NativeEndian = LittleEndian;

#[cfg(target_endian = "little")]
#[allow(non_upper_case_globals)]
#[doc(hidden)]
pub const NativeEndian: LittleEndian = LittleEndian;

/// The native endianity for the target platform.
#[cfg(target_endian = "big")]
pub type NativeEndian = BigEndian;

#[cfg(target_endian = "big")]
#[allow(non_upper_case_globals)]
#[doc(hidden)]
pub const NativeEndian: BigEndian = BigEndian;

/// A `&[u8]` slice with endianity metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EndianBuf<'input, Endian>
    where Endian: Endianity
{
    buf: &'input [u8],
    endian: Endian,
}

impl<'input, Endian> EndianBuf<'input, Endian>
    where Endian: Endianity
{
    /// Construct a new `EndianBuf` with the given buffer.
    #[inline]
    pub fn new(buf: &'input [u8], endian: Endian) -> EndianBuf<'input, Endian> {
        EndianBuf { buf, endian }
    }

    /// Return a reference to the raw buffer.
    #[inline]
    pub fn buf(&self) -> &'input [u8] {
        self.buf
    }

    /// Split the buffer in two at the given index, resulting in the tuple where
    /// the first item has range [0, idx), and the second has range
    /// [idx, len). Panics if the index is out of bounds.
    #[inline]
    pub fn split_at(&self, idx: usize) -> (EndianBuf<'input, Endian>, EndianBuf<'input, Endian>) {
        (self.range_to(..idx), self.range_from(idx..))
    }

    /// Find the first occurence of a byte in the buffer, and return its index.
    #[inline]
    pub fn find(&self, byte: u8) -> Option<usize> {
        self.buf.iter().position(|ch| *ch == byte)
    }

    /// Return the offset of the start of the buffer relative to the start
    /// of the given buffer.
    #[inline]
    pub fn offset_from(&self, base: EndianBuf<'input, Endian>) -> usize {
        let base_ptr = base.buf.as_ptr() as *const u8 as usize;
        let ptr = self.buf.as_ptr() as *const u8 as usize;
        debug_assert!(base_ptr <= ptr);
        debug_assert!(ptr + self.buf.len() <= base_ptr + base.buf.len());
        ptr - base_ptr
    }

    /// Converts the buffer to a string, including invalid characters,
    /// using `String::from_utf8_lossy`.
    #[inline]
    pub fn to_string_lossy(&self) -> Cow<'input, str> {
        String::from_utf8_lossy(self.buf)
    }

    #[inline]
    fn read_slice(&mut self, len: usize) -> Result<&'input [u8]> {
        if self.buf.len() < len {
            Err(Error::UnexpectedEof)
        } else {
            let val = &self.buf[..len];
            self.buf = &self.buf[len..];
            Ok(val)
        }
    }
}

/// # Range Methods
///
/// Unfortunately, `std::ops::Index` *must* return a reference, so we can't
/// implement `Index<Range<usize>>` to return a new `EndianBuf` the way we would
/// like to. Instead, we abandon fancy indexing operators and have these plain
/// old methods.
impl<'input, Endian> EndianBuf<'input, Endian>
    where Endian: Endianity
{
    /// Take the given `start..end` range of the underlying buffer and return a
    /// new `EndianBuf`.
    ///
    /// ```
    /// use gimli::{EndianBuf, LittleEndian};
    ///
    /// let buf = [0x01, 0x02, 0x03, 0x04];
    /// let endian_buf = EndianBuf::new(&buf, LittleEndian);
    /// assert_eq!(endian_buf.range(1..3),
    ///            EndianBuf::new(&buf[1..3], LittleEndian));
    /// ```
    pub fn range(&self, idx: Range<usize>) -> EndianBuf<'input, Endian> {
        EndianBuf {
            buf: &self.buf[idx],
            endian: self.endian,
        }
    }

    /// Take the given `start..` range of the underlying buffer and return a new
    /// `EndianBuf`.
    ///
    /// ```
    /// use gimli::{EndianBuf, LittleEndian};
    ///
    /// let buf = [0x01, 0x02, 0x03, 0x04];
    /// let endian_buf = EndianBuf::new(&buf, LittleEndian);
    /// assert_eq!(endian_buf.range_from(2..),
    ///            EndianBuf::new(&buf[2..], LittleEndian));
    /// ```
    pub fn range_from(&self, idx: RangeFrom<usize>) -> EndianBuf<'input, Endian> {
        EndianBuf {
            buf: &self.buf[idx],
            endian: self.endian,
        }
    }

    /// Take the given `..end` range of the underlying buffer and return a new
    /// `EndianBuf`.
    ///
    /// ```
    /// use gimli::{EndianBuf, LittleEndian};
    ///
    /// let buf = [0x01, 0x02, 0x03, 0x04];
    /// let endian_buf = EndianBuf::new(&buf, LittleEndian);
    /// assert_eq!(endian_buf.range_to(..3),
    ///            EndianBuf::new(&buf[..3], LittleEndian));
    /// ```
    pub fn range_to(&self, idx: RangeTo<usize>) -> EndianBuf<'input, Endian> {
        EndianBuf {
            buf: &self.buf[idx],
            endian: self.endian,
        }
    }
}

impl<'input, Endian> Index<usize> for EndianBuf<'input, Endian>
    where Endian: Endianity
{
    type Output = u8;
    fn index(&self, idx: usize) -> &Self::Output {
        &self.buf[idx]
    }
}

impl<'input, Endian> Index<RangeFrom<usize>> for EndianBuf<'input, Endian>
    where Endian: Endianity
{
    type Output = [u8];
    fn index(&self, idx: RangeFrom<usize>) -> &Self::Output {
        &self.buf[idx]
    }
}

impl<'input, Endian> Deref for EndianBuf<'input, Endian>
    where Endian: Endianity
{
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.buf
    }
}

impl<'input, Endian> Into<&'input [u8]> for EndianBuf<'input, Endian>
    where Endian: Endianity
{
    fn into(self) -> &'input [u8] {
        self.buf
    }
}

impl<'input, Endian> Reader for EndianBuf<'input, Endian>
    where Endian: Endianity
{
    type Endian = Endian;
    type Offset = usize;

    #[inline]
    fn endian(&self) -> Endian {
        self.endian
    }

    #[inline]
    fn len(&self) -> usize {
        self.buf.len()
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    #[inline]
    fn empty(&mut self) {
        self.buf = &[];
    }

    #[inline]
    fn truncate(&mut self, len: usize) -> Result<()> {
        if self.buf.len() < len {
            Err(Error::UnexpectedEof)
        } else {
            self.buf = &self.buf[..len];
            Ok(())
        }
    }

    #[inline]
    fn offset_from(&self, base: &Self) -> usize {
        self.offset_from(*base)
    }

    #[inline]
    fn find(&self, byte: u8) -> Option<usize> {
        self.find(byte)
    }

    #[inline]
    fn skip(&mut self, len: usize) -> Result<()> {
        if self.buf.len() < len {
            Err(Error::UnexpectedEof)
        } else {
            self.buf = &self.buf[len..];
            Ok(())
        }
    }

    #[inline]
    fn split(&mut self, len: usize) -> Result<Self> {
        let slice = self.read_slice(len)?;
        Ok(EndianBuf::new(slice, self.endian))
    }

    #[inline]
    fn to_slice(&self) -> Cow<[u8]> {
        Cow::from(self.buf)
    }

    #[inline]
    fn to_string(&self) -> Result<Cow<str>> {
        match str::from_utf8(self.buf) {
            Ok(s) => Ok(Cow::from(s)),
            _ => Err(Error::BadUtf8),
        }
    }

    #[inline]
    fn to_string_lossy(&self) -> Cow<str> {
        String::from_utf8_lossy(self.buf)
    }

    #[inline]
    fn read_u8_array<A>(&mut self) -> Result<A>
        where A: Sized + Default + AsMut<[u8]>
    {
        let len = mem::size_of::<A>();
        let slice = self.read_slice(len)?;
        let mut val = Default::default();
        <A as AsMut<[u8]>>::as_mut(&mut val).clone_from_slice(slice);
        Ok(val)
    }

    #[inline]
    fn read_u8(&mut self) -> Result<u8> {
        let slice = self.read_slice(1)?;
        Ok(slice[0])
    }

    #[inline]
    fn read_i8(&mut self) -> Result<i8> {
        let slice = self.read_slice(1)?;
        Ok(slice[0] as i8)
    }

    #[inline]
    fn read_u16(&mut self) -> Result<u16> {
        let slice = self.read_slice(2)?;
        Ok(self.endian.read_u16(slice))
    }

    #[inline]
    fn read_i16(&mut self) -> Result<i16> {
        let slice = self.read_slice(2)?;
        Ok(self.endian.read_i16(slice))
    }

    #[inline]
    fn read_u32(&mut self) -> Result<u32> {
        let slice = self.read_slice(4)?;
        Ok(self.endian.read_u32(slice))
    }

    #[inline]
    fn read_i32(&mut self) -> Result<i32> {
        let slice = self.read_slice(4)?;
        Ok(self.endian.read_i32(slice))
    }

    #[inline]
    fn read_u64(&mut self) -> Result<u64> {
        let slice = self.read_slice(8)?;
        Ok(self.endian.read_u64(slice))
    }

    #[inline]
    fn read_i64(&mut self) -> Result<i64> {
        let slice = self.read_slice(8)?;
        Ok(self.endian.read_i64(slice))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endian_buf_split_at() {
        let endian = NativeEndian;
        let buf = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0];
        let eb = EndianBuf::new(&buf, endian);
        assert_eq!(eb.split_at(3),
                   (EndianBuf::new(&buf[..3], endian), EndianBuf::new(&buf[3..], endian)));
    }

    #[test]
    #[should_panic]
    fn test_endian_buf_split_at_out_of_bounds() {
        let buf = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0];
        let eb = EndianBuf::new(&buf, NativeEndian);
        eb.split_at(30);
    }
}
