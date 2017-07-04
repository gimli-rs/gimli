//! Types for compile-time endianity.

use byteorder;
use std::borrow::Cow;
use std::cmp;
use std::fmt::Debug;
use std::io;
use std::io::Read;
use std::marker::PhantomData;
use std::mem;
use std::ops::{Deref, Index, Range, RangeFrom, RangeTo};
use parser::{Error, Result};
use reader::Reader;

/// A trait describing the endianity of some buffer.
///
/// All interesting methods are from the `byteorder` crate's `ByteOrder`
/// trait. All methods are static. You shouldn't instantiate concrete objects
/// that implement this trait, it is just used as compile-time phantom data.
pub trait Endianity
    : byteorder::ByteOrder + Debug + Default + Clone + Copy + PartialEq + Eq {
    /// Return true for big endian byte order.
    fn is_big_endian() -> bool;

    /// Return true for little endian byte order.
    fn is_little_endian() -> bool {
        !Self::is_big_endian()
    }
}

/// Little endian byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LittleEndian {}

impl Default for LittleEndian {
    fn default() -> LittleEndian {
        unreachable!()
    }
}

impl byteorder::ByteOrder for LittleEndian {
    fn read_u16(buf: &[u8]) -> u16 {
        byteorder::LittleEndian::read_u16(buf)
    }
    fn read_u32(buf: &[u8]) -> u32 {
        byteorder::LittleEndian::read_u32(buf)
    }
    fn read_u64(buf: &[u8]) -> u64 {
        byteorder::LittleEndian::read_u64(buf)
    }
    fn read_uint(buf: &[u8], nbytes: usize) -> u64 {
        byteorder::LittleEndian::read_uint(buf, nbytes)
    }
    fn write_u16(buf: &mut [u8], n: u16) {
        byteorder::LittleEndian::write_u16(buf, n)
    }
    fn write_u32(buf: &mut [u8], n: u32) {
        byteorder::LittleEndian::write_u32(buf, n)
    }
    fn write_u64(buf: &mut [u8], n: u64) {
        byteorder::LittleEndian::write_u64(buf, n)
    }
    fn write_uint(buf: &mut [u8], n: u64, nbytes: usize) {
        byteorder::LittleEndian::write_uint(buf, n, nbytes)
    }
}

impl Endianity for LittleEndian {
    fn is_big_endian() -> bool {
        false
    }
}

/// Big endian byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BigEndian {}

impl Default for BigEndian {
    fn default() -> BigEndian {
        unreachable!()
    }
}

impl byteorder::ByteOrder for BigEndian {
    fn read_u16(buf: &[u8]) -> u16 {
        byteorder::BigEndian::read_u16(buf)
    }
    fn read_u32(buf: &[u8]) -> u32 {
        byteorder::BigEndian::read_u32(buf)
    }
    fn read_u64(buf: &[u8]) -> u64 {
        byteorder::BigEndian::read_u64(buf)
    }
    fn read_uint(buf: &[u8], nbytes: usize) -> u64 {
        byteorder::BigEndian::read_uint(buf, nbytes)
    }
    fn write_u16(buf: &mut [u8], n: u16) {
        byteorder::BigEndian::write_u16(buf, n)
    }
    fn write_u32(buf: &mut [u8], n: u32) {
        byteorder::BigEndian::write_u32(buf, n)
    }
    fn write_u64(buf: &mut [u8], n: u64) {
        byteorder::BigEndian::write_u64(buf, n)
    }
    fn write_uint(buf: &mut [u8], n: u64, nbytes: usize) {
        byteorder::BigEndian::write_uint(buf, n, nbytes)
    }
}

impl Endianity for BigEndian {
    fn is_big_endian() -> bool {
        true
    }
}

/// The native endianity for the target platform.
#[cfg(target_endian = "little")]
pub type NativeEndian = LittleEndian;
#[cfg(target_endian = "big")]
pub type NativeEndian = BigEndian;

/// A `&[u8]` slice with compile-time endianity metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EndianBuf<'input, Endian>
    where Endian: Endianity
{
    buf: &'input [u8],
    endian: PhantomData<Endian>,
}

impl<'input, Endian> EndianBuf<'input, Endian>
    where Endian: Endianity
{
    /// Construct a new `EndianBuf` with the given buffer.
    pub fn new(buf: &'input [u8]) -> EndianBuf<'input, Endian> {
        EndianBuf {
            buf,
            endian: PhantomData,
        }
    }

    /// Return a reference to the raw buffer.
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
    pub fn offset_from(&self, base: EndianBuf<'input, Endian>) -> usize {
        let base_ptr = base.buf.as_ptr() as *const u8 as usize;
        let ptr = self.buf.as_ptr() as *const u8 as usize;
        debug_assert!(base_ptr <= ptr);
        debug_assert!(ptr + self.buf.len() <= base_ptr + base.buf.len());
        ptr - base_ptr
    }

    /// Converts the buffer to a string, including invalid characters,
    /// using `String::from_utf8_lossy`.
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
    /// let endian_buf = EndianBuf::<LittleEndian>::new(&buf);
    /// assert_eq!(endian_buf.range(1..3),
    ///            EndianBuf::new(&buf[1..3]));
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
    /// let endian_buf = EndianBuf::<LittleEndian>::new(&buf);
    /// assert_eq!(endian_buf.range_from(2..),
    ///            EndianBuf::new(&buf[2..]));
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
    /// let endian_buf = EndianBuf::<LittleEndian>::new(&buf);
    /// assert_eq!(endian_buf.range_to(..3),
    ///            EndianBuf::new(&buf[..3]));
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

impl<'input, Endian> Read for EndianBuf<'input, Endian>
    where Endian: Endianity
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = cmp::min(buf.len(), self.buf.len());
        buf[..len].copy_from_slice(&self.buf[..len]);
        self.buf = &self.buf[len..];
        Ok(len)
    }
}

impl<'input, Endian> Reader for EndianBuf<'input, Endian>
    where Endian: Endianity
{
    type Endian = Endian;

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
        Ok(EndianBuf::new(slice))
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
        Ok(Endian::read_u16(slice))
    }

    #[inline]
    fn read_i16(&mut self) -> Result<i16> {
        let slice = self.read_slice(2)?;
        Ok(Endian::read_i16(slice))
    }

    #[inline]
    fn read_u32(&mut self) -> Result<u32> {
        let slice = self.read_slice(4)?;
        Ok(Endian::read_u32(slice))
    }

    #[inline]
    fn read_i32(&mut self) -> Result<i32> {
        let slice = self.read_slice(4)?;
        Ok(Endian::read_i32(slice))
    }

    #[inline]
    fn read_u64(&mut self) -> Result<u64> {
        let slice = self.read_slice(8)?;
        Ok(Endian::read_u64(slice))
    }

    #[inline]
    fn read_i64(&mut self) -> Result<i64> {
        let slice = self.read_slice(8)?;
        Ok(Endian::read_i64(slice))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endian_buf_split_at() {
        let buf = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0];
        let eb = EndianBuf::<NativeEndian>::new(&buf);
        assert_eq!(eb.split_at(3),
                   (EndianBuf::new(&buf[..3]), EndianBuf::new(&buf[3..])));
    }

    #[test]
    #[should_panic]
    fn test_endian_buf_split_at_out_of_bounds() {
        let buf = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0];
        let eb = EndianBuf::<NativeEndian>::new(&buf);
        eb.split_at(30);
    }
}
