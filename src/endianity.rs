//! Types for compile-time endianity.

use byteorder;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::ops::{Deref, Index, Range, RangeFrom, RangeTo};

/// A trait describing the endianity of some buffer.
///
/// All interesting methods are from the `byteorder` crate's `ByteOrder`
/// trait. All methods are static. You shouldn't instantiate concrete objects
/// that implement this trait, it is just used as compile-time phantom data.
pub trait Endianity
    : byteorder::ByteOrder + Debug + Clone + Copy + PartialEq + Eq {
}

/// Little endian byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LittleEndian {}

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

impl Endianity for LittleEndian {}

/// Big endian byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BigEndian {}

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

impl Endianity for BigEndian {}

/// A `&[u8]` slice with compile-time endianity metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndianBuf<'input, Endian>(pub &'input [u8], pub PhantomData<Endian>)
    where Endian: Endianity;

impl<'input, Endian> EndianBuf<'input, Endian>
    where Endian: Endianity
{
    /// Construct a new `EndianBuf` with the given buffer.
    pub fn new(buf: &'input [u8]) -> EndianBuf<'input, Endian> {
        EndianBuf(buf, PhantomData)
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
        EndianBuf(&self.0[idx], self.1)
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
        EndianBuf(&self.0[idx], self.1)
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
        EndianBuf(&self.0[idx], self.1)
    }
}

impl<'input, Endian> Index<usize> for EndianBuf<'input, Endian>
    where Endian: Endianity
{
    type Output = u8;
    fn index(&self, idx: usize) -> &Self::Output {
        &self.0[idx]
    }
}

impl<'input, Endian> Deref for EndianBuf<'input, Endian>
    where Endian: Endianity
{
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<'input, Endian> Into<&'input [u8]> for EndianBuf<'input, Endian>
    where Endian: Endianity
{
    fn into(self) -> &'input [u8] {
        self.0
    }
}
