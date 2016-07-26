//! Types for compile-time endianity.

use byteorder;
use std::fmt::Debug;

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
