use endianity::{Endianity, EndianBuf};
use fallible_iterator::FallibleIterator;
use parser::{Error, Result, parse_address};
use std::marker::PhantomData;

/// An offset into the `.debug_ranges` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugRangesOffset(pub u64);

/// The `DebugRanges` struct represents the DWARF strings
/// found in the `.debug_ranges` section.
#[derive(Debug, Clone, Copy)]
pub struct DebugRanges<'input, Endian>
    where Endian: Endianity
{
    debug_ranges_section: EndianBuf<'input, Endian>,
}

impl<'input, Endian> DebugRanges<'input, Endian>
    where Endian: Endianity
{
    /// Construct a new `DebugRanges` instance from the data in the `.debug_ranges`
    /// section.
    ///
    /// It is the caller's responsibility to read the `.debug_ranges` section and
    /// present it as a `&[u8]` slice. That means using some ELF loader on
    /// Linux, a Mach-O loader on OSX, etc.
    ///
    /// ```
    /// use gimli::{DebugRanges, LittleEndian};
    ///
    /// # let buf = [0x00, 0x01, 0x02, 0x03];
    /// # let read_debug_ranges_section_somehow = || &buf;
    /// let debug_ranges = DebugRanges::<LittleEndian>::new(read_debug_ranges_section_somehow());
    /// ```
    pub fn new(debug_ranges_section: &'input [u8]) -> DebugRanges<'input, Endian> {
        DebugRanges { debug_ranges_section: EndianBuf(debug_ranges_section, PhantomData) }
    }

    /// Iterate over the `Range` list entries starting at the given offset.
    ///
    /// The `address_size` must be match the compilation unit for this range list.
    /// The `base_address` should be obtained from the `DebuggingInformationEntry`
    /// that this range list applies to.  Generally this will be a `DW_AT_low_pc`
    /// attribute within the entry.
    ///
    /// Can be [used with
    /// `FallibleIterator`](./index.html#using-with-fallibleiterator).
    pub fn ranges(&self,
                  offset: DebugRangesOffset,
                  address_size: u8,
                  base_address: u64)
                  -> Result<RangesIter<Endian>> {
        let offset = offset.0 as usize;
        if self.debug_ranges_section.len() < offset {
            return Err(Error::UnexpectedEof);
        }

        let input = self.debug_ranges_section.range_from(offset..);
        Ok(RangesIter::new(input, address_size, base_address))
    }

    /// Iterate over the raw `Range` list entries starting at the given offset.
    ///
    /// The `address_size` must be match the compilation unit for this range list.
    ///
    /// This iterator does not perform any processing of the range entries,
    /// such as handling base addresses.
    ///
    /// Can be [used with
    /// `FallibleIterator`](./index.html#using-with-fallibleiterator).
    pub fn raw_ranges(&self,
                      offset: DebugRangesOffset,
                      address_size: u8)
                      -> Result<RawRangesIter<Endian>> {
        let offset = offset.0 as usize;
        if self.debug_ranges_section.len() < offset {
            return Err(Error::UnexpectedEof);
        }

        let input = self.debug_ranges_section.range_from(offset..);
        Ok(RawRangesIter::new(input, address_size))
    }
}

/// An raw iterator over an address range list.
///
/// This iterator does not perform any processing of the range entries,
/// such as handling base addresses.
#[derive(Debug)]
pub struct RawRangesIter<'input, Endian>
    where Endian: Endianity
{
    input: EndianBuf<'input, Endian>,
    address_size: u8,
}

impl<'input, Endian> RawRangesIter<'input, Endian>
    where Endian: Endianity
{
    /// Construct a `RawRangesIter`.
    pub fn new(input: EndianBuf<'input, Endian>,
               address_size: u8)
               -> RawRangesIter<'input, Endian> {
        RawRangesIter {
            input: input,
            address_size: address_size,
        }
    }

    /// Advance the iterator to the next range.
    pub fn next(&mut self) -> Result<Option<Range>> {
        if self.input.is_empty() {
            return Ok(None);
        }

        let (rest, begin) = try!(parse_address(self.input, self.address_size));
        let (rest, end) = try!(parse_address(rest, self.address_size));
        let range = Range {
            begin: begin,
            end: end,
        };

        if range.is_end() {
            self.input = EndianBuf::new(&[]);
        } else {
            self.input = rest;
        }

        Ok(Some(range))
    }
}

impl<'input, Endian> FallibleIterator for RawRangesIter<'input, Endian>
    where Endian: Endianity
{
    type Item = Range;
    type Error = Error;

    fn next(&mut self) -> ::std::result::Result<Option<Self::Item>, Self::Error> {
        RawRangesIter::next(self)
    }
}

/// An iterator over an address range list.
#[derive(Debug)]
pub struct RangesIter<'input, Endian>
    where Endian: Endianity
{
    raw: RawRangesIter<'input, Endian>,
    base_address: u64,
}

impl<'input, Endian> RangesIter<'input, Endian>
    where Endian: Endianity
{
    /// Construct a `RangesIter`.
    pub fn new(input: EndianBuf<'input, Endian>,
               address_size: u8,
               base_address: u64)
               -> RangesIter<'input, Endian> {
        RangesIter {
            raw: RawRangesIter::new(input, address_size),
            base_address: base_address,
        }
    }

    /// Advance the iterator to the next range.
    pub fn next(&mut self) -> Result<Option<Range>> {
        loop {
            let range = match try!(self.raw.next()) {
                Some(range) => range,
                None => return Ok(None),
            };

            if range.is_end() {
                return Ok(None);
            }

            if range.is_base_address(self.raw.address_size) {
                self.base_address = range.end;
                continue;
            }

            let mask = !0 >> (64 - self.raw.address_size * 8);
            let begin = self.base_address.wrapping_add(range.begin) & mask;
            let end = self.base_address.wrapping_add(range.end) & mask;

            if begin == end {
                // An empty range list entry, skip it.
                continue;
            }

            if begin > end {
                self.raw.input = EndianBuf::new(&[]);
                return Err(Error::InvalidAddressRange);
            }

            return Ok(Some(Range {
                begin: begin,
                end: end,
            }));
        }
    }
}

impl<'input, Endian> FallibleIterator for RangesIter<'input, Endian>
    where Endian: Endianity
{
    type Item = Range;
    type Error = Error;

    fn next(&mut self) -> ::std::result::Result<Option<Self::Item>, Self::Error> {
        RangesIter::next(self)
    }
}

/// An address range from the `.debug_ranges` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    /// The beginning address of the range.
    pub begin: u64,

    /// The first address past the end of the range.
    pub end: u64,
}

impl Range {
    /// Check if this is a range end entry.
    ///
    /// This will only occur for raw ranges.
    pub fn is_end(&self) -> bool {
        self.begin == 0 && self.end == 0
    }

    /// Check if this is a base address selection entry.
    ///
    /// A base address selection entry changes the base address that subsequent
    /// range entries are relative to.  This will only occur for raw ranges.
    pub fn is_base_address(&self, address_size: u8) -> bool {
        self.begin == !0 >> (64 - address_size * 8)
    }
}

#[cfg(test)]
mod tests {
    extern crate test_assembler;

    use super::*;
    use endianity::LittleEndian;
    use parser::Error;
    use self::test_assembler::{Endian, Section};

    #[test]
    fn test_range() {
        let range = Range {
            begin: 0,
            end: 0xffffffff,
        };
        assert!(!range.is_end());
        assert!(!range.is_base_address(4));
        assert!(!range.is_base_address(8));

        let range = Range { begin: 0, end: 0 };
        assert!(range.is_end());
        assert!(!range.is_base_address(4));
        assert!(!range.is_base_address(8));

        let range = Range {
            begin: 0xffffffff,
            end: 0,
        };
        assert!(!range.is_end());
        assert!(range.is_base_address(4));
        assert!(!range.is_base_address(8));

        let range = Range {
            begin: 0xffffffffffffffff,
            end: 0,
        };
        assert!(!range.is_end());
        assert!(!range.is_base_address(4));
        assert!(range.is_base_address(8));
    }

    #[test]
    fn test_ranges_32() {
        let section = Section::with_endian(Endian::Little)
            // A range before the offset.
            .L32(0x10000).L32(0x10100)
            // A normal range.
            .L32(0x10200).L32(0x10300)
            // A base address selection followed by a normal range.
            .L32(0xffffffff).L32(0x02000000)
            .L32(0x10400).L32(0x10500)
            // An empty range followed by a normal range.
            .L32(0x10600).L32(0x10600)
            .L32(0x10800).L32(0x10900)
            // A range that starts at 0.
            .L32(0).L32(1)
            // A range that ends at -1.
            .L32(0xffffffff).L32(0x00000000)
            .L32(0).L32(0xffffffff)
            // A range end.
            .L32(0).L32(0)
            // Some extra data.
            .L32(0);

        let buf = section.get_contents().unwrap();
        let debug_ranges = DebugRanges::<LittleEndian>::new(&buf);
        let mut ranges = debug_ranges.ranges(DebugRangesOffset(0x8), 4, 0x01000000).unwrap();

        // A normal range.
        assert_eq!(ranges.next(),
                   Ok(Some(Range {
                       begin: 0x01010200,
                       end: 0x01010300,
                   })));

        // A base address selection followed by a normal range.
        assert_eq!(ranges.next(),
                   Ok(Some(Range {
                       begin: 0x02010400,
                       end: 0x02010500,
                   })));

        // An empty range followed by a normal range.
        assert_eq!(ranges.next(),
                   Ok(Some(Range {
                       begin: 0x02010800,
                       end: 0x02010900,
                   })));

        // A range that starts at 0.
        assert_eq!(ranges.next(),
                   Ok(Some(Range {
                       begin: 0x02000000,
                       end: 0x02000001,
                   })));

        // A range that ends at -1.
        assert_eq!(ranges.next(),
                   Ok(Some(Range {
                       begin: 0x00000000,
                       end: 0xffffffff,
                   })));

        // A range end.
        assert_eq!(ranges.next(), Ok(None));

        // An offset at the end of buf.
        let mut ranges = debug_ranges.ranges(DebugRangesOffset(buf.len() as u64), 4, 0x01000000)
            .unwrap();
        assert_eq!(ranges.next(), Ok(None));
    }

    #[test]
    fn test_ranges_64() {
        let section = Section::with_endian(Endian::Little)
            // A range before the offset.
            .L64(0x10000).L64(0x10100)
            // A normal range.
            .L64(0x10200).L64(0x10300)
            // A base address selection followed by a normal range.
            .L64(0xffffffffffffffff).L64(0x02000000)
            .L64(0x10400).L64(0x10500)
            // An empty range followed by a normal range.
            .L64(0x10600).L64(0x10600)
            .L64(0x10800).L64(0x10900)
            // A range that starts at 0.
            .L64(0).L64(1)
            // A range that ends at -1.
            .L64(0xffffffffffffffff).L64(0x00000000)
            .L64(0).L64(0xffffffffffffffff)
            // A range end.
            .L64(0).L64(0)
            // Some extra data.
            .L64(0);

        let buf = section.get_contents().unwrap();
        let debug_ranges = DebugRanges::<LittleEndian>::new(&buf);
        let mut ranges = debug_ranges.ranges(DebugRangesOffset(0x10), 8, 0x01000000).unwrap();

        // A normal range.
        assert_eq!(ranges.next(),
                   Ok(Some(Range {
                       begin: 0x01010200,
                       end: 0x01010300,
                   })));

        // A base address selection followed by a normal range.
        assert_eq!(ranges.next(),
                   Ok(Some(Range {
                       begin: 0x02010400,
                       end: 0x02010500,
                   })));

        // An empty range followed by a normal range.
        assert_eq!(ranges.next(),
                   Ok(Some(Range {
                       begin: 0x02010800,
                       end: 0x02010900,
                   })));

        // A range that starts at 0.
        assert_eq!(ranges.next(),
                   Ok(Some(Range {
                       begin: 0x02000000,
                       end: 0x02000001,
                   })));

        // A range that ends at -1.
        assert_eq!(ranges.next(),
                   Ok(Some(Range {
                       begin: 0x0,
                       end: 0xffffffffffffffff,
                   })));

        // A range end.
        assert_eq!(ranges.next(), Ok(None));

        // An offset at the end of buf.
        let mut ranges = debug_ranges.ranges(DebugRangesOffset(buf.len() as u64), 8, 0x01000000)
            .unwrap();
        assert_eq!(ranges.next(), Ok(None));
    }

    #[test]
    fn test_ranges_invalid() {
        let section = Section::with_endian(Endian::Little)
            // An invalid range.
            .L32(0x20000).L32(0x10000)
            // An invalid range after wrapping.
            .L32(0x20000).L32(0xff010000);

        let buf = section.get_contents().unwrap();
        let debug_ranges = DebugRanges::<LittleEndian>::new(&buf);

        // An invalid range.
        let mut ranges = debug_ranges.ranges(DebugRangesOffset(0x0), 4, 0x01000000).unwrap();
        assert_eq!(ranges.next(), Err(Error::InvalidAddressRange));

        // An invalid range after wrapping.
        let mut ranges = debug_ranges.ranges(DebugRangesOffset(0x8), 4, 0x01000000).unwrap();
        assert_eq!(ranges.next(), Err(Error::InvalidAddressRange));

        // An invalid offset.
        match debug_ranges.ranges(DebugRangesOffset(buf.len() as u64 + 1), 4, 0x01000000) {
            Err(Error::UnexpectedEof) => {}
            otherwise => panic!("Unexpected result: {:?}", otherwise),
        }
    }
}
