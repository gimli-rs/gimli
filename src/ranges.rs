use endianity::{Endianity, EndianBuf};
use fallible_iterator::FallibleIterator;
use parser::{Error, Result};
use reader::Reader;
use Section;

/// An offset into the `.debug_ranges` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DebugRangesOffset(pub usize);

/// The `DebugRanges` struct represents the DWARF strings
/// found in the `.debug_ranges` section.
#[derive(Debug, Clone, Copy)]
pub struct DebugRanges<R: Reader> {
    debug_ranges_section: R,
}

impl<'input, Endian> DebugRanges<EndianBuf<'input, Endian>>
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
    /// let debug_ranges = DebugRanges::new(read_debug_ranges_section_somehow(), LittleEndian);
    /// ```
    pub fn new(debug_ranges_section: &'input [u8], endian: Endian) -> Self {
        Self::from(EndianBuf::new(debug_ranges_section, endian))
    }
}

impl<R: Reader> DebugRanges<R> {
    /// Iterate over the `Range` list entries starting at the given offset.
    ///
    /// The `address_size` must be match the compilation unit for this range list.
    /// The `base_address` should be obtained from the `DW_AT_low_pc` attribute in the
    /// `DW_TAG_compile_unit` entry for the compilation unit that contains this range list.
    ///
    /// Can be [used with
    /// `FallibleIterator`](./index.html#using-with-fallibleiterator).
    pub fn ranges(&self,
                  offset: DebugRangesOffset,
                  address_size: u8,
                  base_address: u64)
                  -> Result<RangesIter<R>> {
        let mut input = self.debug_ranges_section.clone();
        input.skip(offset.0)?;
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
                      -> Result<RawRangesIter<R>> {
        let mut input = self.debug_ranges_section.clone();
        input.skip(offset.0)?;
        Ok(RawRangesIter::new(input, address_size))
    }
}

impl<R: Reader> Section<R> for DebugRanges<R> {
    fn section_name() -> &'static str {
        ".debug_ranges"
    }
}

impl<R: Reader> From<R> for DebugRanges<R> {
    fn from(debug_ranges_section: R) -> Self {
        DebugRanges { debug_ranges_section }
    }
}

/// A raw iterator over an address range list.
///
/// This iterator does not perform any processing of the range entries,
/// such as handling base addresses.
#[derive(Debug)]
pub struct RawRangesIter<R: Reader> {
    input: R,
    address_size: u8,
}

impl<R: Reader> RawRangesIter<R> {
    /// Construct a `RawRangesIter`.
    fn new(input: R, address_size: u8) -> RawRangesIter<R> {
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

        match Range::parse(&mut self.input, self.address_size) {
            Ok(range) => {
                if range.is_end() {
                    self.input.empty();
                }
                Ok(Some(range))
            }
            Err(e) => {
                self.input.empty();
                Err(e)
            }
        }
    }
}

impl<R: Reader> FallibleIterator for RawRangesIter<R> {
    type Item = Range;
    type Error = Error;

    fn next(&mut self) -> ::std::result::Result<Option<Self::Item>, Self::Error> {
        RawRangesIter::next(self)
    }
}

/// An iterator over an address range list.
///
/// This iterator internally handles processing of base address selection entries
/// and range end entries.  Thus, it only returns range entries that are valid
/// and already adjusted for the base address.
#[derive(Debug)]
pub struct RangesIter<R: Reader> {
    raw: RawRangesIter<R>,
    base_address: u64,
}

impl<R: Reader> RangesIter<R> {
    /// Construct a `RangesIter`.
    fn new(input: R, address_size: u8, base_address: u64) -> RangesIter<R> {
        RangesIter {
            raw: RawRangesIter::new(input, address_size),
            base_address: base_address,
        }
    }

    /// Advance the iterator to the next range.
    pub fn next(&mut self) -> Result<Option<Range>> {
        loop {
            let mut range = match self.raw.next()? {
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

            if range.begin == range.end {
                // An empty range list entry, skip it.
                continue;
            }

            range.add_base_address(self.base_address, self.raw.address_size);
            if range.begin > range.end {
                self.raw.input.empty();
                return Err(Error::InvalidAddressRange);
            }

            return Ok(Some(range));
        }
    }
}

impl<R: Reader> FallibleIterator for RangesIter<R> {
    type Item = Range;
    type Error = Error;

    fn next(&mut self) -> ::std::result::Result<Option<Self::Item>, Self::Error> {
        RangesIter::next(self)
    }
}

/// An address range from the `.debug_ranges` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

    /// Add a base address to this range.
    ///
    /// This should only be called for raw ranges.
    pub fn add_base_address(&mut self, base_address: u64, address_size: u8) {
        debug_assert!(!self.is_end());
        debug_assert!(!self.is_base_address(address_size));
        let mask = !0 >> (64 - address_size * 8);
        self.begin = base_address.wrapping_add(self.begin) & mask;
        self.end = base_address.wrapping_add(self.end) & mask;
    }

    /// Parse an address range entry from `.debug_ranges` or `.debug_loc`.
    #[doc(hidden)]
    #[inline]
    pub fn parse<R: Reader>(input: &mut R, address_size: u8) -> Result<Range> {
        let begin = input.read_address(address_size)?;
        let end = input.read_address(address_size)?;
        let range = Range {
            begin: begin,
            end: end,
        };
        Ok(range)
    }
}

#[cfg(test)]
mod tests {
    extern crate test_assembler;

    use super::*;
    use endianity::LittleEndian;
    use parser::Error;
    use self::test_assembler::{Endian, Label, LabelMaker, Section};

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
        let start = Label::new();
        let first = Label::new();
        let section = Section::with_endian(Endian::Little)
            // A range before the offset.
            .mark(&start)
            .L32(0x10000).L32(0x10100)
            .mark(&first)
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
        let debug_ranges = DebugRanges::new(&buf, LittleEndian);
        let offset = DebugRangesOffset((&first - &start) as usize);
        let mut ranges = debug_ranges.ranges(offset, 4, 0x01000000).unwrap();

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
        let mut ranges = debug_ranges
            .ranges(DebugRangesOffset(buf.len()), 4, 0x01000000)
            .unwrap();
        assert_eq!(ranges.next(), Ok(None));
    }

    #[test]
    fn test_ranges_64() {
        let start = Label::new();
        let first = Label::new();
        let section = Section::with_endian(Endian::Little)
            // A range before the offset.
            .mark(&start)
            .L64(0x10000).L64(0x10100)
            .mark(&first)
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
        let debug_ranges = DebugRanges::new(&buf, LittleEndian);
        let offset = DebugRangesOffset((&first - &start) as usize);
        let mut ranges = debug_ranges.ranges(offset, 8, 0x01000000).unwrap();

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
        let mut ranges = debug_ranges
            .ranges(DebugRangesOffset(buf.len()), 8, 0x01000000)
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
        let debug_ranges = DebugRanges::new(&buf, LittleEndian);

        // An invalid range.
        let mut ranges = debug_ranges
            .ranges(DebugRangesOffset(0x0), 4, 0x01000000)
            .unwrap();
        assert_eq!(ranges.next(), Err(Error::InvalidAddressRange));

        // An invalid range after wrapping.
        let mut ranges = debug_ranges
            .ranges(DebugRangesOffset(0x8), 4, 0x01000000)
            .unwrap();
        assert_eq!(ranges.next(), Err(Error::InvalidAddressRange));

        // An invalid offset.
        match debug_ranges.ranges(DebugRangesOffset(buf.len() + 1), 4, 0x01000000) {
            Err(Error::UnexpectedEof) => {}
            otherwise => panic!("Unexpected result: {:?}", otherwise),
        }
    }
}
