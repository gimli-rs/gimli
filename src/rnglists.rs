use constants;
use endianity::{EndianBuf, Endianity};
use fallible_iterator::FallibleIterator;
use parser::{self, Error, Format, Result};
use ranges::{Range, DebugRangesOffset};
use reader::{Reader, ReaderOffset};
use Section;

/// An offset into the `.debug_addr` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AddressIndex(pub u64);

#[derive(Debug, Clone, Copy)]
struct RngListsHeader {
    format: Format,
    address_size: u8,
    offset_entry_count: u32,
}

/// The `DebugRngLists` struct represents the contents of the
/// `.debug_rnglists` section.
#[derive(Debug, Clone, Copy)]
pub struct DebugRngLists<R: Reader> {
    debug_rnglists_section: R,
}

fn parse_header<R: Reader>(input: &mut R) -> Result<RngListsHeader> {
    let (length, format) = parser::parse_initial_length(input)?;
    let length = R::Offset::from_u64(length)?;
    let mut rest = input.split(length)?;

    let version = rest.read_u16()?;
    if version != 5 {
        return Err(Error::UnknownVersion(version as u64));
    }

    let address_size = rest.read_u8()?;
    let segment_selector_size = rest.read_u8()?;
    if segment_selector_size != 0 {
        return Err(Error::UnsupportedSegmentSize);
    }
    let offset_entry_count = rest.read_u32()?;
    Ok(RngListsHeader {
        format: format,
        address_size: address_size,
        offset_entry_count: offset_entry_count,
    })
}

impl<'input, Endian> DebugRngLists<EndianBuf<'input, Endian>>
where
    Endian: Endianity,
{
    /// Construct a new `DebugRngLists` instance from the data in the
    /// `.debug_rnglists` section.
    ///
    /// It is the caller's responsibility to read the `.debug_rnglists`
    /// section and present it as a `&[u8]` slice. That means using some ELF
    /// loader on Linux, a Mach-O loader on OSX, etc.
    ///
    /// ```
    /// use gimli::{DebugRngLists, LittleEndian};
    ///
    /// # let buf = [0x00, 0x01, 0x02, 0x03];
    /// # let read_debug_rnglists_section_somehow = || &buf;
    /// let debug_ranges =
    ///     DebugRngLists::new(read_debug_rnglists_section_somehow(), LittleEndian);
    /// ```
    pub fn new(debug_rnglists_section: &'input [u8], endian: Endian) -> Self {
        Self::from(EndianBuf::new(debug_rnglists_section, endian))
    }
}

impl<R: Reader> Section<R> for DebugRngLists<R> {
    fn section_name() -> &'static str {
        ".debug_rnglists"
    }
}

impl<R: Reader> From<R> for DebugRngLists<R> {
    fn from(debug_rnglists_section: R) -> Self {
        DebugRngLists {
            debug_rnglists_section,
        }
    }
}

impl<R: Reader> DebugRngLists<R> {
    /// Iterate over the `Range` list entries starting at the given offset.
    ///
    /// The `address_size` must be match the compilation unit for this range list.
    /// The `base_address` should be obtained from the `DW_AT_low_pc` attribute in the
    /// `DW_TAG_compile_unit` entry for the compilation unit that contains this range list.
    ///
    /// Can be [used with
    /// `FallibleIterator`](./index.html#using-with-fallibleiterator).
    pub fn ranges(
        &self,
        offset: DebugRangesOffset<R::Offset>,
        base_address: u64,
    ) -> Result<RngListIter<R>> {
        Ok(RngListIter::new(self.raw_ranges(offset)?, base_address))
    }

    /// Iterate over the `RawRngListEntry`ies starting at the given offset.
    ///
    /// This iterator does not perform any processing of the range entries,
    /// such as handling base addresses.
    ///
    /// Can be [used with
    /// `FallibleIterator`](./index.html#using-with-fallibleiterator).
    pub fn raw_ranges(
        &self,
        offset: DebugRangesOffset<R::Offset>,
    ) -> Result<RawRngListIter<R>> {
        let mut input = self.debug_rnglists_section.clone();
        let header = parse_header(&mut input)?;
        input = self.debug_rnglists_section.clone();
        input.skip(offset.0)?;
        Ok(RawRngListIter::new(input, header.address_size))
    }
}

/// A raw iterator over an address range list.
///
/// This iterator does not perform any processing of the range entries,
/// such as handling base addresses.
#[derive(Debug)]
pub struct RawRngListIter<R: Reader> {
    input: R,
    address_size: u8,
}

#[derive(Clone, Debug)]
pub enum RawRngListEntry {
    BaseAddress {
        addr: u64,
    },
    BaseAddressx {
        addr: AddressIndex,
    },
    StartxEndx {
        begin: AddressIndex,
        end: AddressIndex,
    },
    StartxLength {
        begin: AddressIndex,
        length: u64,
    },
    OffsetPair {
        begin: u64,
        end: u64,
    },
    StartEnd {
        begin: u64,
        end: u64,
    },
    StartLength {
        begin: u64,
        length: u64,
    }
}

impl RawRngListEntry {
    /// Parse a range entry from `.debug_rnglists`
    fn parse<R: Reader>(input: &mut R, address_size: u8) -> Result<Option<Self>> {
        Ok(match constants::DwRle(input.read_u8()?) {
            constants::DW_RLE_end_of_list => {
                None
            },
            constants::DW_RLE_base_addressx => {
                Some(RawRngListEntry::BaseAddressx {
                    addr: AddressIndex(input.read_uleb128()?),
                })
            },
            constants::DW_RLE_startx_endx => {
                Some(RawRngListEntry::StartxEndx {
                    begin: AddressIndex(input.read_uleb128()?),
                    end: AddressIndex(input.read_uleb128()?),
                })
            },
            constants::DW_RLE_startx_length => {
                Some(RawRngListEntry::StartxLength {
                    begin: AddressIndex(input.read_uleb128()?),
                    length: input.read_uleb128()?,
                })
            },
            constants::DW_RLE_offset_pair => {
                Some(RawRngListEntry::OffsetPair {
                    begin: input.read_uleb128()?,
                    end: input.read_uleb128()?,
                })
            },
            constants::DW_RLE_base_address => {
                Some(RawRngListEntry::BaseAddress {
                    addr: input.read_address(address_size)?,
                })
            },
            constants::DW_RLE_start_end => {
                Some(RawRngListEntry::StartEnd {
                    begin: input.read_address(address_size)?,
                    end: input.read_address(address_size)?,
                })
            },
            constants::DW_RLE_start_length => {
                Some(RawRngListEntry::StartLength {
                    begin: input.read_address(address_size)?,
                    length: input.read_uleb128()?,
                })
            },
            _ => {
                return Err(Error::InvalidAddressRange);
            }
        })
    }
}

impl<R: Reader> RawRngListIter<R> {
    /// Construct a `RawRngListIter`.
    fn new(input: R, address_size: u8) -> RawRngListIter<R> {
        RawRngListIter {
            input: input,
            address_size: address_size,
        }
    }

    /// Advance the iterator to the next range.
    pub fn next(&mut self) -> Result<Option<RawRngListEntry>> {
        if self.input.is_empty() {
            return Ok(None);
        }

        match RawRngListEntry::parse(&mut self.input, self.address_size) {
            Ok(range) => {
                if range.is_none() {
                    self.input.empty();
                }
                Ok(range)
            }
            Err(e) => {
                self.input.empty();
                Err(e)
            }
        }
    }
}

impl<R: Reader> FallibleIterator for RawRngListIter<R> {
    type Item = RawRngListEntry;
    type Error = Error;

    fn next(&mut self) -> ::std::result::Result<Option<Self::Item>, Self::Error> {
        RawRngListIter::next(self)
    }
}

/// An iterator over an address range list.
///
/// This iterator internally handles processing of base addresses and different
/// entry types.  Thus, it only returns range entries that are valid
/// and already adjusted for the base address.
#[derive(Debug)]
pub struct RngListIter<R: Reader> {
    raw: RawRngListIter<R>,
    base_address: u64,
}

impl<R: Reader> RngListIter<R> {
    /// Construct a `RngListIter`.
    fn new(raw: RawRngListIter<R>, base_address: u64) -> RngListIter<R> {
        RngListIter {
            raw: raw,
            base_address: base_address,
        }
    }

    /// Advance the iterator to the next range.
    pub fn next(&mut self) -> Result<Option<Range>> {
        loop {
            let raw_range = match self.raw.next()? {
                Some(range) => range,
                None => return Ok(None),
            };

            let range = match raw_range {
                RawRngListEntry::BaseAddress { addr } => {
                    self.base_address = addr;
                    continue;
                },
                RawRngListEntry::OffsetPair { begin, end } => {
                    Range { begin: self.base_address + begin, end: self.base_address + end }
                },
                RawRngListEntry::StartEnd { begin, end } => {
                    Range { begin: begin, end: end }
                },
                RawRngListEntry::StartLength { begin, length } => {
                    Range { begin: begin, end: begin + length }
                },
                _ => {
                    // We don't support AddressIndex-based entries yet
                    return Err(Error::UnsupportedAddressIndex);
                }
            };

            if range.begin == range.end {
                // An empty range list entry, skip it.
                continue;
            }

            if range.begin > range.end {
                self.raw.input.empty();
                return Err(Error::InvalidAddressRange);
            }

            return Ok(Some(range));
        }
    }
}

impl<R: Reader> FallibleIterator for RngListIter<R> {
    type Item = Range;
    type Error = Error;

    fn next(&mut self) -> ::std::result::Result<Option<Self::Item>, Self::Error> {
        RngListIter::next(self)
    }
}

#[cfg(test)]
mod tests {
    extern crate test_assembler;

    use super::*;
    use endianity::LittleEndian;
    use self::test_assembler::{Endian, Label, LabelMaker, Section};
    use test_util::GimliSectionMethods;

    #[test]
    fn test_rnglists_32() {
        let start = Label::new();
        let first = Label::new();
        let size = Label::new();
        let section = Section::with_endian(Endian::Little)
            // Header
            .mark(&start)
            .L32(&size)
            .L16(5)
            .L8(4)
            .L8(0)
            .L32(0)
            .mark(&first)
            // OffsetPair
            .L8(4).uleb(0x10200).uleb(0x10300)
            // A base address selection followed by an OffsetPair.
            .L8(5).L32(0x02000000)
            .L8(4).uleb(0x10400).uleb(0x10500)
            // An empty OffsetPair followed by a normal OffsetPair.
            .L8(4).uleb(0x10600).uleb(0x10600)
            .L8(4).uleb(0x10800).uleb(0x10900)
            // A StartEnd
            .L8(6).L32(0x2010a00).L32(0x2010b00)
            // A StartLength
            .L8(7).L32(0x2010c00).uleb(0x100)
            // An OffsetPair that starts at 0.
            .L8(4).uleb(0).uleb(1)
            // An OffsetPair that ends at -1.
            .L8(5).L32(0)
            .L8(4).uleb(0).uleb(0xffffffff)
            // A range end.
            .L8(0)
            // Some extra data.
            .L32(0xffffffff);
        size.set_const((&section.here() - &start - 4) as u64);

        let buf = section.get_contents().unwrap();
        let debug_rnglists = DebugRngLists::new(&buf, LittleEndian);
        let offset = DebugRangesOffset((&first - &start) as usize);
        let mut ranges = debug_rnglists.ranges(offset, 0x01000000).unwrap();

        // A normal range.
        assert_eq!(
            ranges.next(),
            Ok(Some(Range {
                begin: 0x01010200,
                end: 0x01010300,
            }))
        );

        // A base address selection followed by a normal range.
        assert_eq!(
            ranges.next(),
            Ok(Some(Range {
                begin: 0x02010400,
                end: 0x02010500,
            }))
        );

        // An empty range followed by a normal range.
        assert_eq!(
            ranges.next(),
            Ok(Some(Range {
                begin: 0x02010800,
                end: 0x02010900,
            }))
        );

        // A normal range.
        assert_eq!(
            ranges.next(),
            Ok(Some(Range {
                begin: 0x02010a00,
                end: 0x02010b00,
            }))
        );

        // A normal range.
        assert_eq!(
            ranges.next(),
            Ok(Some(Range {
                begin: 0x02010c00,
                end: 0x02010d00,
            }))
        );

        // A range that starts at 0.
        assert_eq!(
            ranges.next(),
            Ok(Some(Range {
                begin: 0x02000000,
                end: 0x02000001,
            }))
        );

        // A range that ends at -1.
        assert_eq!(
            ranges.next(),
            Ok(Some(Range {
                begin: 0x00000000,
                end: 0xffffffff,
            }))
        );

        // A range end.
        assert_eq!(ranges.next(), Ok(None));

        // An offset at the end of buf.
        let mut ranges = debug_rnglists
            .ranges(DebugRangesOffset(buf.len()), 0x01000000)
            .unwrap();
        assert_eq!(ranges.next(), Ok(None));
    }

    #[test]
    fn test_rnglists_64() {
        let start = Label::new();
        let first = Label::new();
        let size = Label::new();
        let section = Section::with_endian(Endian::Little)
            // Header
            .mark(&start)
            .L32(0xffffffff)
            .L64(&size)
            .L16(5)
            .L8(8)
            .L8(0)
            .L32(0)
            .mark(&first)
            // OffsetPair
            .L8(4).uleb(0x10200).uleb(0x10300)
            // A base address selection followed by an OffsetPair.
            .L8(5).L64(0x02000000)
            .L8(4).uleb(0x10400).uleb(0x10500)
            // An empty OffsetPair followed by a normal OffsetPair.
            .L8(4).uleb(0x10600).uleb(0x10600)
            .L8(4).uleb(0x10800).uleb(0x10900)
            // A StartEnd
            .L8(6).L64(0x2010a00).L64(0x2010b00)
            // A StartLength
            .L8(7).L64(0x2010c00).uleb(0x100)
            // An OffsetPair that starts at 0.
            .L8(4).uleb(0).uleb(1)
            // An OffsetPair that ends at -1.
            .L8(5).L64(0)
            .L8(4).uleb(0).uleb(0xffffffff)
            // A range end.
            .L8(0)
            // Some extra data.
            .L32(0xffffffff);
        size.set_const((&section.here() - &start - 12) as u64);

        let buf = section.get_contents().unwrap();
        let debug_rnglists = DebugRngLists::new(&buf, LittleEndian);
        let offset = DebugRangesOffset((&first - &start) as usize);
        let mut ranges = debug_rnglists.ranges(offset, 0x01000000).unwrap();

        // A normal range.
        assert_eq!(
            ranges.next(),
            Ok(Some(Range {
                begin: 0x01010200,
                end: 0x01010300,
            }))
        );

        // A base address selection followed by a normal range.
        assert_eq!(
            ranges.next(),
            Ok(Some(Range {
                begin: 0x02010400,
                end: 0x02010500,
            }))
        );

        // An empty range followed by a normal range.
        assert_eq!(
            ranges.next(),
            Ok(Some(Range {
                begin: 0x02010800,
                end: 0x02010900,
            }))
        );

        // A normal range.
        assert_eq!(
            ranges.next(),
            Ok(Some(Range {
                begin: 0x02010a00,
                end: 0x02010b00,
            }))
        );

        // A normal range.
        assert_eq!(
            ranges.next(),
            Ok(Some(Range {
                begin: 0x02010c00,
                end: 0x02010d00,
            }))
        );

        // A range that starts at 0.
        assert_eq!(
            ranges.next(),
            Ok(Some(Range {
                begin: 0x02000000,
                end: 0x02000001,
            }))
        );

        // A range that ends at -1.
        assert_eq!(
            ranges.next(),
            Ok(Some(Range {
                begin: 0x00000000,
                end: 0xffffffff,
            }))
        );

        // A range end.
        assert_eq!(ranges.next(), Ok(None));

        // An offset at the end of buf.
        let mut ranges = debug_rnglists
            .ranges(DebugRangesOffset(buf.len()), 0x01000000)
            .unwrap();
        assert_eq!(ranges.next(), Ok(None));
    }
}
