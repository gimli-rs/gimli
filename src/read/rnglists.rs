use constants;
use endian_slice::EndianSlice;
use endianity::Endianity;
use fallible_iterator::FallibleIterator;
use parser::{Error, Format, Result};
use reader::{Reader, ReaderOffset};
use Section;

/// An offset into the `.debug_addr` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AddressIndex(pub u64);

/// The `DebugRanges` struct represents the DWARF strings
/// found in the `.debug_ranges` section.
#[derive(Debug, Clone, Copy)]
pub struct DebugRanges<R: Reader> {
    pub(crate) debug_ranges_section: R,
}

impl<'input, Endian> DebugRanges<EndianSlice<'input, Endian>>
where
    Endian: Endianity,
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
        Self::from(EndianSlice::new(debug_ranges_section, endian))
    }
}

impl<R: Reader> Section<R> for DebugRanges<R> {
    fn section_name() -> &'static str {
        ".debug_ranges"
    }
}

impl<R: Reader> From<R> for DebugRanges<R> {
    fn from(debug_ranges_section: R) -> Self {
        DebugRanges {
            debug_ranges_section,
        }
    }
}

/// The `DebugRngLists` struct represents the contents of the
/// `.debug_rnglists` section.
#[derive(Debug, Clone, Copy)]
pub struct DebugRngLists<R: Reader> {
    debug_rnglists_section: R,
}

impl<'input, Endian> DebugRngLists<EndianSlice<'input, Endian>>
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
    /// let debug_rnglists =
    ///     DebugRngLists::new(read_debug_rnglists_section_somehow(), LittleEndian);
    /// ```
    pub fn new(debug_rnglists_section: &'input [u8], endian: Endian) -> Self {
        Self::from(EndianSlice::new(debug_rnglists_section, endian))
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

#[derive(Debug, Clone, Copy)]
struct RngListsHeader {
    format: Format,
    address_size: u8,
    offset_entry_count: u32,
}

impl RngListsHeader {
    /// Return the serialized size of the table header.
    fn size(&self) -> u8 {
        // initial_length + version + address_size + segment_selector_size + offset_entry_count
        self.format.initial_length_size() + 2 + 1 + 1 + 4
    }
}

fn parse_header<R: Reader>(input: &mut R) -> Result<RngListsHeader> {
    let (length, format) = input.read_initial_length()?;
    input.truncate(length)?;

    let version = input.read_u16()?;
    if version != 5 {
        return Err(Error::UnknownVersion(u64::from(version)));
    }

    let address_size = input.read_u8()?;
    let segment_selector_size = input.read_u8()?;
    if segment_selector_size != 0 {
        return Err(Error::UnsupportedSegmentSize);
    }
    let offset_entry_count = input.read_u32()?;
    Ok(RngListsHeader {
        format,
        address_size,
        offset_entry_count,
    })
}

/// An offset into either the `.debug_ranges` section or the `.debug_rnglists` section,
/// depending on the version of the unit the offset was contained in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RangeListsOffset<T = usize>(pub T);

/// The DWARF data found in `.debug_ranges` and `.debug_rnglists` sections.
#[derive(Debug, Clone, Copy)]
pub struct RangeLists<R: Reader> {
    debug_ranges: DebugRanges<R>,
    debug_rnglists: DebugRngLists<R>,
    header: RngListsHeader,
}

impl<R: Reader> RangeLists<R> {
    /// Construct a new `RangeLists` instance from the data in the `.debug_ranges` and
    /// `.debug_rnglists` sections.
    pub fn new(
        debug_ranges: DebugRanges<R>,
        debug_rnglists: DebugRngLists<R>,
    ) -> Result<RangeLists<R>> {
        let mut input = debug_rnglists.debug_rnglists_section.clone();
        let header = if input.is_empty() {
            RngListsHeader {
                format: Format::Dwarf32,
                address_size: 0,
                offset_entry_count: 0,
            }
        } else {
            parse_header(&mut input)?
        };
        Ok(RangeLists {
            debug_ranges,
            debug_rnglists,
            header,
        })
    }

    /// Iterate over the `Range` list entries starting at the given offset.
    ///
    /// The `unit_version` and `address_size` must match the compilation unit that the
    /// offset was contained in.
    ///
    /// The `base_address` should be obtained from the `DW_AT_low_pc` attribute in the
    /// `DW_TAG_compile_unit` entry for the compilation unit that contains this range list.
    ///
    /// Can be [used with
    /// `FallibleIterator`](./index.html#using-with-fallibleiterator).
    pub fn ranges(
        &self,
        offset: RangeListsOffset<R::Offset>,
        unit_version: u16,
        address_size: u8,
        base_address: u64,
    ) -> Result<RngListIter<R>> {
        Ok(RngListIter::new(
            self.raw_ranges(offset, unit_version, address_size)?,
            base_address,
        ))
    }

    /// Iterate over the `RawRngListEntry`ies starting at the given offset.
    ///
    /// The `unit_version` and `address_size` must match the compilation unit that the
    /// offset was contained in.
    ///
    /// This iterator does not perform any processing of the range entries,
    /// such as handling base addresses.
    ///
    /// Can be [used with
    /// `FallibleIterator`](./index.html#using-with-fallibleiterator).
    pub fn raw_ranges(
        &self,
        offset: RangeListsOffset<R::Offset>,
        unit_version: u16,
        address_size: u8,
    ) -> Result<RawRngListIter<R>> {
        if unit_version < 5 {
            let mut input = self.debug_ranges.debug_ranges_section.clone();
            input.skip(offset.0)?;
            Ok(RawRngListIter::new(input, unit_version, address_size))
        } else {
            if offset.0 < R::Offset::from_u8(self.header.size()) {
                return Err(Error::OffsetOutOfBounds);
            }
            let mut input = self.debug_rnglists.debug_rnglists_section.clone();
            input.skip(offset.0)?;
            Ok(RawRngListIter::new(
                input,
                unit_version,
                self.header.address_size,
            ))
        }
    }
}

/// A raw iterator over an address range list.
///
/// This iterator does not perform any processing of the range entries,
/// such as handling base addresses.
#[derive(Debug)]
pub struct RawRngListIter<R: Reader> {
    input: R,
    version: u16,
    address_size: u8,
}

/// A raw entry in .debug_rnglists
#[derive(Clone, Debug)]
pub enum RawRngListEntry {
    /// DW_RLE_base_address
    BaseAddress {
        /// base address
        addr: u64,
    },
    /// DW_RLE_base_addressx
    BaseAddressx {
        /// base address
        addr: AddressIndex,
    },
    /// DW_RLE_startx_endx
    StartxEndx {
        /// start of range
        begin: AddressIndex,
        /// end of range
        end: AddressIndex,
    },
    /// DW_RLE_startx_length
    StartxLength {
        /// start of range
        begin: AddressIndex,
        /// length of range
        length: u64,
    },
    /// DW_RLE_offset_pair
    OffsetPair {
        /// start of range
        begin: u64,
        /// end of range
        end: u64,
    },
    /// DW_RLE_start_end
    StartEnd {
        /// start of range
        begin: u64,
        /// end of range
        end: u64,
    },
    /// DW_RLE_start_length
    StartLength {
        /// start of range
        begin: u64,
        /// length of range
        length: u64,
    },
}

impl RawRngListEntry {
    /// Parse a range entry from `.debug_rnglists`
    fn parse<R: Reader>(input: &mut R, version: u16, address_size: u8) -> Result<Option<Self>> {
        if version < 5 {
            let range = RawRange::parse(input, address_size)?;
            return Ok(if range.is_end() {
                None
            } else if range.is_base_address(address_size) {
                Some(RawRngListEntry::BaseAddress { addr: range.end })
            } else {
                Some(RawRngListEntry::OffsetPair {
                    begin: range.begin,
                    end: range.end,
                })
            });
        }
        Ok(match constants::DwRle(input.read_u8()?) {
            constants::DW_RLE_end_of_list => None,
            constants::DW_RLE_base_addressx => Some(RawRngListEntry::BaseAddressx {
                addr: AddressIndex(input.read_uleb128()?),
            }),
            constants::DW_RLE_startx_endx => Some(RawRngListEntry::StartxEndx {
                begin: AddressIndex(input.read_uleb128()?),
                end: AddressIndex(input.read_uleb128()?),
            }),
            constants::DW_RLE_startx_length => Some(RawRngListEntry::StartxLength {
                begin: AddressIndex(input.read_uleb128()?),
                length: input.read_uleb128()?,
            }),
            constants::DW_RLE_offset_pair => Some(RawRngListEntry::OffsetPair {
                begin: input.read_uleb128()?,
                end: input.read_uleb128()?,
            }),
            constants::DW_RLE_base_address => Some(RawRngListEntry::BaseAddress {
                addr: input.read_address(address_size)?,
            }),
            constants::DW_RLE_start_end => Some(RawRngListEntry::StartEnd {
                begin: input.read_address(address_size)?,
                end: input.read_address(address_size)?,
            }),
            constants::DW_RLE_start_length => Some(RawRngListEntry::StartLength {
                begin: input.read_address(address_size)?,
                length: input.read_uleb128()?,
            }),
            _ => {
                return Err(Error::InvalidAddressRange);
            }
        })
    }
}

impl<R: Reader> RawRngListIter<R> {
    /// Construct a `RawRngListIter`.
    fn new(input: R, version: u16, address_size: u8) -> RawRngListIter<R> {
        RawRngListIter {
            input,
            version,
            address_size,
        }
    }

    /// Advance the iterator to the next range.
    pub fn next(&mut self) -> Result<Option<RawRngListEntry>> {
        if self.input.is_empty() {
            return Ok(None);
        }

        match RawRngListEntry::parse(&mut self.input, self.version, self.address_size) {
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
        RngListIter { raw, base_address }
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
                }
                RawRngListEntry::OffsetPair { begin, end } => {
                    let mut range = Range { begin, end };
                    range.add_base_address(self.base_address, self.raw.address_size);
                    range
                }
                RawRngListEntry::StartEnd { begin, end } => Range { begin, end },
                RawRngListEntry::StartLength { begin, length } => Range {
                    begin,
                    end: begin + length,
                },
                _ => {
                    // We don't support AddressIndex-based entries yet
                    return Err(Error::UnsupportedAddressIndex);
                }
            };

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

/// A raw address range from the `.debug_ranges` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct RawRange {
    /// The beginning address of the range.
    pub begin: u64,

    /// The first address past the end of the range.
    pub end: u64,
}

impl RawRange {
    /// Check if this is a range end entry.
    ///
    /// This will only occur for raw ranges.
    #[inline]
    pub fn is_end(&self) -> bool {
        self.begin == 0 && self.end == 0
    }

    /// Check if this is a base address selection entry.
    ///
    /// A base address selection entry changes the base address that subsequent
    /// range entries are relative to.  This will only occur for raw ranges.
    #[inline]
    pub fn is_base_address(&self, address_size: u8) -> bool {
        self.begin == !0 >> (64 - address_size * 8)
    }

    /// Parse an address range entry from `.debug_ranges` or `.debug_loc`.
    #[doc(hidden)]
    #[inline]
    pub fn parse<R: Reader>(input: &mut R, address_size: u8) -> Result<RawRange> {
        let begin = input.read_address(address_size)?;
        let end = input.read_address(address_size)?;
        let range = RawRange { begin, end };
        Ok(range)
    }
}

/// An address range from the `.debug_ranges` or `.debug_rnglists` sections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Range {
    /// The beginning address of the range.
    pub begin: u64,

    /// The first address past the end of the range.
    pub end: u64,
}

impl Range {
    /// Add a base address to this range.
    #[inline]
    pub(crate) fn add_base_address(&mut self, base_address: u64, address_size: u8) {
        let mask = !0 >> (64 - address_size * 8);
        self.begin = base_address.wrapping_add(self.begin) & mask;
        self.end = base_address.wrapping_add(self.end) & mask;
    }
}

#[cfg(test)]
mod tests {
    extern crate test_assembler;

    use self::test_assembler::{Endian, Label, LabelMaker, Section};
    use super::*;
    use endianity::LittleEndian;
    use test_util::GimliSectionMethods;

    #[test]
    fn test_rnglists_32() {
        let start = Label::new();
        let first = Label::new();
        let size = Label::new();
        #[cfg_attr(rustfmt, rustfmt_skip)]
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
            // An OffsetPair that starts and ends at 0.
            .L8(4).uleb(0).uleb(0)
            // An OffsetPair that ends at -1.
            .L8(5).L32(0)
            .L8(4).uleb(0).uleb(0xffffffff)
            // A range end.
            .L8(0)
            // Some extra data.
            .L32(0xffffffff);
        size.set_const((&section.here() - &start - 4) as u64);

        let buf = section.get_contents().unwrap();
        let debug_ranges = DebugRanges::new(&[], LittleEndian);
        let debug_rnglists = DebugRngLists::new(&buf, LittleEndian);
        let rnglists = RangeLists::new(debug_ranges, debug_rnglists).unwrap();
        let offset = RangeListsOffset((&first - &start) as usize);
        let mut ranges = rnglists.ranges(offset, 5, 0, 0x01000000).unwrap();

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
                begin: 0x02010600,
                end: 0x02010600,
            }))
        );
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

        // A range that starts and ends at 0.
        assert_eq!(
            ranges.next(),
            Ok(Some(Range {
                begin: 0x02000000,
                end: 0x02000000,
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
        let mut ranges = rnglists
            .ranges(RangeListsOffset(buf.len()), 5, 0, 0x01000000)
            .unwrap();
        assert_eq!(ranges.next(), Ok(None));
    }

    #[test]
    fn test_rnglists_64() {
        let start = Label::new();
        let first = Label::new();
        let size = Label::new();
        #[cfg_attr(rustfmt, rustfmt_skip)]
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
            // An OffsetPair that starts and ends at 0.
            .L8(4).uleb(0).uleb(0)
            // An OffsetPair that ends at -1.
            .L8(5).L64(0)
            .L8(4).uleb(0).uleb(0xffffffff)
            // A range end.
            .L8(0)
            // Some extra data.
            .L32(0xffffffff);
        size.set_const((&section.here() - &start - 12) as u64);

        let buf = section.get_contents().unwrap();
        let debug_ranges = DebugRanges::new(&[], LittleEndian);
        let debug_rnglists = DebugRngLists::new(&buf, LittleEndian);
        let rnglists = RangeLists::new(debug_ranges, debug_rnglists).unwrap();
        let offset = RangeListsOffset((&first - &start) as usize);
        let mut ranges = rnglists.ranges(offset, 5, 0, 0x01000000).unwrap();

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
                begin: 0x02010600,
                end: 0x02010600,
            }))
        );
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

        // A range that starts and ends at 0.
        assert_eq!(
            ranges.next(),
            Ok(Some(Range {
                begin: 0x02000000,
                end: 0x02000000,
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
        let mut ranges = rnglists
            .ranges(RangeListsOffset(buf.len()), 5, 0, 0x01000000)
            .unwrap();
        assert_eq!(ranges.next(), Ok(None));
    }

    #[test]
    fn test_raw_range() {
        let range = RawRange {
            begin: 0,
            end: 0xffffffff,
        };
        assert!(!range.is_end());
        assert!(!range.is_base_address(4));
        assert!(!range.is_base_address(8));

        let range = RawRange { begin: 0, end: 0 };
        assert!(range.is_end());
        assert!(!range.is_base_address(4));
        assert!(!range.is_base_address(8));

        let range = RawRange {
            begin: 0xffffffff,
            end: 0,
        };
        assert!(!range.is_end());
        assert!(range.is_base_address(4));
        assert!(!range.is_base_address(8));

        let range = RawRange {
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
        #[cfg_attr(rustfmt, rustfmt_skip)]
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
        let debug_rnglists = DebugRngLists::new(&[], LittleEndian);
        let rnglists = RangeLists::new(debug_ranges, debug_rnglists).unwrap();
        let offset = RangeListsOffset((&first - &start) as usize);
        let version = 4;
        let mut ranges = rnglists.ranges(offset, version, 4, 0x01000000).unwrap();

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
                begin: 0x02010600,
                end: 0x02010600,
            }))
        );
        assert_eq!(
            ranges.next(),
            Ok(Some(Range {
                begin: 0x02010800,
                end: 0x02010900,
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
        let mut ranges = rnglists
            .ranges(RangeListsOffset(buf.len()), version, 4, 0x01000000)
            .unwrap();
        assert_eq!(ranges.next(), Ok(None));
    }

    #[test]
    fn test_ranges_64() {
        let start = Label::new();
        let first = Label::new();
        #[cfg_attr(rustfmt, rustfmt_skip)]
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
        let debug_rnglists = DebugRngLists::new(&[], LittleEndian);
        let rnglists = RangeLists::new(debug_ranges, debug_rnglists).unwrap();
        let offset = RangeListsOffset((&first - &start) as usize);
        let version = 4;
        let mut ranges = rnglists.ranges(offset, version, 8, 0x01000000).unwrap();

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
                begin: 0x02010600,
                end: 0x02010600,
            }))
        );
        assert_eq!(
            ranges.next(),
            Ok(Some(Range {
                begin: 0x02010800,
                end: 0x02010900,
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
                begin: 0x0,
                end: 0xffffffffffffffff,
            }))
        );

        // A range end.
        assert_eq!(ranges.next(), Ok(None));

        // An offset at the end of buf.
        let mut ranges = rnglists
            .ranges(RangeListsOffset(buf.len()), version, 8, 0x01000000)
            .unwrap();
        assert_eq!(ranges.next(), Ok(None));
    }

    #[test]
    fn test_ranges_invalid() {
        #[cfg_attr(rustfmt, rustfmt_skip)]
        let section = Section::with_endian(Endian::Little)
            // An invalid range.
            .L32(0x20000).L32(0x10000)
            // An invalid range after wrapping.
            .L32(0x20000).L32(0xff010000);

        let buf = section.get_contents().unwrap();
        let debug_ranges = DebugRanges::new(&buf, LittleEndian);
        let debug_rnglists = DebugRngLists::new(&[], LittleEndian);
        let rnglists = RangeLists::new(debug_ranges, debug_rnglists).unwrap();
        let version = 4;

        // An invalid range.
        let mut ranges = rnglists
            .ranges(RangeListsOffset(0x0), version, 4, 0x01000000)
            .unwrap();
        assert_eq!(ranges.next(), Err(Error::InvalidAddressRange));

        // An invalid range after wrapping.
        let mut ranges = rnglists
            .ranges(RangeListsOffset(0x8), version, 4, 0x01000000)
            .unwrap();
        assert_eq!(ranges.next(), Err(Error::InvalidAddressRange));

        // An invalid offset.
        match rnglists.ranges(RangeListsOffset(buf.len() + 1), version, 4, 0x01000000) {
            Err(Error::UnexpectedEof) => {}
            otherwise => panic!("Unexpected result: {:?}", otherwise),
        }
    }
}
