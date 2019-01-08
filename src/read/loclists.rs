use fallible_iterator::FallibleIterator;

use common::{Format, LocationListsOffset};
use constants;
use endianity::Endianity;
use read::{
    AddressIndex, EndianSlice, Error, Expression, Range, RawRange, Reader, ReaderOffset, Result,
    Section,
};

/// The `DebugLoc` struct represents the DWARF strings
/// found in the `.debug_loc` section.
#[derive(Debug, Clone, Copy)]
pub struct DebugLoc<R: Reader> {
    pub(crate) debug_loc_section: R,
}

impl<'input, Endian> DebugLoc<EndianSlice<'input, Endian>>
where
    Endian: Endianity,
{
    /// Construct a new `DebugLoc` instance from the data in the `.debug_loc`
    /// section.
    ///
    /// It is the caller's responsibility to read the `.debug_loc` section and
    /// present it as a `&[u8]` slice. That means using some ELF loader on
    /// Linux, a Mach-O loader on OSX, etc.
    ///
    /// ```
    /// use gimli::{DebugLoc, LittleEndian};
    ///
    /// # let buf = [0x00, 0x01, 0x02, 0x03];
    /// # let read_debug_loc_section_somehow = || &buf;
    /// let debug_loc = DebugLoc::new(read_debug_loc_section_somehow(), LittleEndian);
    /// ```
    pub fn new(debug_loc_section: &'input [u8], endian: Endian) -> Self {
        Self::from(EndianSlice::new(debug_loc_section, endian))
    }
}

impl<R: Reader> Section<R> for DebugLoc<R> {
    fn section_name() -> &'static str {
        ".debug_loc"
    }
}

impl<R: Reader> From<R> for DebugLoc<R> {
    fn from(debug_loc_section: R) -> Self {
        DebugLoc { debug_loc_section }
    }
}

/// The `DebugLocLists` struct represents the DWARF data
/// found in the `.debug_loclists` section.
#[derive(Debug, Clone, Copy)]
pub struct DebugLocLists<R: Reader> {
    debug_loclists_section: R,
}

impl<'input, Endian> DebugLocLists<EndianSlice<'input, Endian>>
where
    Endian: Endianity,
{
    /// Construct a new `DebugLocLists` instance from the data in the `.debug_loclists`
    /// section.
    ///
    /// It is the caller's responsibility to read the `.debug_loclists` section and
    /// present it as a `&[u8]` slice. That means using some ELF loader on
    /// Linux, a Mach-O loader on OSX, etc.
    ///
    /// ```
    /// use gimli::{DebugLocLists, LittleEndian};
    ///
    /// # let buf = [0x00, 0x01, 0x02, 0x03];
    /// # let read_debug_loclists_section_somehow = || &buf;
    /// let debug_loclists = DebugLocLists::new(read_debug_loclists_section_somehow(), LittleEndian);
    /// ```
    pub fn new(debug_loclists_section: &'input [u8], endian: Endian) -> Self {
        Self::from(EndianSlice::new(debug_loclists_section, endian))
    }
}

impl<R: Reader> Section<R> for DebugLocLists<R> {
    fn section_name() -> &'static str {
        ".debug_loclists"
    }
}

impl<R: Reader> From<R> for DebugLocLists<R> {
    fn from(debug_loclists_section: R) -> Self {
        DebugLocLists {
            debug_loclists_section,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct LocListsHeader {
    format: Format,
    address_size: u8,
    offset_entry_count: u32,
}

impl LocListsHeader {
    /// Return the serialized size of the table header.
    #[inline]
    fn size(self) -> u8 {
        // initial_length + version + address_size + segment_selector_size + offset_entry_count
        self.format.initial_length_size() + 2 + 1 + 1 + 4
    }
}

fn parse_header<R: Reader>(input: &mut R) -> Result<LocListsHeader> {
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
    Ok(LocListsHeader {
        format,
        address_size,
        offset_entry_count,
    })
}

/// The DWARF data found in `.debug_loc` and `.debug_loclists` sections.
#[derive(Debug, Clone, Copy)]
pub struct LocationLists<R: Reader> {
    debug_loc: DebugLoc<R>,
    debug_loclists: DebugLocLists<R>,
    header: LocListsHeader,
}

impl<R: Reader> LocationLists<R> {
    /// Construct a new `LocationLists` instance from the data in the `.debug_loc` and
    /// `.debug_loclists` sections.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        debug_loc: DebugLoc<R>,
        debug_loclists: DebugLocLists<R>,
    ) -> Result<LocationLists<R>> {
        let mut input = debug_loclists.debug_loclists_section.clone();
        let header = if input.is_empty() {
            LocListsHeader {
                format: Format::Dwarf32,
                address_size: 0,
                offset_entry_count: 0,
            }
        } else {
            parse_header(&mut input)?
        };
        Ok(LocationLists {
            debug_loc,
            debug_loclists,
            header,
        })
    }

    /// Iterate over the `LocationListEntry`s starting at the given offset.
    ///
    /// The `unit_version` and `address_size` must match the compilation unit that the
    /// offset was contained in.
    ///
    /// The `base_address` should be obtained from the `DW_AT_low_pc` attribute in the
    /// `DW_TAG_compile_unit` entry for the compilation unit that contains this location
    /// list.
    ///
    /// Can be [used with
    /// `FallibleIterator`](./index.html#using-with-fallibleiterator).
    pub fn locations(
        &self,
        offset: LocationListsOffset<R::Offset>,
        unit_version: u16,
        address_size: u8,
        base_address: u64,
    ) -> Result<LocListIter<R>> {
        Ok(LocListIter::new(
            self.raw_locations(offset, unit_version, address_size)?,
            base_address,
        ))
    }

    /// Iterate over the raw `LocationListEntry`s starting at the given offset.
    ///
    /// The `unit_version` and `address_size` must match the compilation unit that the
    /// offset was contained in.
    ///
    /// This iterator does not perform any processing of the location entries,
    /// such as handling base addresses.
    ///
    /// Can be [used with
    /// `FallibleIterator`](./index.html#using-with-fallibleiterator).
    pub fn raw_locations(
        &self,
        offset: LocationListsOffset<R::Offset>,
        unit_version: u16,
        address_size: u8,
    ) -> Result<RawLocListIter<R>> {
        if unit_version < 5 {
            let mut input = self.debug_loc.debug_loc_section.clone();
            input.skip(offset.0)?;
            Ok(RawLocListIter::new(input, unit_version, address_size))
        } else {
            if offset.0 < R::Offset::from_u8(self.header.size()) {
                return Err(Error::OffsetOutOfBounds);
            }
            let mut input = self.debug_loclists.debug_loclists_section.clone();
            input.skip(offset.0)?;
            Ok(RawLocListIter::new(
                input,
                unit_version,
                self.header.address_size,
            ))
        }
    }
}

/// A raw iterator over a location list.
///
/// This iterator does not perform any processing of the location entries,
/// such as handling base addresses.
#[derive(Debug)]
pub struct RawLocListIter<R: Reader> {
    input: R,
    version: u16,
    address_size: u8,
}

/// A raw entry in .debug_loclists.
#[derive(Clone, Debug)]
pub enum RawLocListEntry<R: Reader> {
    /// DW_LLE_base_address
    BaseAddress {
        /// base address
        addr: u64,
    },
    /// DW_LLE_base_addressx
    BaseAddressx {
        /// base address
        addr: AddressIndex,
    },
    /// DW_LLE_startx_endx
    StartxEndx {
        /// start of range
        begin: AddressIndex,
        /// end of range
        end: AddressIndex,
        /// expression
        data: Expression<R>,
    },
    /// DW_LLE_startx_length
    StartxLength {
        /// start of range
        begin: AddressIndex,
        /// length of range
        length: u64,
        /// expression
        data: Expression<R>,
    },
    /// DW_LLE_offset_pair
    OffsetPair {
        /// start of range
        begin: u64,
        /// end of range
        end: u64,
        /// expression
        data: Expression<R>,
    },
    /// DW_LLE_default_location
    DefaultLocation {
        /// expression
        data: Expression<R>,
    },
    /// DW_LLE_start_end
    StartEnd {
        /// start of range
        begin: u64,
        /// end of range
        end: u64,
        /// expression
        data: Expression<R>,
    },
    /// DW_LLE_start_length
    StartLength {
        /// start of range
        begin: u64,
        /// length of range
        length: u64,
        /// expression
        data: Expression<R>,
    },
}

fn parse_data<R: Reader>(input: &mut R) -> Result<Expression<R>> {
    let len = R::Offset::from_u64(input.read_uleb128()?)?;
    Ok(Expression(input.split(len)?))
}

impl<R: Reader> RawLocListEntry<R> {
    /// Parse a range entry from `.debug_rnglists`
    fn parse(input: &mut R, version: u16, address_size: u8) -> Result<Option<Self>> {
        if version < 5 {
            let range = RawRange::parse(input, address_size)?;
            return Ok(if range.is_end() {
                None
            } else if range.is_base_address(address_size) {
                Some(RawLocListEntry::BaseAddress { addr: range.end })
            } else {
                let len = R::Offset::from_u16(input.read_u16()?);
                let data = Expression(input.split(len)?);
                Some(RawLocListEntry::OffsetPair {
                    begin: range.begin,
                    end: range.end,
                    data,
                })
            });
        }
        Ok(match constants::DwLle(input.read_u8()?) {
            constants::DW_LLE_end_of_list => None,
            constants::DW_LLE_base_addressx => Some(RawLocListEntry::BaseAddressx {
                addr: AddressIndex(input.read_uleb128()?),
            }),
            constants::DW_LLE_startx_endx => Some(RawLocListEntry::StartxEndx {
                begin: AddressIndex(input.read_uleb128()?),
                end: AddressIndex(input.read_uleb128()?),
                data: parse_data(input)?,
            }),
            constants::DW_LLE_startx_length => Some(RawLocListEntry::StartxLength {
                begin: AddressIndex(input.read_uleb128()?),
                length: input.read_uleb128()?,
                data: parse_data(input)?,
            }),
            constants::DW_LLE_offset_pair => Some(RawLocListEntry::OffsetPair {
                begin: input.read_uleb128()?,
                end: input.read_uleb128()?,
                data: parse_data(input)?,
            }),
            constants::DW_LLE_default_location => Some(RawLocListEntry::DefaultLocation {
                data: parse_data(input)?,
            }),
            constants::DW_LLE_base_address => Some(RawLocListEntry::BaseAddress {
                addr: input.read_address(address_size)?,
            }),
            constants::DW_LLE_start_end => Some(RawLocListEntry::StartEnd {
                begin: input.read_address(address_size)?,
                end: input.read_address(address_size)?,
                data: parse_data(input)?,
            }),
            constants::DW_LLE_start_length => Some(RawLocListEntry::StartLength {
                begin: input.read_address(address_size)?,
                length: input.read_uleb128()?,
                data: parse_data(input)?,
            }),
            _ => {
                return Err(Error::InvalidAddressRange);
            }
        })
    }
}

impl<R: Reader> RawLocListIter<R> {
    /// Construct a `RawLocListIter`.
    pub fn new(input: R, version: u16, address_size: u8) -> RawLocListIter<R> {
        RawLocListIter {
            input,
            version,
            address_size,
        }
    }

    /// Advance the iterator to the next location.
    pub fn next(&mut self) -> Result<Option<RawLocListEntry<R>>> {
        if self.input.is_empty() {
            return Ok(None);
        }

        match RawLocListEntry::parse(&mut self.input, self.version, self.address_size) {
            Ok(entry) => {
                if entry.is_none() {
                    self.input.empty();
                }
                Ok(entry)
            }
            Err(e) => {
                self.input.empty();
                Err(e)
            }
        }
    }
}

impl<R: Reader> FallibleIterator for RawLocListIter<R> {
    type Item = RawLocListEntry<R>;
    type Error = Error;

    fn next(&mut self) -> ::std::result::Result<Option<Self::Item>, Self::Error> {
        RawLocListIter::next(self)
    }
}

/// An iterator over a location list.
///
/// This iterator internally handles processing of base address selection entries
/// and list end entries.  Thus, it only returns location entries that are valid
/// and already adjusted for the base address.
#[derive(Debug)]
pub struct LocListIter<R: Reader> {
    raw: RawLocListIter<R>,
    base_address: u64,
}

impl<R: Reader> LocListIter<R> {
    /// Construct a `LocListIter`.
    fn new(raw: RawLocListIter<R>, base_address: u64) -> LocListIter<R> {
        LocListIter { raw, base_address }
    }

    /// Advance the iterator to the next location.
    pub fn next(&mut self) -> Result<Option<LocationListEntry<R>>> {
        loop {
            let raw_loc = match self.raw.next()? {
                Some(loc) => loc,
                None => return Ok(None),
            };

            let (range, data) = match raw_loc {
                RawLocListEntry::BaseAddress { addr } => {
                    self.base_address = addr;
                    continue;
                }
                RawLocListEntry::DefaultLocation { data } => (
                    Range {
                        begin: 0,
                        end: u64::max_value(),
                    },
                    data,
                ),
                RawLocListEntry::OffsetPair { begin, end, data } => {
                    let mut range = Range { begin, end };
                    range.add_base_address(self.base_address, self.raw.address_size);
                    (range, data)
                }
                RawLocListEntry::StartEnd { begin, end, data } => (Range { begin, end }, data),
                RawLocListEntry::StartLength {
                    begin,
                    length,
                    data,
                } => (
                    Range {
                        begin,
                        end: begin + length,
                    },
                    data,
                ),
                _ => {
                    // We don't support AddressIndex-based entries yet
                    return Err(Error::UnsupportedAddressIndex);
                }
            };

            if range.begin > range.end {
                self.raw.input.empty();
                return Err(Error::InvalidLocationAddressRange);
            }

            return Ok(Some(LocationListEntry { range, data }));
        }
    }
}

impl<R: Reader> FallibleIterator for LocListIter<R> {
    type Item = LocationListEntry<R>;
    type Error = Error;

    fn next(&mut self) -> ::std::result::Result<Option<Self::Item>, Self::Error> {
        LocListIter::next(self)
    }
}

/// A location list entry from the `.debug_loc` or `.debug_loclists` sections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LocationListEntry<R: Reader> {
    /// The address range that this location is valid for.
    pub range: Range,

    /// The data containing a single location description.
    pub data: Expression<R>,
}

#[cfg(test)]
mod tests {
    extern crate test_assembler;

    use self::test_assembler::{Endian, Label, LabelMaker, Section};
    use super::*;
    use endianity::LittleEndian;
    use read::{EndianSlice, Range};
    use test_util::GimliSectionMethods;

    #[test]
    fn test_loclists_32() {
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
            .L8(4).uleb(0x10200).uleb(0x10300).uleb(4).L32(2)
            // A base address selection followed by an OffsetPair.
            .L8(6).L32(0x0200_0000)
            .L8(4).uleb(0x10400).uleb(0x10500).uleb(4).L32(3)
            // An empty OffsetPair followed by a normal OffsetPair.
            .L8(4).uleb(0x10600).uleb(0x10600).uleb(4).L32(4)
            .L8(4).uleb(0x10800).uleb(0x10900).uleb(4).L32(5)
            // A StartEnd
            .L8(7).L32(0x201_0a00).L32(0x201_0b00).uleb(4).L32(6)
            // A StartLength
            .L8(8).L32(0x201_0c00).uleb(0x100).uleb(4).L32(7)
            // An OffsetPair that starts at 0.
            .L8(4).uleb(0).uleb(1).uleb(4).L32(8)
            // An OffsetPair that ends at -1.
            .L8(6).L32(0)
            .L8(4).uleb(0).uleb(0xffff_ffff).uleb(4).L32(9)
            // A DefaultLocation
            .L8(5).uleb(4).L32(10)
            // A range end.
            .L8(0)
            // Some extra data.
            .L32(0xffff_ffff);
        size.set_const((&section.here() - &start - 4) as u64);

        let buf = section.get_contents().unwrap();
        let debug_loc = DebugLoc::new(&[], LittleEndian);
        let debug_loclists = DebugLocLists::new(&buf, LittleEndian);
        let loclists = LocationLists::new(debug_loc, debug_loclists).unwrap();
        let offset = LocationListsOffset((&first - &start) as usize);
        let mut locations = loclists.locations(offset, 5, 0, 0x0100_0000).unwrap();

        // A normal location.
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0x0101_0200,
                    end: 0x0101_0300,
                },
                data: Expression(EndianSlice::new(&[2, 0, 0, 0], LittleEndian)),
            }))
        );

        // A base address selection followed by a normal location.
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0x0201_0400,
                    end: 0x0201_0500,
                },
                data: Expression(EndianSlice::new(&[3, 0, 0, 0], LittleEndian)),
            }))
        );

        // An empty location range followed by a normal location.
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0x0201_0600,
                    end: 0x0201_0600,
                },
                data: Expression(EndianSlice::new(&[4, 0, 0, 0], LittleEndian)),
            }))
        );
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0x0201_0800,
                    end: 0x0201_0900,
                },
                data: Expression(EndianSlice::new(&[5, 0, 0, 0], LittleEndian)),
            }))
        );

        // A normal location.
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0x0201_0a00,
                    end: 0x0201_0b00,
                },
                data: Expression(EndianSlice::new(&[6, 0, 0, 0], LittleEndian)),
            }))
        );

        // A normal location.
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0x0201_0c00,
                    end: 0x0201_0d00,
                },
                data: Expression(EndianSlice::new(&[7, 0, 0, 0], LittleEndian)),
            }))
        );

        // A location range that starts at 0.
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0x0200_0000,
                    end: 0x0200_0001,
                },
                data: Expression(EndianSlice::new(&[8, 0, 0, 0], LittleEndian)),
            }))
        );

        // A location range that ends at -1.
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0x0000_0000,
                    end: 0xffff_ffff,
                },
                data: Expression(EndianSlice::new(&[9, 0, 0, 0], LittleEndian)),
            }))
        );

        // A DefaultLocation.
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0,
                    end: u64::max_value(),
                },
                data: Expression(EndianSlice::new(&[10, 0, 0, 0], LittleEndian)),
            }))
        );

        // A location list end.
        assert_eq!(locations.next(), Ok(None));

        // An offset at the end of buf.
        let mut locations = loclists
            .locations(LocationListsOffset(buf.len()), 5, 0, 0x0100_0000)
            .unwrap();
        assert_eq!(locations.next(), Ok(None));
    }

    #[test]
    fn test_loclists_64() {
        let start = Label::new();
        let first = Label::new();
        let size = Label::new();
        #[cfg_attr(rustfmt, rustfmt_skip)]
        let section = Section::with_endian(Endian::Little)
            // Header
            .mark(&start)
            .L32(0xffff_ffff)
            .L64(&size)
            .L16(5)
            .L8(8)
            .L8(0)
            .L32(0)
            .mark(&first)
            // OffsetPair
            .L8(4).uleb(0x10200).uleb(0x10300).uleb(4).L32(2)
            // A base address selection followed by an OffsetPair.
            .L8(6).L64(0x0200_0000)
            .L8(4).uleb(0x10400).uleb(0x10500).uleb(4).L32(3)
            // An empty OffsetPair followed by a normal OffsetPair.
            .L8(4).uleb(0x10600).uleb(0x10600).uleb(4).L32(4)
            .L8(4).uleb(0x10800).uleb(0x10900).uleb(4).L32(5)
            // A StartEnd
            .L8(7).L64(0x201_0a00).L64(0x201_0b00).uleb(4).L32(6)
            // A StartLength
            .L8(8).L64(0x201_0c00).uleb(0x100).uleb(4).L32(7)
            // An OffsetPair that starts at 0.
            .L8(4).uleb(0).uleb(1).uleb(4).L32(8)
            // An OffsetPair that ends at -1.
            .L8(6).L64(0)
            .L8(4).uleb(0).uleb(0xffff_ffff).uleb(4).L32(9)
            // A DefaultLocation
            .L8(5).uleb(4).L32(10)
            // A range end.
            .L8(0)
            // Some extra data.
            .L32(0xffff_ffff);
        size.set_const((&section.here() - &start - 12) as u64);

        let buf = section.get_contents().unwrap();
        let debug_loc = DebugLoc::new(&[], LittleEndian);
        let debug_loclists = DebugLocLists::new(&buf, LittleEndian);
        let loclists = LocationLists::new(debug_loc, debug_loclists).unwrap();
        let offset = LocationListsOffset((&first - &start) as usize);
        let mut locations = loclists.locations(offset, 5, 0, 0x0100_0000).unwrap();

        // A normal location.
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0x0101_0200,
                    end: 0x0101_0300,
                },
                data: Expression(EndianSlice::new(&[2, 0, 0, 0], LittleEndian)),
            }))
        );

        // A base address selection followed by a normal location.
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0x0201_0400,
                    end: 0x0201_0500,
                },
                data: Expression(EndianSlice::new(&[3, 0, 0, 0], LittleEndian)),
            }))
        );

        // An empty location range followed by a normal location.
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0x0201_0600,
                    end: 0x0201_0600,
                },
                data: Expression(EndianSlice::new(&[4, 0, 0, 0], LittleEndian)),
            }))
        );
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0x0201_0800,
                    end: 0x0201_0900,
                },
                data: Expression(EndianSlice::new(&[5, 0, 0, 0], LittleEndian)),
            }))
        );

        // A normal location.
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0x0201_0a00,
                    end: 0x0201_0b00,
                },
                data: Expression(EndianSlice::new(&[6, 0, 0, 0], LittleEndian)),
            }))
        );

        // A normal location.
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0x0201_0c00,
                    end: 0x0201_0d00,
                },
                data: Expression(EndianSlice::new(&[7, 0, 0, 0], LittleEndian)),
            }))
        );

        // A location range that starts at 0.
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0x0200_0000,
                    end: 0x0200_0001,
                },
                data: Expression(EndianSlice::new(&[8, 0, 0, 0], LittleEndian)),
            }))
        );

        // A location range that ends at -1.
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0x0000_0000,
                    end: 0xffff_ffff,
                },
                data: Expression(EndianSlice::new(&[9, 0, 0, 0], LittleEndian)),
            }))
        );

        // A DefaultLocation.
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0,
                    end: u64::max_value(),
                },
                data: Expression(EndianSlice::new(&[10, 0, 0, 0], LittleEndian)),
            }))
        );

        // A location list end.
        assert_eq!(locations.next(), Ok(None));

        // An offset at the end of buf.
        let mut locations = loclists
            .locations(LocationListsOffset(buf.len()), 5, 0, 0x0100_0000)
            .unwrap();
        assert_eq!(locations.next(), Ok(None));
    }

    #[test]
    fn test_location_list_32() {
        let start = Label::new();
        let first = Label::new();
        #[cfg_attr(rustfmt, rustfmt_skip)]
        let section = Section::with_endian(Endian::Little)
            // A location before the offset.
            .mark(&start)
            .L32(0x10000).L32(0x10100).L16(4).L32(1)
            .mark(&first)
            // A normal location.
            .L32(0x10200).L32(0x10300).L16(4).L32(2)
            // A base address selection followed by a normal location.
            .L32(0xffff_ffff).L32(0x0200_0000)
            .L32(0x10400).L32(0x10500).L16(4).L32(3)
            // An empty location range followed by a normal location.
            .L32(0x10600).L32(0x10600).L16(4).L32(4)
            .L32(0x10800).L32(0x10900).L16(4).L32(5)
            // A location range that starts at 0.
            .L32(0).L32(1).L16(4).L32(6)
            // A location range that ends at -1.
            .L32(0xffff_ffff).L32(0x0000_0000)
            .L32(0).L32(0xffff_ffff).L16(4).L32(7)
            // A location list end.
            .L32(0).L32(0)
            // Some extra data.
            .L32(0);

        let buf = section.get_contents().unwrap();
        let debug_loc = DebugLoc::new(&buf, LittleEndian);
        let debug_loclists = DebugLocLists::new(&[], LittleEndian);
        let loclists = LocationLists::new(debug_loc, debug_loclists).unwrap();
        let offset = LocationListsOffset((&first - &start) as usize);
        let version = 4;
        let mut locations = loclists.locations(offset, version, 4, 0x0100_0000).unwrap();

        // A normal location.
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0x0101_0200,
                    end: 0x0101_0300,
                },
                data: Expression(EndianSlice::new(&[2, 0, 0, 0], LittleEndian)),
            }))
        );

        // A base address selection followed by a normal location.
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0x0201_0400,
                    end: 0x0201_0500,
                },
                data: Expression(EndianSlice::new(&[3, 0, 0, 0], LittleEndian)),
            }))
        );

        // An empty location range followed by a normal location.
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0x0201_0600,
                    end: 0x0201_0600,
                },
                data: Expression(EndianSlice::new(&[4, 0, 0, 0], LittleEndian)),
            }))
        );
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0x0201_0800,
                    end: 0x0201_0900,
                },
                data: Expression(EndianSlice::new(&[5, 0, 0, 0], LittleEndian)),
            }))
        );

        // A location range that starts at 0.
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0x0200_0000,
                    end: 0x0200_0001,
                },
                data: Expression(EndianSlice::new(&[6, 0, 0, 0], LittleEndian)),
            }))
        );

        // A location range that ends at -1.
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0x0000_0000,
                    end: 0xffff_ffff,
                },
                data: Expression(EndianSlice::new(&[7, 0, 0, 0], LittleEndian)),
            }))
        );

        // A location list end.
        assert_eq!(locations.next(), Ok(None));

        // An offset at the end of buf.
        let mut locations = loclists
            .locations(LocationListsOffset(buf.len()), version, 4, 0x0100_0000)
            .unwrap();
        assert_eq!(locations.next(), Ok(None));
    }

    #[test]
    fn test_location_list_64() {
        let start = Label::new();
        let first = Label::new();
        #[cfg_attr(rustfmt, rustfmt_skip)]
        let section = Section::with_endian(Endian::Little)
            // A location before the offset.
            .mark(&start)
            .L64(0x10000).L64(0x10100).L16(4).L32(1)
            .mark(&first)
            // A normal location.
            .L64(0x10200).L64(0x10300).L16(4).L32(2)
            // A base address selection followed by a normal location.
            .L64(0xffff_ffff_ffff_ffff).L64(0x0200_0000)
            .L64(0x10400).L64(0x10500).L16(4).L32(3)
            // An empty location range followed by a normal location.
            .L64(0x10600).L64(0x10600).L16(4).L32(4)
            .L64(0x10800).L64(0x10900).L16(4).L32(5)
            // A location range that starts at 0.
            .L64(0).L64(1).L16(4).L32(6)
            // A location range that ends at -1.
            .L64(0xffff_ffff_ffff_ffff).L64(0x0000_0000)
            .L64(0).L64(0xffff_ffff_ffff_ffff).L16(4).L32(7)
            // A location list end.
            .L64(0).L64(0)
            // Some extra data.
            .L64(0);

        let buf = section.get_contents().unwrap();
        let debug_loc = DebugLoc::new(&buf, LittleEndian);
        let debug_loclists = DebugLocLists::new(&[], LittleEndian);
        let loclists = LocationLists::new(debug_loc, debug_loclists).unwrap();
        let offset = LocationListsOffset((&first - &start) as usize);
        let version = 4;
        let mut locations = loclists.locations(offset, version, 8, 0x0100_0000).unwrap();

        // A normal location.
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0x0101_0200,
                    end: 0x0101_0300,
                },
                data: Expression(EndianSlice::new(&[2, 0, 0, 0], LittleEndian)),
            }))
        );

        // A base address selection followed by a normal location.
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0x0201_0400,
                    end: 0x0201_0500,
                },
                data: Expression(EndianSlice::new(&[3, 0, 0, 0], LittleEndian)),
            }))
        );

        // An empty location range followed by a normal location.
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0x0201_0600,
                    end: 0x0201_0600,
                },
                data: Expression(EndianSlice::new(&[4, 0, 0, 0], LittleEndian)),
            }))
        );
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0x0201_0800,
                    end: 0x0201_0900,
                },
                data: Expression(EndianSlice::new(&[5, 0, 0, 0], LittleEndian)),
            }))
        );

        // A location range that starts at 0.
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0x0200_0000,
                    end: 0x0200_0001,
                },
                data: Expression(EndianSlice::new(&[6, 0, 0, 0], LittleEndian)),
            }))
        );

        // A location range that ends at -1.
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0x0,
                    end: 0xffff_ffff_ffff_ffff,
                },
                data: Expression(EndianSlice::new(&[7, 0, 0, 0], LittleEndian)),
            }))
        );

        // A location list end.
        assert_eq!(locations.next(), Ok(None));

        // An offset at the end of buf.
        let mut locations = loclists
            .locations(LocationListsOffset(buf.len()), version, 8, 0x0100_0000)
            .unwrap();
        assert_eq!(locations.next(), Ok(None));
    }

    #[test]
    fn test_locations_invalid() {
        #[cfg_attr(rustfmt, rustfmt_skip)]
        let section = Section::with_endian(Endian::Little)
            // An invalid location range.
            .L32(0x20000).L32(0x10000).L16(4).L32(1)
            // An invalid range after wrapping.
            .L32(0x20000).L32(0xff01_0000).L16(4).L32(2);

        let buf = section.get_contents().unwrap();
        let debug_loc = DebugLoc::new(&buf, LittleEndian);
        let debug_loclists = DebugLocLists::new(&[], LittleEndian);
        let loclists = LocationLists::new(debug_loc, debug_loclists).unwrap();
        let version = 4;

        // An invalid location range.
        let mut locations = loclists
            .locations(LocationListsOffset(0x0), version, 4, 0x0100_0000)
            .unwrap();
        assert_eq!(locations.next(), Err(Error::InvalidLocationAddressRange));

        // An invalid location range after wrapping.
        let mut locations = loclists
            .locations(LocationListsOffset(14), version, 4, 0x0100_0000)
            .unwrap();
        assert_eq!(locations.next(), Err(Error::InvalidLocationAddressRange));

        // An invalid offset.
        match loclists.locations(LocationListsOffset(buf.len() + 1), version, 4, 0x0100_0000) {
            Err(Error::UnexpectedEof) => {}
            otherwise => panic!("Unexpected result: {:?}", otherwise),
        }
    }
}
