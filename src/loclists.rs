use constants;
use endianity::{EndianBuf, Endianity};
use fallible_iterator::FallibleIterator;
use loc::{DebugLocOffset, LocationListEntry};
use op::Expression;
use parser::{self, Format, Error, Result};
use reader::{Reader, ReaderOffset};
use ranges::Range;
use rnglists::AddressIndex;
use Section;

/// The `DebugLocLists` struct represents the DWARF data
/// found in the `.debug_loclists` section.
#[derive(Debug, Clone, Copy)]
pub struct DebugLocLists<R: Reader> {
    debug_loclists_section: R,
}

impl<'input, Endian> DebugLocLists<EndianBuf<'input, Endian>>
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
        Self::from(EndianBuf::new(debug_loclists_section, endian))
    }
}

#[derive(Debug, Clone, Copy)]
struct LocListsHeader {
    format: Format,
    address_size: u8,
    offset_entry_count: u32,
}

fn parse_header<R: Reader>(input: &mut R) -> Result<LocListsHeader> {
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
    Ok(LocListsHeader {
        format: format,
        address_size: address_size,
        offset_entry_count: offset_entry_count,
    })
}

impl<R: Reader> DebugLocLists<R> {
    /// Iterate over the `LocationListEntry`s starting at the given offset.
    ///
    /// The `base_address` should be obtained from the `DW_AT_low_pc` attribute in the
    /// `DW_TAG_compile_unit` entry for the compilation unit that contains this location
    /// list.
    ///
    /// Can be [used with
    /// `FallibleIterator`](./index.html#using-with-fallibleiterator).
    pub fn locations(
        &self,
        offset: DebugLocOffset<R::Offset>,
        base_address: u64,
    ) -> Result<LocListIter<R>> {
        Ok(LocListIter::new(self.raw_locations(offset)?, base_address))
    }

    /// Iterate over the raw `LocationListEntry`s starting at the given offset.
    ///
    /// This iterator does not perform any processing of the location entries,
    /// such as handling base addresses.
    ///
    /// Can be [used with
    /// `FallibleIterator`](./index.html#using-with-fallibleiterator).
    pub fn raw_locations(
        &self,
        offset: DebugLocOffset<R::Offset>,
    ) -> Result<RawLocListIter<R>> {
        let mut input = self.debug_loclists_section.clone();
        let header = parse_header(&mut input)?;
        input = self.debug_loclists_section.clone();
        input.skip(offset.0)?;
        Ok(RawLocListIter::new(input, header.address_size))
    }
}

impl<R: Reader> Section<R> for DebugLocLists<R> {
    fn section_name() -> &'static str {
        ".debug_loclists"
    }
}

impl<R: Reader> From<R> for DebugLocLists<R> {
    fn from(debug_loclists_section: R) -> Self {
        DebugLocLists { debug_loclists_section }
    }
}

/// A raw iterator over a location list.
///
/// This iterator does not perform any processing of the location entries,
/// such as handling base addresses.
#[derive(Debug)]
pub struct RawLocListIter<R: Reader> {
    input: R,
    address_size: u8,
}

#[derive(Clone, Debug)]
pub enum RawLocListEntry<R: Reader> {
    BaseAddress {
        addr: u64,
    },
    BaseAddressx {
        addr: AddressIndex,
    },
    StartxEndx {
        begin: AddressIndex,
        end: AddressIndex,
        data: Expression<R>,
    },
    StartxLength {
        begin: AddressIndex,
        length: u64,
        data: Expression<R>,
    },
    OffsetPair {
        begin: u64,
        end: u64,
        data: Expression<R>,
    },
    DefaultLocation {
        data: Expression<R>,
    },
    StartEnd {
        begin: u64,
        end: u64,
        data: Expression<R>,
    },
    StartLength {
        begin: u64,
        length: u64,
        data: Expression<R>,
    }
}

fn parse_data<R: Reader>(input: &mut R) -> Result<Expression<R>> {
    let len = R::Offset::from_u64(input.read_uleb128()?)?;
    Ok(Expression(input.split(len)?))
}

impl<R: Reader> RawLocListEntry<R> {
    /// Parse a range entry from `.debug_rnglists`
    fn parse(input: &mut R, address_size: u8) -> Result<Option<Self>> {
        Ok(match constants::DwLle(input.read_u8()?) {
            constants::DW_LLE_end_of_list => {
                None
            },
            constants::DW_LLE_base_addressx => {
                Some(RawLocListEntry::BaseAddressx {
                    addr: AddressIndex(input.read_uleb128()?),
                })
            },
            constants::DW_LLE_startx_endx => {
                Some(RawLocListEntry::StartxEndx {
                    begin: AddressIndex(input.read_uleb128()?),
                    end: AddressIndex(input.read_uleb128()?),
                    data: parse_data(input)?,
                })
            },
            constants::DW_LLE_startx_length => {
                Some(RawLocListEntry::StartxLength {
                    begin: AddressIndex(input.read_uleb128()?),
                    length: input.read_uleb128()?,
                    data: parse_data(input)?,
                })
            },
            constants::DW_LLE_offset_pair => {
                Some(RawLocListEntry::OffsetPair {
                    begin: input.read_uleb128()?,
                    end: input.read_uleb128()?,
                    data: parse_data(input)?,
                })
            },
            constants::DW_LLE_default_location => {
                Some(RawLocListEntry::DefaultLocation {
                    data: parse_data(input)?,
                })
            },
            constants::DW_LLE_base_address => {
                Some(RawLocListEntry::BaseAddress {
                    addr: input.read_address(address_size)?,
                })
            },
            constants::DW_LLE_start_end => {
                Some(RawLocListEntry::StartEnd {
                    begin: input.read_address(address_size)?,
                    end: input.read_address(address_size)?,
                    data: parse_data(input)?,
                })
            },
            constants::DW_LLE_start_length => {
                Some(RawLocListEntry::StartLength {
                    begin: input.read_address(address_size)?,
                    length: input.read_uleb128()?,
                    data: parse_data(input)?,
                })
            },
            _ => {
                return Err(Error::InvalidAddressRange);
            }
        })
    }
}

impl<R: Reader> RawLocListIter<R> {
    /// Construct a `RawLocListIter`.
    pub fn new(input: R, address_size: u8) -> RawLocListIter<R> {
        RawLocListIter {
            input: input,
            address_size: address_size,
        }
    }

    /// Advance the iterator to the next location.
    pub fn next(&mut self) -> Result<Option<RawLocListEntry<R>>> {
        if self.input.is_empty() {
            return Ok(None);
        }

        match RawLocListEntry::parse(&mut self.input, self.address_size) {
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
        LocListIter {
            raw: raw,
            base_address: base_address,
        }
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
                },
                RawLocListEntry::DefaultLocation { data } => {
                    (Range { begin: 0, end: u64::max_value() }, data)
                }
                RawLocListEntry::OffsetPair { begin, end, data } => {
                    (Range { begin: self.base_address + begin, end: self.base_address + end }, data)
                },
                RawLocListEntry::StartEnd { begin, end, data } => {
                    (Range { begin: begin, end: end }, data)
                },
                RawLocListEntry::StartLength { begin, length, data } => {
                    (Range { begin: begin, end: begin + length }, data)
                },
                _ => {
                    // We don't support AddressIndex-based entries yet
                    return Err(Error::UnsupportedAddressIndex);
                }
            };

            if range.begin == range.end {
                // An empty location list entry, skip it.
                continue;
            }

            if range.begin > range.end {
                self.raw.input.empty();
                return Err(Error::InvalidLocationAddressRange);
            }

            return Ok(Some(LocationListEntry {
                range: range,
                data: data,
            }));
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

#[cfg(test)]
mod tests {
    extern crate test_assembler;

    use super::*;
    use endianity::{EndianBuf, LittleEndian};
    use ranges::Range;
    use self::test_assembler::{Endian, Label, LabelMaker, Section};
    use test_util::GimliSectionMethods;

    #[test]
    fn test_loclists_32() {
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
            .L8(4).uleb(0x10200).uleb(0x10300).uleb(4).L32(2)
            // A base address selection followed by an OffsetPair.
            .L8(6).L32(0x02000000)
            .L8(4).uleb(0x10400).uleb(0x10500).uleb(4).L32(3)
            // An empty OffsetPair followed by a normal OffsetPair.
            .L8(4).uleb(0x10600).uleb(0x10600).uleb(4).L32(4)
            .L8(4).uleb(0x10800).uleb(0x10900).uleb(4).L32(5)
            // A StartEnd
            .L8(7).L32(0x2010a00).L32(0x2010b00).uleb(4).L32(6)
            // A StartLength
            .L8(8).L32(0x2010c00).uleb(0x100).uleb(4).L32(7)
            // An OffsetPair that starts at 0.
            .L8(4).uleb(0).uleb(1).uleb(4).L32(8)
            // An OffsetPair that ends at -1.
            .L8(6).L32(0)
            .L8(4).uleb(0).uleb(0xffffffff).uleb(4).L32(9)
            // A DefaultLocation
            .L8(5).uleb(4).L32(10)
            // A range end.
            .L8(0)
            // Some extra data.
            .L32(0xffffffff);
        size.set_const((&section.here() - &start - 4) as u64);

        let buf = section.get_contents().unwrap();
        let debug_loclists = DebugLocLists::new(&buf, LittleEndian);
        let offset = DebugLocOffset((&first - &start) as usize);
        let mut locations = debug_loclists.locations(offset, 0x01000000).unwrap();

        // A normal location.
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0x01010200,
                    end: 0x01010300,
                },
                data: Expression(EndianBuf::new(&[2, 0, 0, 0], LittleEndian)),
            }))
        );

        // A base address selection followed by a normal location.
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0x02010400,
                    end: 0x02010500,
                },
                data: Expression(EndianBuf::new(&[3, 0, 0, 0], LittleEndian)),
            }))
        );

        // An empty location range followed by a normal location.
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0x02010800,
                    end: 0x02010900,
                },
                data: Expression(EndianBuf::new(&[5, 0, 0, 0], LittleEndian)),
            }))
        );

        // An empty location range followed by a normal location.
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0x02010a00,
                    end: 0x02010b00,
                },
                data: Expression(EndianBuf::new(&[6, 0, 0, 0], LittleEndian)),
            }))
        );

        // An empty location range followed by a normal location.
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0x02010c00,
                    end: 0x02010d00,
                },
                data: Expression(EndianBuf::new(&[7, 0, 0, 0], LittleEndian)),
            }))
        );

        // A location range that starts at 0.
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0x02000000,
                    end: 0x02000001,
                },
                data: Expression(EndianBuf::new(&[8, 0, 0, 0], LittleEndian)),
            }))
        );

        // A location range that ends at -1.
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0x00000000,
                    end: 0xffffffff,
                },
                data: Expression(EndianBuf::new(&[9, 0, 0, 0], LittleEndian)),
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
                data: Expression(EndianBuf::new(&[10, 0, 0, 0], LittleEndian)),
            }))
        );

        // A location list end.
        assert_eq!(locations.next(), Ok(None));

        // An offset at the end of buf.
        let mut locations = debug_loclists
            .locations(DebugLocOffset(buf.len()), 0x01000000)
            .unwrap();
        assert_eq!(locations.next(), Ok(None));
    }

    #[test]
    fn test_loclists_64() {
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
            .L8(4).uleb(0x10200).uleb(0x10300).uleb(4).L32(2)
            // A base address selection followed by an OffsetPair.
            .L8(6).L64(0x02000000)
            .L8(4).uleb(0x10400).uleb(0x10500).uleb(4).L32(3)
            // An empty OffsetPair followed by a normal OffsetPair.
            .L8(4).uleb(0x10600).uleb(0x10600).uleb(4).L32(4)
            .L8(4).uleb(0x10800).uleb(0x10900).uleb(4).L32(5)
            // A StartEnd
            .L8(7).L64(0x2010a00).L64(0x2010b00).uleb(4).L32(6)
            // A StartLength
            .L8(8).L64(0x2010c00).uleb(0x100).uleb(4).L32(7)
            // An OffsetPair that starts at 0.
            .L8(4).uleb(0).uleb(1).uleb(4).L32(8)
            // An OffsetPair that ends at -1.
            .L8(6).L64(0)
            .L8(4).uleb(0).uleb(0xffffffff).uleb(4).L32(9)
            // A DefaultLocation
            .L8(5).uleb(4).L32(10)
            // A range end.
            .L8(0)
            // Some extra data.
            .L32(0xffffffff);
        size.set_const((&section.here() - &start - 12) as u64);

        let buf = section.get_contents().unwrap();
        let debug_loclists = DebugLocLists::new(&buf, LittleEndian);
        let offset = DebugLocOffset((&first - &start) as usize);
        let mut locations = debug_loclists.locations(offset, 0x01000000).unwrap();

        // A normal location.
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0x01010200,
                    end: 0x01010300,
                },
                data: Expression(EndianBuf::new(&[2, 0, 0, 0], LittleEndian)),
            }))
        );

        // A base address selection followed by a normal location.
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0x02010400,
                    end: 0x02010500,
                },
                data: Expression(EndianBuf::new(&[3, 0, 0, 0], LittleEndian)),
            }))
        );

        // An empty location range followed by a normal location.
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0x02010800,
                    end: 0x02010900,
                },
                data: Expression(EndianBuf::new(&[5, 0, 0, 0], LittleEndian)),
            }))
        );

        // An empty location range followed by a normal location.
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0x02010a00,
                    end: 0x02010b00,
                },
                data: Expression(EndianBuf::new(&[6, 0, 0, 0], LittleEndian)),
            }))
        );

        // An empty location range followed by a normal location.
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0x02010c00,
                    end: 0x02010d00,
                },
                data: Expression(EndianBuf::new(&[7, 0, 0, 0], LittleEndian)),
            }))
        );

        // A location range that starts at 0.
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0x02000000,
                    end: 0x02000001,
                },
                data: Expression(EndianBuf::new(&[8, 0, 0, 0], LittleEndian)),
            }))
        );

        // A location range that ends at -1.
        assert_eq!(
            locations.next(),
            Ok(Some(LocationListEntry {
                range: Range {
                    begin: 0x00000000,
                    end: 0xffffffff,
                },
                data: Expression(EndianBuf::new(&[9, 0, 0, 0], LittleEndian)),
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
                data: Expression(EndianBuf::new(&[10, 0, 0, 0], LittleEndian)),
            }))
        );

        // A location list end.
        assert_eq!(locations.next(), Ok(None));

        // An offset at the end of buf.
        let mut locations = debug_loclists
            .locations(DebugLocOffset(buf.len()), 0x01000000)
            .unwrap();
        assert_eq!(locations.next(), Ok(None));
    }
}
