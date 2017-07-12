use endianity::{Endianity, EndianBuf};
use fallible_iterator::FallibleIterator;
use parser::{Error, Result};
use reader::Reader;
use ranges::Range;
use Section;

/// An offset into the `.debug_loc` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DebugLocOffset(pub usize);

/// The `DebugLoc` struct represents the DWARF strings
/// found in the `.debug_loc` section.
#[derive(Debug, Clone, Copy)]
pub struct DebugLoc<R: Reader> {
    debug_loc_section: R,
}

impl<'input, Endian> DebugLoc<EndianBuf<'input, Endian>>
    where Endian: Endianity
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
        Self::from(EndianBuf::new(debug_loc_section, endian))
    }
}

impl<R: Reader> DebugLoc<R> {
    /// Iterate over the `LocationListEntry`s starting at the given offset.
    ///
    /// The `address_size` must be match the compilation unit for this location list.
    /// The `base_address` should be obtained from the `DW_AT_low_pc` attribute in the
    /// `DW_TAG_compile_unit` entry for the compilation unit that contains this location
    /// list.
    ///
    /// Can be [used with
    /// `FallibleIterator`](./index.html#using-with-fallibleiterator).
    pub fn locations(&self,
                     offset: DebugLocOffset,
                     address_size: u8,
                     base_address: u64)
                     -> Result<LocationListIter<R>> {
        let mut input = self.debug_loc_section.clone();
        input.skip(offset.0)?;
        Ok(LocationListIter::new(input, address_size, base_address))
    }

    /// Iterate over the raw `LocationListEntry`s starting at the given offset.
    ///
    /// The `address_size` must be match the compilation unit for this location list.
    ///
    /// This iterator does not perform any processing of the location entries,
    /// such as handling base addresses.
    ///
    /// Can be [used with
    /// `FallibleIterator`](./index.html#using-with-fallibleiterator).
    pub fn raw_locations(&self,
                         offset: DebugLocOffset,
                         address_size: u8)
                         -> Result<RawLocationListIter<R>> {
        let mut input = self.debug_loc_section.clone();
        input.skip(offset.0)?;
        Ok(RawLocationListIter::new(input, address_size))
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

/// A raw iterator over a location list.
///
/// This iterator does not perform any processing of the location entries,
/// such as handling base addresses.
#[derive(Debug)]
pub struct RawLocationListIter<R: Reader> {
    input: R,
    address_size: u8,
}

impl<R: Reader> RawLocationListIter<R> {
    /// Construct a `RawLocationListIter`.
    pub fn new(input: R, address_size: u8) -> RawLocationListIter<R> {
        RawLocationListIter {
            input: input,
            address_size: address_size,
        }
    }

    /// Advance the iterator to the next location.
    pub fn next(&mut self) -> Result<Option<LocationListEntry<R>>> {
        if self.input.is_empty() {
            return Ok(None);
        }

        let location = LocationListEntry::parse(&mut self.input, self.address_size)?;
        if location.range.is_end() {
            self.input.empty();
        }

        Ok(Some(location))
    }
}

impl<R: Reader> FallibleIterator for RawLocationListIter<R> {
    type Item = LocationListEntry<R>;
    type Error = Error;

    fn next(&mut self) -> ::std::result::Result<Option<Self::Item>, Self::Error> {
        RawLocationListIter::next(self)
    }
}

/// An iterator over a location list.
///
/// This iterator internally handles processing of base address selection entries
/// and list end entries.  Thus, it only returns location entries that are valid
/// and already adjusted for the base address.
#[derive(Debug)]
pub struct LocationListIter<R: Reader> {
    raw: RawLocationListIter<R>,
    base_address: u64,
}

impl<R: Reader> LocationListIter<R> {
    /// Construct a `LocationListIter`.
    fn new(input: R, address_size: u8, base_address: u64) -> LocationListIter<R> {
        LocationListIter {
            raw: RawLocationListIter::new(input, address_size),
            base_address: base_address,
        }
    }

    /// Advance the iterator to the next location.
    pub fn next(&mut self) -> Result<Option<LocationListEntry<R>>> {
        loop {
            let mut location = match self.raw.next()? {
                Some(location) => location,
                None => return Ok(None),
            };

            if location.range.is_end() {
                return Ok(None);
            }

            if location.range.is_base_address(self.raw.address_size) {
                self.base_address = location.range.end;
                continue;
            }

            if location.range.begin == location.range.end {
                // An empty location list entry, skip it.
                continue;
            }

            location
                .range
                .add_base_address(self.base_address, self.raw.address_size);
            if location.range.begin > location.range.end {
                self.raw.input.empty();
                return Err(Error::InvalidLocationAddressRange);
            }

            return Ok(Some(location));
        }
    }
}

impl<R: Reader> FallibleIterator for LocationListIter<R> {
    type Item = LocationListEntry<R>;
    type Error = Error;

    fn next(&mut self) -> ::std::result::Result<Option<Self::Item>, Self::Error> {
        LocationListIter::next(self)
    }
}

/// A location list entry from the `.debug_loc` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LocationListEntry<R: Reader> {
    /// The address range that this location is valid for.
    pub range: Range,

    /// The data containing a single location description.
    pub data: R,
}

impl<R: Reader> LocationListEntry<R> {
    /// Parse a location list entry from `.debug_loc`.
    fn parse(input: &mut R, address_size: u8) -> Result<LocationListEntry<R>> {
        let range = Range::parse(input, address_size)?;
        if range.is_end() || range.is_base_address(address_size) {
            let mut data = input.clone();
            data.empty();
            let location = LocationListEntry {
                range: range,
                data: data,
            };
            Ok(location)
        } else {
            let len = input.read_u16()?;
            let data = input.split(len as usize)?;
            let location = LocationListEntry {
                range: range,
                data: data,
            };
            Ok(location)
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate test_assembler;

    use super::*;
    use endianity::{EndianBuf, LittleEndian};
    use parser::Error;
    use ranges::Range;
    use self::test_assembler::{Endian, Label, LabelMaker, Section};

    #[test]
    fn test_location_list_32() {
        let start = Label::new();
        let first = Label::new();
        let section = Section::with_endian(Endian::Little)
            // A location before the offset.
            .mark(&start)
            .L32(0x10000).L32(0x10100).L16(4).L32(1)
            .mark(&first)
            // A normal location.
            .L32(0x10200).L32(0x10300).L16(4).L32(2)
            // A base address selection followed by a normal location.
            .L32(0xffffffff).L32(0x02000000)
            .L32(0x10400).L32(0x10500).L16(4).L32(3)
            // An empty location range followed by a normal location.
            .L32(0x10600).L32(0x10600).L16(4).L32(4)
            .L32(0x10800).L32(0x10900).L16(4).L32(5)
            // A location range that starts at 0.
            .L32(0).L32(1).L16(4).L32(6)
            // A location range that ends at -1.
            .L32(0xffffffff).L32(0x00000000)
            .L32(0).L32(0xffffffff).L16(4).L32(7)
            // A location list end.
            .L32(0).L32(0)
            // Some extra data.
            .L32(0);

        let buf = section.get_contents().unwrap();
        let debug_loc = DebugLoc::new(&buf, LittleEndian);
        let offset = DebugLocOffset((&first - &start) as usize);
        let mut locations = debug_loc.locations(offset, 4, 0x01000000).unwrap();

        // A normal location.
        assert_eq!(locations.next(),
                   Ok(Some(LocationListEntry {
                               range: Range {
                                   begin: 0x01010200,
                                   end: 0x01010300,
                               },
                               data: EndianBuf::new(&[2, 0, 0, 0], LittleEndian),
                           })));

        // A base address selection followed by a normal location.
        assert_eq!(locations.next(),
                   Ok(Some(LocationListEntry {
                               range: Range {
                                   begin: 0x02010400,
                                   end: 0x02010500,
                               },
                               data: EndianBuf::new(&[3, 0, 0, 0], LittleEndian),
                           })));

        // An empty location range followed by a normal location.
        assert_eq!(locations.next(),
                   Ok(Some(LocationListEntry {
                               range: Range {
                                   begin: 0x02010800,
                                   end: 0x02010900,
                               },
                               data: EndianBuf::new(&[5, 0, 0, 0], LittleEndian),
                           })));

        // A location range that starts at 0.
        assert_eq!(locations.next(),
                   Ok(Some(LocationListEntry {
                               range: Range {
                                   begin: 0x02000000,
                                   end: 0x02000001,
                               },
                               data: EndianBuf::new(&[6, 0, 0, 0], LittleEndian),
                           })));

        // A location range that ends at -1.
        assert_eq!(locations.next(),
                   Ok(Some(LocationListEntry {
                               range: Range {
                                   begin: 0x00000000,
                                   end: 0xffffffff,
                               },
                               data: EndianBuf::new(&[7, 0, 0, 0], LittleEndian),
                           })));

        // A location list end.
        assert_eq!(locations.next(), Ok(None));

        // An offset at the end of buf.
        let mut locations = debug_loc
            .locations(DebugLocOffset(buf.len()), 4, 0x01000000)
            .unwrap();
        assert_eq!(locations.next(), Ok(None));
    }

    #[test]
    fn test_location_list_64() {
        let start = Label::new();
        let first = Label::new();
        let section = Section::with_endian(Endian::Little)
            // A location before the offset.
            .mark(&start)
            .L64(0x10000).L64(0x10100).L16(4).L32(1)
            .mark(&first)
            // A normal location.
            .L64(0x10200).L64(0x10300).L16(4).L32(2)
            // A base address selection followed by a normal location.
            .L64(0xffffffffffffffff).L64(0x02000000)
            .L64(0x10400).L64(0x10500).L16(4).L32(3)
            // An empty location range followed by a normal location.
            .L64(0x10600).L64(0x10600).L16(4).L32(4)
            .L64(0x10800).L64(0x10900).L16(4).L32(5)
            // A location range that starts at 0.
            .L64(0).L64(1).L16(4).L32(6)
            // A location range that ends at -1.
            .L64(0xffffffffffffffff).L64(0x00000000)
            .L64(0).L64(0xffffffffffffffff).L16(4).L32(7)
            // A location list end.
            .L64(0).L64(0)
            // Some extra data.
            .L64(0);

        let buf = section.get_contents().unwrap();
        let debug_loc = DebugLoc::new(&buf, LittleEndian);
        let offset = DebugLocOffset((&first - &start) as usize);
        let mut locations = debug_loc.locations(offset, 8, 0x01000000).unwrap();

        // A normal location.
        assert_eq!(locations.next(),
                   Ok(Some(LocationListEntry {
                               range: Range {
                                   begin: 0x01010200,
                                   end: 0x01010300,
                               },
                               data: EndianBuf::new(&[2, 0, 0, 0], LittleEndian),
                           })));

        // A base address selection followed by a normal location.
        assert_eq!(locations.next(),
                   Ok(Some(LocationListEntry {
                               range: Range {
                                   begin: 0x02010400,
                                   end: 0x02010500,
                               },
                               data: EndianBuf::new(&[3, 0, 0, 0], LittleEndian),
                           })));

        // An empty location range followed by a normal location.
        assert_eq!(locations.next(),
                   Ok(Some(LocationListEntry {
                               range: Range {
                                   begin: 0x02010800,
                                   end: 0x02010900,
                               },
                               data: EndianBuf::new(&[5, 0, 0, 0], LittleEndian),
                           })));

        // A location range that starts at 0.
        assert_eq!(locations.next(),
                   Ok(Some(LocationListEntry {
                               range: Range {
                                   begin: 0x02000000,
                                   end: 0x02000001,
                               },
                               data: EndianBuf::new(&[6, 0, 0, 0], LittleEndian),
                           })));

        // A location range that ends at -1.
        assert_eq!(locations.next(),
                   Ok(Some(LocationListEntry {
                               range: Range {
                                   begin: 0x0,
                                   end: 0xffffffffffffffff,
                               },
                               data: EndianBuf::new(&[7, 0, 0, 0], LittleEndian),
                           })));

        // A location list end.
        assert_eq!(locations.next(), Ok(None));

        // An offset at the end of buf.
        let mut locations = debug_loc
            .locations(DebugLocOffset(buf.len()), 8, 0x01000000)
            .unwrap();
        assert_eq!(locations.next(), Ok(None));
    }

    #[test]
    fn test_ranges_invalid() {
        let section = Section::with_endian(Endian::Little)
            // An invalid location range.
            .L32(0x20000).L32(0x10000).L16(4).L32(1)
            // An invalid range after wrapping.
            .L32(0x20000).L32(0xff010000).L16(4).L32(2);

        let buf = section.get_contents().unwrap();
        let debug_loc = DebugLoc::new(&buf, LittleEndian);

        // An invalid location range.
        let mut locations = debug_loc
            .locations(DebugLocOffset(0x0), 4, 0x01000000)
            .unwrap();
        assert_eq!(locations.next(), Err(Error::InvalidLocationAddressRange));

        // An invalid location range after wrapping.
        let mut locations = debug_loc
            .locations(DebugLocOffset(0x8), 4, 0x01000000)
            .unwrap();
        assert_eq!(locations.next(), Err(Error::InvalidLocationAddressRange));

        // An invalid offset.
        match debug_loc.locations(DebugLocOffset(buf.len() + 1), 4, 0x01000000) {
            Err(Error::UnexpectedEof) => {}
            otherwise => panic!("Unexpected result: {:?}", otherwise),
        }
    }
}
