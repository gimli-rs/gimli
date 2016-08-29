#![deny(missing_docs)]

use endianity::{Endianity, EndianBuf};
use lookup::{LookupParser, LookupEntryIter, DebugLookup};
use parser::{parse_address_size, parse_debug_info_offset, parse_initial_length, parse_u16,
             parse_address, Error, Format, DebugInfoOffset, ParseResult};
use std::cmp::Ordering;
use std::marker::PhantomData;
use std::rc::Rc;

#[derive(Debug, PartialEq, Eq)]
pub struct ArangeHeader {
    format: Format,
    length: u64,
    version: u16,
    offset: DebugInfoOffset,
    address_size: u8,
    segment_size: u8,
}

/// A single parsed arange.
#[derive(Debug, Clone, Eq)]
pub struct ArangeEntry {
    segment: u64,
    address: u64,
    length: u64,
    header: Rc<ArangeHeader>,
}

impl ArangeEntry {
    /// Return the segment selector of this arange.
    pub fn segment(&self) -> Option<u64> {
        if self.header.segment_size != 0 {
            Some(self.segment)
        } else {
            None
        }
    }

    /// Return the beginning address of this arange.
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Return the length of this arange.
    pub fn length(&self) -> u64 {
        self.length
    }

    /// Return the offset into the .debug_info section for this arange.
    pub fn debug_info_offset(&self) -> DebugInfoOffset {
        self.header.offset
    }
}

impl PartialEq for ArangeEntry {
    fn eq(&self, other: &ArangeEntry) -> bool {
        // The expected comparison, but verify that header matches if everything else does.
        match (self.segment == other.segment,
               self.address == other.address,
               self.length == other.length) {
            (true, true, true) => {
                debug_assert!(self.header == other.header);
                true
            }
            _ => false,
        }
    }
}

impl PartialOrd for ArangeEntry {
    fn partial_cmp(&self, other: &ArangeEntry) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ArangeEntry {
    fn cmp(&self, other: &ArangeEntry) -> Ordering {
        // The expected comparison, but ignore header.
        match (self.segment.cmp(&other.segment),
               self.address.cmp(&other.address),
               self.length.cmp(&other.length)) {
            (Ordering::Equal, Ordering::Equal, Ordering::Equal) => Ordering::Equal,
            (Ordering::Less, _, _) |
            (Ordering::Equal, Ordering::Less, _) |
            (Ordering::Equal, Ordering::Equal, Ordering::Less) => Ordering::Less,
            (Ordering::Greater, _, _) |
            (Ordering::Equal, Ordering::Greater, _) |
            (Ordering::Equal, Ordering::Equal, Ordering::Greater) => Ordering::Greater,
        }
    }
}

pub struct ArangeParser<'input, Endian>
    where Endian: 'input + Endianity
{
    // This struct is never instantiated.
    phantom: PhantomData<&'input Endian>,
}

impl<'input, Endian> LookupParser<'input, Endian> for ArangeParser<'input, Endian>
    where Endian: 'input + Endianity
{
    type Header = ArangeHeader;
    type Entry = ArangeEntry;

    /// Parse an arange set header. Returns a tuple of the remaining arange sets, the aranges to be
    /// parsed for this set, and the newly created ArangeHeader struct.
    fn parse_header(input: EndianBuf<Endian>)
                    -> ParseResult<(EndianBuf<Endian>, EndianBuf<Endian>, Rc<Self::Header>)> {
        let (rest, (length, format)) = try!(parse_initial_length(input));
        if length as usize > rest.len() {
            return Err(Error::UnexpectedEof);
        }
        let after_set = rest.range_from(length as usize..);
        let rest = rest.range_to(..length as usize);

        let (rest, version) = try!(parse_u16(rest));
        if version != 2 {
            return Err(Error::UnknownVersion);
        }

        let (rest, offset) = try!(parse_debug_info_offset(rest, format));
        let (rest, address_size) = try!(parse_address_size(rest));
        let (rest, segment_size) = try!(parse_address_size(rest));

        // unit_length + version + offset + address_size + segment_size
        let header_length = match format {
            Format::Dwarf32 => 4 + 2 + 4 + 1 + 1,
            Format::Dwarf64 => 12 + 2 + 8 + 1 + 1,
        };

        // The first tuple following the header in each set begins at an offset that is
        // a multiple of the size of a single tuple (that is, the size of a segment selector
        // plus twice the size of an address).
        let tuple_length = (2 * address_size + segment_size) as usize;
        let padding = if header_length % tuple_length == 0 {
            0
        } else {
            tuple_length - header_length % tuple_length
        };
        if padding > rest.len() {
            return Err(Error::UnexpectedEof);
        }
        let rest = rest.range_from(padding..);

        Ok((after_set,
            rest,
            Rc::new(ArangeHeader {
            format: format,
            length: length,
            version: version,
            offset: offset,
            address_size: address_size,
            segment_size: segment_size,
        })))
    }

    /// Parse a single arange. Return `None` for the null arange, `Some` for an actual arange.
    fn parse_entry(input: EndianBuf<'input, Endian>,
                   header: &Rc<Self::Header>)
                   -> ParseResult<(EndianBuf<'input, Endian>, Option<Self::Entry>)> {
        let address_size = header.address_size;
        let segment_size = header.segment_size; // May be zero!

        let tuple_length = (2 * address_size + segment_size) as usize;
        if tuple_length > input.len() {
            return Ok((EndianBuf::new(&[]), None));
        }

        let (rest, segment) = if segment_size != 0 {
            try!(parse_address(input, segment_size))
        } else {
            (input, 0)
        };
        let (rest, address) = try!(parse_address(rest, address_size));
        let (rest, length) = try!(parse_address(rest, address_size));

        match (segment, address, length) {
            // There may be multiple sets of tuples, each terminated by a zero tuple.
            // It's not clear what purpose these zero tuples serve.  For now, we
            // simply skip them.
            (0, 0, 0) => Self::parse_entry(rest, header),
            _ => {
                Ok((rest,
                    Some(ArangeEntry {
                    segment: segment,
                    address: address,
                    length: length,
                    header: header.clone(),
                })))
            }
        }
    }
}

/// The `DebugAranges` struct represents the DWARF address range information
/// found in the `.debug_aranges` section.
///
/// Provides:
///
/// * `new(input: EndianBuf<'input, Endian>) -> DebugAranges<'input, Endian>`
///
///   Construct a new `DebugAranges` instance from the data in the `.debug_aranges`
///   section.
///
///   It is the caller's responsibility to read the `.debug_aranges` section and
///   present it as a `&[u8]` slice. That means using some ELF loader on
///   Linux, a Mach-O loader on OSX, etc.
///
///   ```
///   use gimli::{DebugAranges, LittleEndian};
///
///   # let buf = [];
///   # let read_debug_aranges_section = || &buf;
///   let debug_aranges = DebugAranges::<LittleEndian>::new(read_debug_aranges_section());
///   ```
///
/// * `items(&self) -> ArangeEntryIter<'input, Endian>`
///
///   Iterate the aranges in the `.debug_aranges` section.
///
///   ```
///   use gimli::{DebugAranges, LittleEndian};
///
///   # let buf = [];
///   # let read_debug_aranges_section = || &buf;
///   let debug_aranges = DebugAranges::<LittleEndian>::new(read_debug_aranges_section());
///
///   let mut iter = debug_aranges.items();
///   while let Some(arange) = iter.next().unwrap() {
///       println!("arange starts at {}, has length {}", arange.address(), arange.length());
///   }
///   ```
pub type DebugAranges<'input, Endian> = DebugLookup<'input, Endian, ArangeParser<'input, Endian>>;

/// An iterator over the aranges from a .debug_aranges section.
///
/// Provides:
///
/// * `next(self: &mut) -> ParseResult<Option<ArangeEntry>>`
///
///   Advance the iterator and return the next arange.
///
///   Returns the newly parsed arange as `Ok(Some(arange))`. Returns `Ok(None)`
///   when iteration is complete and all aranges have already been parsed and
///   yielded. If an error occurs while parsing the next arange, then this error
///   is returned on all subsequent calls as `Err(e)`.
///
///   Can be [used with
///   `FallibleIterator`](./index.html#using-with-fallibleiterator).
pub type ArangeEntryIter<'input, Endian> = LookupEntryIter<'input,
                                                           Endian,
                                                           ArangeParser<'input, Endian>>;

#[cfg(test)]
mod tests {
    use super::*;
    use lookup::LookupParser;
    use endianity::{EndianBuf, LittleEndian};
    use parser::{Format, DebugInfoOffset};
    use std::rc::Rc;

    #[test]
    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn test_parse_header_ok() {
        let buf = [
            // 32-bit length = 32.
            0x20, 0x00, 0x00, 0x00,
            // Version.
            0x02, 0x00,
            // Offset.
            0x01, 0x02, 0x03, 0x04,
            // Address size.
            0x08,
            // Segment size.
            0x04,
            // Length to here = 12, tuple length = 20.
            // Padding to tuple length multiple = 4.
            0x10, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,

            // Dummy arange tuple data.
            0x20, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,

            // Dummy next arange.
            0x30, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        let input = EndianBuf::<LittleEndian>::new(&buf);

        let (rest, tuples, header) = ArangeParser::parse_header(input)
            .expect("should parse header ok");

        assert_eq!(rest, EndianBuf::new(&buf[buf.len() - 16..]));
        assert_eq!(tuples, EndianBuf::new(&buf[buf.len() - 32..buf.len() - 16]));
        assert_eq!(*header,
                   ArangeHeader {
                       format: Format::Dwarf32,
                       length: 0x20,
                       version: 2,
                       offset: DebugInfoOffset(0x04030201),
                       address_size: 8,
                       segment_size: 4,
                   });
    }

    #[test]
    fn test_parse_entry_ok() {
        let header = Rc::new(ArangeHeader {
            format: Format::Dwarf32,
            length: 0,
            version: 2,
            offset: DebugInfoOffset(0),
            address_size: 4,
            segment_size: 0,
        });
        let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];
        let input = EndianBuf::<LittleEndian>::new(&buf);
        let (rest, entry) = ArangeParser::parse_entry(input, &header)
            .expect("should parse entry ok");
        assert_eq!(rest, EndianBuf::new(&buf[buf.len() - 1..]));
        assert_eq!(entry,
                   Some(ArangeEntry {
                       segment: 0,
                       address: 0x04030201,
                       length: 0x08070605,
                       header: header.clone(),
                   }));
    }

    #[test]
    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn test_parse_entry_segment() {
        let header = Rc::new(ArangeHeader {
            format: Format::Dwarf32,
            length: 0,
            version: 2,
            offset: DebugInfoOffset(0),
            address_size: 4,
            segment_size: 8,
        });
        let buf = [
            // Segment.
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            // Address.
            0x01, 0x02, 0x03, 0x04,
            // Length.
            0x05, 0x06, 0x07, 0x08,
            // Next tuple.
            0x09
        ];
        let input = EndianBuf::<LittleEndian>::new(&buf);
        let (rest, entry) = ArangeParser::parse_entry(input, &header)
            .expect("should parse entry ok");
        assert_eq!(rest, EndianBuf::new(&buf[buf.len() - 1..]));
        assert_eq!(entry,
                   Some(ArangeEntry {
                       segment: 0x1817161514131211,
                       address: 0x04030201,
                       length: 0x08070605,
                       header: header.clone(),
                   }));
    }

    #[test]
    #[cfg_attr(rustfmt, rustfmt_skip)]
    fn test_parse_entry_zero() {
        let header = Rc::new(ArangeHeader {
            format: Format::Dwarf32,
            length: 0,
            version: 2,
            offset: DebugInfoOffset(0),
            address_size: 4,
            segment_size: 0,
        });
        let buf = [
            // Zero tuple.
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // Address.
            0x01, 0x02, 0x03, 0x04,
            // Length.
            0x05, 0x06, 0x07, 0x08,
            // Next tuple.
            0x09
        ];
        let input = EndianBuf::<LittleEndian>::new(&buf);
        let (rest, entry) = ArangeParser::parse_entry(input, &header)
            .expect("should parse entry ok");
        assert_eq!(rest, EndianBuf::new(&buf[buf.len() - 1..]));
        assert_eq!(entry,
                   Some(ArangeEntry {
                       segment: 0,
                       address: 0x04030201,
                       length: 0x08070605,
                       header: header.clone(),
                   }));
    }
}
