use endianity::{Endianity, EndianBuf};
use parser::{Format, ParseResult, parse_word};
use std::marker::PhantomData;

/// The `SectionData` struct represents the data in a DWARF section.
#[derive(Debug, Clone, Copy)]
pub struct SectionData<'input, Endian, Section>
    where Endian: Endianity
{
    data: EndianBuf<'input, Endian>,
    section: PhantomData<Section>,
}

impl<'input, Endian, Section> SectionData<'input, Endian, Section>
    where Endian: Endianity
{
    /// Construct a new `SectionData` instance from the data in the section.
    ///
    /// It is the caller's responsibility to read the section and
    /// present it as a `&[u8]` slice. That means using some ELF loader on
    /// Linux, a Mach-O loader on OSX, etc.
    pub fn new(data: &'input [u8]) -> SectionData<'input, Endian, Section> {
        SectionData {
            data: EndianBuf(data, PhantomData),
            section: PhantomData,
        }
    }

    /// Return the data in this section.
    pub fn data(&self) -> EndianBuf<'input, Endian> {
        self.data
    }
}

/// An offset into a DWARF section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionOffset<Section>(pub u64, PhantomData<Section>);

impl<Section> SectionOffset<Section> {
    /// Construct a new `SectionOffset` instance.
    pub fn new(offset: u64) -> Self {
        SectionOffset::<Section>(offset, PhantomData)
    }

    /// Parse an offset according to the DWARF format.
    pub fn parse<Endian>(input: EndianBuf<Endian>,
                         format: Format)
                         -> ParseResult<(EndianBuf<Endian>, Self)>
        where Endian: Endianity
    {
        parse_word(input, format).map(|(rest, offset)| (rest, Self::new(offset)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use endianity::{EndianBuf, LittleEndian};
    use parser::{Error, Format};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum TestSection {}

    type TestOffset = SectionOffset<TestSection>;

    #[test]
    fn test_parse_offset_32() {
        let buf = [0x01, 0x02, 0x03, 0x04];

        match TestOffset::parse(EndianBuf::<LittleEndian>::new(&buf), Format::Dwarf32) {
            Ok((_, val)) => assert_eq!(val, TestOffset::new(0x04030201)),
            otherwise => panic!("Unexpected result: {:?}", otherwise),
        };
    }

    #[test]
    fn test_parse_offset_32_incomplete() {
        let buf = [0x01, 0x02];

        match TestOffset::parse(EndianBuf::<LittleEndian>::new(&buf), Format::Dwarf32) {
            Err(Error::UnexpectedEof) => assert!(true),
            otherwise => panic!("Unexpected result: {:?}", otherwise),
        };
    }

    #[test]
    fn test_parse_offset_64() {
        let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        match TestOffset::parse(EndianBuf::<LittleEndian>::new(&buf), Format::Dwarf64) {
            Ok((_, val)) => assert_eq!(val, TestOffset::new(0x0807060504030201)),
            otherwise => panic!("Unexpected result: {:?}", otherwise),
        };
    }

    #[test]
    fn test_parse_offset_64_incomplete() {
        let buf = [0x01, 0x02];

        match TestOffset::parse(EndianBuf::<LittleEndian>::new(&buf), Format::Dwarf64) {
            Err(Error::UnexpectedEof) => assert!(true),
            otherwise => panic!("Unexpected result: {:?}", otherwise),
        };
    }
}
