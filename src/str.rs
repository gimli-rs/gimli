use endianity::{Endianity, EndianBuf};
use parser::Result;
use reader::Reader;
use Section;

/// An offset into the `.debug_str` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugStrOffset(pub usize);

/// The `DebugStr` struct represents the DWARF strings
/// found in the `.debug_str` section.
#[derive(Debug, Clone, Copy)]
pub struct DebugStr<R: Reader> {
    debug_str_section: R,
}

impl<'input, Endian> DebugStr<EndianBuf<'input, Endian>>
    where Endian: Endianity
{
    /// Construct a new `DebugStr` instance from the data in the `.debug_str`
    /// section.
    ///
    /// It is the caller's responsibility to read the `.debug_str` section and
    /// present it as a `&[u8]` slice. That means using some ELF loader on
    /// Linux, a Mach-O loader on OSX, etc.
    ///
    /// ```
    /// use gimli::{DebugStr, LittleEndian};
    ///
    /// # let buf = [0x00, 0x01, 0x02, 0x03];
    /// # let read_debug_str_section_somehow = || &buf;
    /// let debug_str = DebugStr::new(read_debug_str_section_somehow(), LittleEndian);
    /// ```
    pub fn new(debug_str_section: &'input [u8], endian: Endian) -> Self {
        Self::from(EndianBuf::new(debug_str_section, endian))
    }
}

impl<R: Reader> DebugStr<R> {
    /// Lookup a string from the `.debug_str` section by DebugStrOffset.
    ///
    /// ```
    /// use gimli::{DebugStr, DebugStrOffset, LittleEndian};
    ///
    /// # let buf = [0x01, 0x02, 0x00];
    /// # let offset = DebugStrOffset(0);
    /// # let read_debug_str_section_somehow = || &buf;
    /// # let debug_str_offset_somehow = || offset;
    /// let debug_str = DebugStr::new(read_debug_str_section_somehow(), LittleEndian);
    /// println!("Found string {:?}", debug_str.get_str(debug_str_offset_somehow()));
    /// ```
    pub fn get_str(&self, offset: DebugStrOffset) -> Result<R> {
        let input = &mut self.debug_str_section.clone();
        input.skip(offset.0)?;
        input.read_null_terminated_slice()
    }
}

impl<R: Reader> Section<R> for DebugStr<R> {
    fn section_name() -> &'static str {
        ".debug_str"
    }
}

impl<R: Reader> From<R> for DebugStr<R> {
    fn from(debug_str_section: R) -> Self {
        DebugStr { debug_str_section }
    }
}
