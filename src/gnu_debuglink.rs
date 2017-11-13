use reader::{Reader, ReaderOffset};
use endianity::{EndianBuf, Endianity};
use parser::Result;
use Section;

/// The `GnuDebuglink` struct represents the external debuginfo information
/// found in the `.gnu_debuglink` section.
#[derive(Debug, Clone, Copy)]
pub struct GnuDebuglink<R: Reader> {
    gnu_debuglink_section: R,
}

impl<'input, Endian> GnuDebuglink<EndianBuf<'input, Endian>>
where
    Endian: Endianity
{
    /// Constructs a new `GnuDebuglink` instance from the data in the
    /// `.gnu_debuglink` section.
    ///
    /// It is the caller's responsibility to read the `.gnu_debuglink` section
    /// and present it as a `&[u8]` slice. This means using some ELF loader on
    /// Linux, a Mach-O loader on OSX, etc.
    ///
    /// ```
    /// use gimli::{GnuDebuglink, LittleEndian};
    ///
    /// # let buf = [0x00, 0x01, 0x02, 0x03];
    /// # let read_gnu_debuglink_section_somehow = || &buf;
    /// let gnu_debuglink = GnuDebuglink::new(read_gnu_debuglink_section_somehow(), LittleEndian);
    /// ```
    pub fn new(gnu_debuglink_section: &'input [u8], endian: Endian) -> Self {
        Self::from(EndianBuf::new(gnu_debuglink_section, endian))
    }
}

impl<R: Reader> GnuDebuglink<R> {
    /// Returns the filename of the debug information file.
    pub fn filename(&self) -> Result<R> {
        self.gnu_debuglink_section.clone().read_null_terminated_slice()
    }

    /// Returns the CRC32 checksum of the debug information file.
    pub fn crc32(&self) -> Result<u32> {
        let mut section = self.gnu_debuglink_section.clone();
        let base = section.len() - ReaderOffset::from_u32(4);
        section.skip(base)?;
        section.read_u32()
    }
}

impl<R: Reader> Section<R> for GnuDebuglink<R> {
    fn section_name() -> &'static str {
        ".gnu_debuglink"
    }
}

impl<R: Reader> From<R> for GnuDebuglink<R> {
    fn from(gnu_debuglink_section: R) -> Self {
        GnuDebuglink {
            gnu_debuglink_section,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use endianity::LittleEndian;

    #[test]
    fn reference() {
        let section = [
            0x6c, 0x69, 0x62, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x64, 0x65, 0x62,
            0x75, 0x67, 0x00, 0x00, 0x00, 0x52, 0xa7, 0xfd, 0x0a];
        let gnu_debuglink = GnuDebuglink::new(&section, LittleEndian);

        assert_eq!(gnu_debuglink.filename().unwrap().buf(), "libtest.debug".as_bytes());
        assert_eq!(gnu_debuglink.crc32().unwrap(), 0x0afda752);
    }
}
