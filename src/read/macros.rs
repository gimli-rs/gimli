use core::fmt::Debug;

use crate::common::{DebugMacinfoOffset, SectionId};
use crate::endianity::Endianity;
use crate::read::{EndianSlice, Reader, Section};
use crate::{constants, DwMacInfo, Error, Result};

/// The raw contents of the `.debug_macinfo` section.
#[derive(Debug, Default, Clone, Copy)]
pub struct DebugMacInfo<R> {
    pub(crate) section: R,
}

impl<'input, Endian> DebugMacInfo<EndianSlice<'input, Endian>>
where
    Endian: Endianity,
{
    /// Construct a new `DebugMacInfo` instance from the data in the `.debug_macinfo`
    /// section.
    ///
    /// It is the caller's responsibility to read the `.debug_macinfo` section and
    /// present it as a `&[u8]` slice. That means using some ELF loader on
    /// Linux, a Mach-O loader on macOS, etc.
    ///
    /// ```
    /// use gimli::{DebugMacInfo, LittleEndian};
    ///
    /// # let buf = [1, 0, 95, 95, 83, 84, 68, 67, 95, 95, 32, 49, 0];
    /// # let read_section_somehow = || &buf;
    /// let debug_str = DebugMacInfo::new(read_section_somehow(), LittleEndian);
    /// ```
    pub fn new(macinfo_section: &'input [u8], endian: Endian) -> Self {
        Self::from(EndianSlice::new(macinfo_section, endian))
    }
}

impl<R: Reader> DebugMacInfo<R> {
    /// Look up a macro reference the `.debug_macinfo` section by DebugMacinfoOffset.
    ///
    /// A macinfo offset points to a list of macro information entries in the `.debug_macinfo` section.
    /// To handle this, the function returns an iterator.
    ///
    /// ```
    /// use gimli::{DebugMacInfo, DebugMacinfoOffset, LittleEndian};
    ///
    /// # fn main() -> Result<(), gimli::Error> {
    /// # let buf = [1, 0, 95, 95, 83, 84, 68, 67, 95, 95, 32, 49, 0, 0];
    /// # let offset = DebugMacinfoOffset(0);
    /// # let read_section_somehow = || &buf;
    /// # let debug_macinfo_offset_somehow = || offset;
    /// let debug_macinfo = DebugMacInfo::new(read_section_somehow(), LittleEndian);
    /// let mut iter = debug_macinfo.get_macinfo(debug_macinfo_offset_somehow())?;
    /// while let Some(macinfo) = iter.next()? {
    ///     println!("Found macro info {:?}", macinfo);
    /// }
    /// # Ok(()) }
    /// ```
    pub fn get_macinfo(
        &self,
        offset: DebugMacinfoOffset<R::Offset>,
    ) -> Result<DebugMacInfoIterator<R>> {
        let mut input = self.section.clone();
        input.skip(offset.0)?;
        Ok(DebugMacInfoIterator { input })
    }
}

impl<T> DebugMacInfo<T> {
    /// Create a `DebugMacInfo` section that references the data in `self`.
    ///
    /// This is useful when `R` implements `Reader` but `T` does not.
    ///
    /// Used by `DwarfSections::borrow`.
    pub fn borrow<'a, F, R>(&'a self, mut borrow: F) -> DebugMacInfo<R>
    where
        F: FnMut(&'a T) -> R,
    {
        borrow(&self.section).into()
    }
}

impl<R> Section<R> for DebugMacInfo<R> {
    fn id() -> SectionId {
        SectionId::DebugMacinfo
    }

    fn reader(&self) -> &R {
        &self.section
    }
}

impl<R> From<R> for DebugMacInfo<R> {
    fn from(macinfo_section: R) -> Self {
        DebugMacInfo {
            section: macinfo_section,
        }
    }
}

/// an Entry in the `.debug_macinfo` section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DebugMacInfoItem<R> {
    /// A macro definition.
    Define {
        /// The line number where the macro is defined.
        line: u64,
        /// The text of the macro: The name of the macro followed immediately by any formal
        /// parameters including the surrounding parentheses, followed by the macro definition.
        text: R,
    },
    /// A macro undefinition.
    Undef {
        /// The line number where the macro is undefined.
        line: u64,
        /// The name of the macro without the definition.
        name: R,
    },
    /// The start of a file.
    StartFile {
        /// Line number of the source file on which the inclusion macro directive occurred.
        line: u64,
        /// An index into the line number table of the compilation unit.
        file: u64,
    },
    /// The end of the current included file.
    EndFile,
    /// A vendor-specific extension.
    VendorExt {
        /// A numeric constant, whose meaning is vendor specific.
        numeric: u64,
        /// A string whose meaning is vendor specific.
        string: R,
    },
}

/// Iterator over the entries in the `.debug_macinfo` section.
#[derive(Clone, Debug)]
pub struct DebugMacInfoIterator<R: Reader> {
    input: R,
}

impl<R: Reader> DebugMacInfoIterator<R> {
    /// Advance the iterator to the next entry in the `.debug_macinfo` section.
    pub fn next(&mut self) -> Result<Option<DebugMacInfoItem<R>>> {
        // Read the next entry from the input reader and return it as a DebugMacInfoItem.
        let macinfo_type = DwMacInfo(self.input.read_u8()?);
        match macinfo_type {
            constants::DW_MACINFO_null => {
                // found the end of the unit, return None to stop the iteration
                self.input.empty();
                Ok(None)
            }
            constants::DW_MACINFO_define => {
                let line = self.input.read_uleb128()?;
                let text = self.input.read_null_terminated_slice()?;
                Ok(Some(DebugMacInfoItem::Define { line, text }))
            }
            constants::DW_MACINFO_undef => {
                let line = self.input.read_uleb128()?;
                let name = self.input.read_null_terminated_slice()?;
                Ok(Some(DebugMacInfoItem::Undef { line, name }))
            }
            constants::DW_MACINFO_start_file => {
                // two operands: line number (LEB128) and an index into the line number table of the compilation unit (LEB128).
                let line = self.input.read_uleb128()?;
                let file = self.input.read_uleb128()?;
                Ok(Some(DebugMacInfoItem::StartFile { line, file }))
            }
            constants::DW_MACINFO_end_file => {
                // no operands
                Ok(Some(DebugMacInfoItem::EndFile))
            }
            constants::DW_MACINFO_vendor_ext => {
                // two operands: a constant (LEB128) and a null terminated string, whose meaning is vendor specific
                let numeric = self.input.read_uleb128()?;
                let string = self.input.read_null_terminated_slice()?;
                Ok(Some(DebugMacInfoItem::VendorExt { numeric, string }))
            }
            _ => {
                self.input.empty();
                Err(Error::InvalidMacinfoType(macinfo_type.0))
            }
        }
    }
}

#[cfg(feature = "fallible-iterator")]
impl<R: Reader> fallible_iterator::FallibleIterator for DebugMacInfoIterator<R> {
    type Item = DebugMacInfoItem<R>;
    type Error = Error;

    fn next(&mut self) -> ::core::result::Result<Option<Self::Item>, Error> {
        DebugMacInfoIterator::next(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test_util::GimliSectionMethods, LittleEndian};
    use test_assembler::{Endian, Label, LabelMaker, Section};

    #[test]
    fn test_get_macinfo() {
        let position = Label::new();

        // Create a test section with some macinfo entries
        let section = Section::with_endian(Endian::Little)
            .set_start_const(0)
            .mark(&position)
            .D8(crate::DW_MACINFO_define.0)
            .uleb(0) // line number: 0 - defined on the compiler command line
            .append_bytes(b"__STDC__ 1\0")
            .D8(crate::DW_MACINFO_define.0)
            .uleb(1) // line number: 1 - defined in the source file
            .append_bytes(b"__GNUC__ 1\0")
            .D8(crate::DW_MACINFO_undef.0)
            .uleb(2) // line number: 2 - undefined in the source file
            .append_bytes(b"__GNUC__\0")
            .D8(crate::DW_MACINFO_start_file.0)
            .uleb(3) // line number: 3 - start of file
            .uleb(4) // file number index: 4 - index into the line number table
            .D8(crate::DW_MACINFO_end_file.0) // end of file
            .D8(crate::DW_MACINFO_vendor_ext.0)
            .uleb(5) // numeric constant: 5 - vendor specific
            .append_bytes(b"foo\0")
            .D8(crate::DW_MACINFO_null.0); // end of unit

        // Create a DebugMacInfo instance from the section
        let section = section.get_contents().unwrap();
        let debug_macinfo = DebugMacInfo::from(EndianSlice::new(&section, LittleEndian));

        let offset = position.value().unwrap() as usize;

        let mut iter = debug_macinfo
            .get_macinfo(DebugMacinfoOffset(offset))
            .unwrap();

        // Test getting macinfo entries
        let entry = iter.next().unwrap().unwrap();
        assert!(
            matches!(entry, DebugMacInfoItem::Define { line: 0, text } if text.slice() == b"__STDC__ 1")
        );

        let entry = iter.next().unwrap().unwrap();
        assert!(
            matches!(entry, DebugMacInfoItem::Define { line: 1, text } if text.slice() == b"__GNUC__ 1")
        );

        let entry = iter.next().unwrap().unwrap();
        assert!(
            matches!(entry, DebugMacInfoItem::Undef { line: 2, name } if name.slice() == b"__GNUC__")
        );

        let entry = iter.next().unwrap().unwrap();
        assert!(matches!(
            entry,
            DebugMacInfoItem::StartFile { line: 3, file: 4 }
        ));

        let entry = iter.next().unwrap().unwrap();
        assert!(matches!(entry, DebugMacInfoItem::EndFile));

        let entry = iter.next().unwrap().unwrap();
        assert!(
            matches!(entry, DebugMacInfoItem::VendorExt { numeric: 5, string } if string.slice() == b"foo")
        );

        assert_eq!(iter.next(), Ok(None));
    }
}
