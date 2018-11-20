//! Low level functionality for writing DWARF debugging information.

use std::error;
use std::fmt;
use std::ops::DerefMut;
use std::result;

mod endian_vec;
pub use self::endian_vec::*;

mod writer;
pub use self::writer::*;

mod abbrev;
pub use self::abbrev::*;

mod str;
pub use self::str::*;

mod unit;
pub use self::unit::*;

/// An error that occurred when writing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The given offset is out of bounds.
    OffsetOutOfBounds,
    /// The given length is out of bounds.
    LengthOutOfBounds,
    /// The attribute value is an invalid for writing.
    InvalidAttributeValue,
    /// The value is too large for the encoding form.
    ValueTooLarge,
    /// Unsupported word size.
    UnsupportedWordSize(u8),
    /// Unsupported DWARF version.
    UnsupportedVersion(u16),
    /// The unit length is too large for the requested DWARF format.
    InitialLengthOverflow,
    /// The address is invalid.
    InvalidAddress,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> result::Result<(), fmt::Error> {
        match *self {
            Error::OffsetOutOfBounds => write!(f, "The given offset is out of bounds."),
            Error::LengthOutOfBounds => write!(f, "The given length is out of bounds."),
            Error::InvalidAttributeValue => {
                write!(f, "The attribute value is an invalid for writing.")
            }
            Error::ValueTooLarge => write!(f, "The value is too large for the encoding form."),
            Error::UnsupportedWordSize(size) => write!(f, "Unsupported word size: {}", size),
            Error::UnsupportedVersion(version) => {
                write!(f, "Unsupported DWARF version: {}", version)
            }
            Error::InitialLengthOverflow => write!(
                f,
                "The unit length is too large for the requested DWARF format."
            ),
            Error::InvalidAddress => write!(f, "The address is invalid."),
        }
    }
}

impl error::Error for Error {}

/// The result of a write.
pub type Result<T> = result::Result<T, Error>;

/// An identifier for a DWARF section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionId {
    /// The `.debug_abbrev` section.
    DebugAbbrev,
    /// The `.debug_info` section.
    DebugInfo,
    /// The `.debug_line` section.
    DebugLine,
    /// The `.debug_loc` section.
    DebugLoc,
    /// The `.debug_loclists` section.
    DebugLocLists,
    /// The `.debug_macinfo` section.
    DebugMacinfo,
    /// The `.debug_ranges` section.
    DebugRanges,
    /// The `.debug_rnglists` section.
    DebugRngLists,
    /// The `.debug_str` section.
    DebugStr,
}

impl SectionId {
    /// Returns the ELF section name for this kind.
    pub fn name(self) -> &'static str {
        match self {
            SectionId::DebugInfo => ".debug_info",
            SectionId::DebugStr => ".debug_str",
            SectionId::DebugAbbrev => ".debug_abbrev",
            SectionId::DebugRanges => ".debug_ranges",
            SectionId::DebugLine => ".debug_line",
            SectionId::DebugLoc => ".debug_loc",
            SectionId::DebugLocLists => ".debug_loclists",
            SectionId::DebugRngLists => ".debug_rnglists",
            SectionId::DebugMacinfo => ".debug_macinfo",
        }
    }
}

/// Functionality common to all writable DWARF sections.
pub trait Section<W: Writer>: From<W> + DerefMut<Target = W> {
    /// Returns the DWARF section kind for this type.
    fn id() -> SectionId;

    /// Returns the ELF section name for this type.
    fn name() -> &'static str {
        Self::id().name()
    }
}

/// An address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Address {
    /// An absolute address that does not require relocation.
    Absolute(u64),
    /// An address that is relative to a symbol which may be relocated.
    Relative {
        /// The symbol that the address is relative to.
        ///
        /// The meaning of this value is decided by the writer, but
        /// will typically be an index into a symbol table.
        symbol: usize,
        /// The offset of the address relative to the symbol.
        ///
        /// This will typically be used as the addend in a relocation.
        addend: i64,
    },
}

#[cfg(feature = "read")]
mod convert {
    use super::*;
    use read;

    /// An error that occurred when converting a read value into a write value.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ConvertError {
        /// An error occurred when reading.
        Read(read::Error),
        /// Writing of this attribute value is not implemented yet.
        UnsupportedAttributeValue,
        /// This attribute value is an invalid name/form combination.
        InvalidAttributeValue,
        /// A `.debug_info` reference does not refer to a valid entry.
        InvalidDebugInfoOffset,
        /// An address could not be converted.
        InvalidAddress,
    }

    impl fmt::Display for ConvertError {
        fn fmt(&self, f: &mut fmt::Formatter) -> result::Result<(), fmt::Error> {
            use self::ConvertError::*;
            match *self {
                Read(ref e) => e.fmt(f),
                UnsupportedAttributeValue => {
                    write!(f, "Writing of this attribute value is not implemented yet.")
                }
                InvalidAttributeValue => write!(
                    f,
                    "This attribute value is an invalid name/form combination."
                ),
                InvalidDebugInfoOffset => write!(
                    f,
                    "A `.debug_info` reference does not refer to a valid entry."
                ),
                InvalidAddress => write!(f, "An address could not be converted."),
            }
        }
    }

    impl error::Error for ConvertError {}

    impl From<read::Error> for ConvertError {
        fn from(e: read::Error) -> Self {
            ConvertError::Read(e)
        }
    }

    /// The result of a conversion.
    pub type ConvertResult<T> = result::Result<T, ConvertError>;
}
#[cfg(feature = "read")]
pub use self::convert::*;
