//! Low level functionality for writing DWARF debugging information.

use std::error;
use std::fmt;
use std::ops::DerefMut;
use std::result;

mod endian_vec;
pub use self::endian_vec::*;

mod writer;
pub use self::writer::*;

macro_rules! define_section {
    ($name:ident, $offset:ident, $docs:expr) => {
        #[doc=$docs]
        #[derive(Debug)]
        pub struct $name<W: Writer>(pub W);

        impl<W: Writer> $name<W> {
            /// Return the offset of the next write.
            pub fn offset(&self) -> $offset {
                $offset(self.len())
            }
        }

        impl<W: Writer> From<W> for $name<W> {
            #[inline]
            fn from(w: W) -> Self {
                $name(w)
            }
        }

        impl<W: Writer> Deref for $name<W> {
            type Target = W;

            #[inline]
            fn deref(&self) -> &W {
                &self.0
            }
        }

        impl<W: Writer> DerefMut for $name<W> {
            #[inline]
            fn deref_mut(&mut self) -> &mut W {
                &mut self.0
            }
        }

        impl<W: Writer> Section<W> for $name<W> {
            #[inline]
            fn id() -> SectionId {
                SectionId::$name
            }
        }
    };
}

macro_rules! define_id {
    ($name:ident, $docs:expr) => {
        #[doc=$docs]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name {
            base_id: BaseId,
            index: usize,
        }

        impl $name {
            #[inline]
            fn new(base_id: BaseId, index: usize) -> Self {
                $name { base_id, index }
            }
        }
    };
}

macro_rules! define_offsets {
    ($offsets:ident: $id:ident => $offset:ident, $off_doc:expr) => {
        #[doc=$off_doc]
        #[derive(Debug)]
        pub struct $offsets {
            base_id: BaseId,
            // We know ids start at 0.
            offsets: Vec<$offset>,
        }

        impl $offsets {
            /// Return an empty list of offsets.
            #[inline]
            pub fn none() -> Self {
                $offsets {
                    base_id: BaseId::default(),
                    offsets: Vec::new(),
                }
            }

            /// Get the offset
            ///
            /// # Panics
            ///
            /// Panics if `id` is invalid.
            #[inline]
            pub fn get(&self, id: $id) -> $offset {
                debug_assert_eq!(self.base_id, id.base_id);
                self.offsets[id.index]
            }

            /// Return the number of offsets.
            #[inline]
            pub fn count(&self) -> usize {
                self.offsets.len()
            }
        }
    };
}

mod abbrev;
pub use self::abbrev::*;

mod line;
pub use self::line::*;

mod str;
pub use self::str::*;

mod unit;
pub use self::unit::*;

mod range;
pub use self::range::*;

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
    /// A requested feature requires a different DWARF version.
    NeedVersion(u16),
    /// Strings in line number program have mismatched forms.
    LineStringFormMismatch,
    /// The range is empty or otherwise invalid.
    InvalidRange,
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
            Error::NeedVersion(version) => write!(
                f,
                "A requested feature requires a DWARF version {}.",
                version
            ),
            Error::LineStringFormMismatch => {
                write!(f, "Strings in line number program have mismatched forms.")
            }
            Error::InvalidRange => write!(f, "The range is empty or otherwise invalid."),
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
    /// The `.debug_line_str` section.
    DebugLineStr,
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
            SectionId::DebugLineStr => ".debug_line_str",
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

// This type is only used in debug assertions.
#[cfg(not(debug_assertions))]
type BaseId = ();

#[cfg(debug_assertions)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct BaseId(usize);

#[cfg(debug_assertions)]
impl Default for BaseId {
    fn default() -> Self {
        use std::sync::atomic;
        static BASE_ID: atomic::AtomicUsize = atomic::ATOMIC_USIZE_INIT;
        BaseId(BASE_ID.fetch_add(1, atomic::Ordering::Relaxed))
    }
}

#[cfg(feature = "read")]
mod convert {
    use super::*;
    use read;

    pub(crate) use super::unit::convert::*;

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
        /// The line number program is missing the compilation directory.
        MissingCompilationDirectory,
        /// The line number program is missing the compilation file.
        MissingCompilationFile,
        /// Writing this line number instruction is not implemented yet.
        UnsupportedLineInstruction,
        /// Writing this form of line string is not implemented yet.
        UnsupportedLineStringForm,
        /// A `.debug_line` file index is invalid.
        InvalidFileIndex,
        /// A `.debug_line` directory index is invalid.
        InvalidDirectoryIndex,
        /// A `.debug_line` line base is invalid.
        InvalidLineBase,
        /// A `.debug_line` reference is invalid.
        InvalidLineRef,
        /// Invalid relative address in a range list.
        InvalidRangeRelativeAddress,
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
                MissingCompilationDirectory => write!(
                    f,
                    "The line number program is missing the compilation directory."
                ),
                MissingCompilationFile => write!(
                    f,
                    "The line number program is missing the compilation file."
                ),
                UnsupportedLineInstruction => write!(
                    f,
                    "Writing this line number instruction is not implemented yet."
                ),
                UnsupportedLineStringForm => write!(
                    f,
                    "Writing this form of line string is not implemented yet."
                ),
                InvalidFileIndex => write!(f, "A `.debug_line` file index is invalid."),
                InvalidDirectoryIndex => write!(f, "A `.debug_line` directory index is invalid."),
                InvalidLineBase => write!(f, "A `.debug_line` line base is invalid."),
                InvalidLineRef => write!(f, "A `.debug_line` reference is invalid."),
                InvalidRangeRelativeAddress => {
                    write!(f, "Invalid relative address in a range list.")
                }
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
