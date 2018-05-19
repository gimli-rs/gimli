//! `gimli` is a blazing fast library for consuming the
//! [DWARF debugging format](http://dwarfstd.org/).
//!
//! * [Example Usage](#example-usage)
//! * [API Structure](#api-structure)
//! * [Using with `FallibleIterator`](#using-with-fallibleiterator)
//! * [Cargo Features](#cargo-features)
//!
//! ## Example Usage
//!
//! Print out all of the functions in the debuggee program:
//!
//! ```rust,no_run
//! extern crate gimli;
//!
//! # fn example() -> Result<(), gimli::Error> {
//! # let debug_info_buf = [];
//! # let debug_abbrev_buf = [];
//! # let read_debug_info = || &debug_info_buf;
//! # let read_debug_abbrev = || &debug_abbrev_buf;
//! // Read the .debug_info and .debug_abbrev sections with whatever object
//! // loader you're using.
//! let endian = gimli::LittleEndian;
//! let debug_info = gimli::DebugInfo::new(read_debug_info(), endian);
//! let debug_abbrev = gimli::DebugAbbrev::new(read_debug_abbrev(), endian);
//!
//! // Iterate over all compilation units.
//! let mut iter = debug_info.units();
//! while let Some(unit) = try!(iter.next()) {
//!     // Parse the abbreviations for this compilation unit.
//!     let abbrevs = try!(unit.abbreviations(&debug_abbrev));
//!
//!     // Iterate over all of this compilation unit's entries.
//!     let mut entries = unit.entries(&abbrevs);
//!     while let Some((_, entry)) = try!(entries.next_dfs()) {
//!         // If we find an entry for a function, print it.
//!         if entry.tag() == gimli::DW_TAG_subprogram {
//!             println!("Found a function: {:?}", entry);
//!         }
//!     }
//! }
//! # unreachable!()
//! # }
//! ```
//!
//! Full example programs:
//!
//!   * [A `dwarfdump` clone](./examples/dwarfdump.rs)
//!
//!   * [An `addr2line` clone](https://github.com/gimli-rs/addr2line)
//!
//!   * [`ddbug`](https://github.com/philipc/ddbug), a utility giving insight into
//!     code generation by making debugging information readable
//!
//!   * [`dwprod`](https://github.com/fitzgen/dwprod), a tiny utility to list the
//!     compilers used to create each compilation unit within a shared library or
//!     executable (via `DW_AT_producer`)
//!
//! ## API Structure
//!
//! * Basic familiarity with DWARF is assumed.
//!
//! * Each section gets its own type. Consider these types the entry points to
//! the library:
//!
//!   * [`DebugAbbrev`](./struct.DebugAbbrev.html): The `.debug_abbrev` section.
//!
//!   * [`DebugAranges`](./struct.DebugAranges.html): The `.debug_aranges`
//!   section.
//!
//!   * [`DebugFrame`](./struct.DebugFrame.html): The `.debug_frame` section.
//!
//!   * [`DebugInfo`](./struct.DebugInfo.html): The `.debug_info` section.
//!
//!   * [`DebugLine`](./struct.DebugLine.html): The `.debug_line` section.
//!
//!   * [`DebugLoc`](./struct.DebugLoc.html): The `.debug_loc` section.
//!
//!   * [`DebugPubNames`](./struct.DebugPubNames.html): The `.debug_pubnames`
//!   section.
//!
//!   * [`DebugPubTypes`](./struct.DebugPubTypes.html): The `.debug_pubtypes`
//!   section.
//!
//!   * [`DebugRanges`](./struct.DebugRanges.html): The `.debug_ranges` section.
//!
//!   * [`DebugStr`](./struct.DebugStr.html): The `.debug_str` section.
//!
//!   * [`DebugTypes`](./struct.DebugTypes.html): The `.debug_types` section.
//!
//!   * [`EhFrame`](./struct.EhFrame.html): The `.eh_frame` section.
//!
//!   * [`EhFrameHdr`](./struct.EhFrameHdr.html): The `.eh_frame_hdr` section.
//!
//! * Each section type exposes methods for accessing the debugging data encoded
//! in that section. For example, the [`DebugInfo`](./struct.DebugInfo.html)
//! struct has the [`units`](./struct.DebugInfo.html#method.units) method for
//! iterating over the compilation units defined within it.
//!
//! * Offsets into a section are strongly typed: an offset into `.debug_info` is
//! the [`DebugInfoOffset`](./struct.DebugInfoOffset.html) type. It cannot be
//! used to index into the [`DebugLine`](./struct.DebugLine.html) type because
//! `DebugLine` represents the `.debug_line` section. There are similar types
//! for offsets relative to a compilation unit rather than a section.
//!
//! ## Using with `FallibleIterator`
//!
//! The standard library's `Iterator` trait and related APIs do not play well
//! with iterators where the `next` operation is fallible. One can make the
//! `Iterator`'s associated `Item` type be a `Result<T, E>`, however the
//! provided methods cannot gracefully handle the case when an `Err` is
//! returned.
//!
//! This situation led to the
//! [`fallible-iterator`](https://crates.io/crates/fallible-iterator) crate's
//! existence. You can read more of the rationale for its existence in its
//! docs. The crate provides the helpers you have come to expect (eg `map`,
//! `filter`, etc) for iterators that can fail.
//!
//! `gimli`'s many lazy parsing iterators are a perfect match for the
//! `fallible-iterator` crate's `FallibleIterator` trait because parsing is not
//! done eagerly. Parse errors later in the input might only be discovered after
//! having iterated through many items.
//!
//! To use `gimli` iterators with `FallibleIterator`, import the crate and trait
//! into your code:
//!
//! ```
//! // Add the `fallible-iterator` crate. Don't forget to add it to your
//! // `Cargo.toml`, too!
//! extern crate fallible_iterator;
//! extern crate gimli;
//!
//! // Use the `FallibleIterator` trait so its methods are in scope!
//! use fallible_iterator::FallibleIterator;
//! use gimli::{DebugAranges, EndianBuf, LittleEndian};
//!
//! fn find_sum_of_address_range_lengths(aranges: DebugAranges<EndianBuf<LittleEndian>>)
//!     -> gimli::Result<u64>
//! {
//!     // `DebugAranges::items` returns a `FallibleIterator`!
//!     aranges.items()
//!         // `map` is provided by `FallibleIterator`!
//!         .map(|arange| arange.length())
//!         // `fold` is provided by `FallibleIterator`!
//!         .fold(0, |sum, len| sum + len)
//! }
//!
//! # fn main() {}
//! ```
//!
//! ## Cargo Features
//!
//! Cargo features that can be enabled with `gimli`:
//!
//! * `std`: Enabled by default. Use the `std` library. Disabling this feature
//! allows using `gimli` in embedded environments that do not have access to
//! `std`. Note that even when `std` is disabled, `gimli` still requires an
//! implementation of the `alloc` crate, and you must enable the `nightly`
//! feature.
//!
//! * `alloc`: Nightly only. Enables usage of the unstable, nightly-only
//! `#![feature(alloc)]` Rust feature that allows `gimli` to use boxes and
//! collection types in a `#[no_std]` environment.
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]
// Allow clippy warnings when we aren't building with clippy.
#![allow(unknown_lints)]
// False positives with `fallible_iterator`.
#![allow(should_implement_trait)]
// Many false positives involving `continue`.
#![allow(never_loop)]
// False positives when block expressions are used inside an assertion.
#![allow(panic_params)]
#![no_std]
#![cfg_attr(feature = "alloc", feature(alloc))]

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;
#[cfg(not(feature = "std"))]
#[macro_use]
extern crate core as std;

extern crate arrayvec;
extern crate byteorder;
extern crate fallible_iterator;

#[cfg(feature = "std")]
mod imports {
    pub use std::borrow;
    pub use std::boxed;
    pub use std::collections::btree_map;
    pub use std::rc;
    pub use std::string;
    pub use std::sync::Arc;
    pub use std::vec;
}

#[cfg(not(feature = "std"))]
mod imports {
    pub use alloc::arc::Arc;
    pub use alloc::borrow;
    pub use alloc::boxed;
    pub use alloc::btree_map;
    pub use alloc::rc;
    pub use alloc::string;
    pub use alloc::vec;
}

use imports::*;

mod cfi;
pub use cfi::*;

mod constants;
pub use constants::*;

mod endianity;
pub use endianity::{BigEndian, Endianity, LittleEndian, NativeEndian, RunTimeEndian};

mod endian_slice;
pub use endian_slice::EndianSlice;

mod endian_reader;
pub use endian_reader::{EndianArcSlice, EndianRcSlice, EndianReader};

/// `EndianBuf` has been renamed to `EndianSlice`. For ease of upgrading across
/// `gimli` versions, we export this type alias.
#[deprecated(note = "EndianBuf has been renamed to EndianSlice, use that instead.")]
pub type EndianBuf<'input, Endian> = EndianSlice<'input, Endian>;

mod gnu_debuglink;
pub use gnu_debuglink::GnuDebuglink;

pub mod leb128;

mod parser;
pub use parser::{Error, Format, Result};
pub use parser::{DebugMacinfoOffset, Pointer};

mod reader;
pub use reader::{Reader, ReaderOffset};

mod abbrev;
pub use abbrev::{Abbreviation, Abbreviations, AttributeSpecification, DebugAbbrev,
                 DebugAbbrevOffset};

mod aranges;
pub use aranges::{ArangeEntry, ArangeEntryIter, DebugAranges};

mod line;
pub use line::*;

mod loclists;
pub use loclists::{DebugLoc, DebugLocLists, LocListIter, LocationListEntry, LocationLists,
                   LocationListsOffset, RawLocListEntry, RawLocListIter};

mod lookup;

mod op;
pub use op::*;

mod pubnames;
pub use pubnames::{DebugPubNames, PubNamesEntry, PubNamesEntryIter};

mod pubtypes;
pub use pubtypes::{DebugPubTypes, PubTypesEntry, PubTypesEntryIter};

mod rnglists;
pub use rnglists::{DebugRanges, DebugRngLists, Range, RangeLists, RangeListsOffset,
                   RawRngListEntry, RngListIter};

mod str;
pub use str::*;

#[cfg(test)]
mod test_util;

mod unit;
pub use unit::{CompilationUnitHeader, CompilationUnitHeadersIter, DebugInfo, DebugInfoOffset,
               UnitOffset};
pub use unit::{DebugTypeSignature, DebugTypes, DebugTypesOffset, TypeUnitHeader,
               TypeUnitHeadersIter};
pub use unit::{DebuggingInformationEntry, EntriesCursor, EntriesTree, EntriesTreeIter,
               EntriesTreeNode};
pub use unit::{Attribute, AttributeValue, AttrsIter};

mod value;
pub use value::{Value, ValueType};

/// A convenience trait for loading DWARF sections from object files.  To be
/// used like:
///
/// ```
/// use gimli::{DebugInfo, EndianBuf, LittleEndian, Reader, Section};
///
/// fn load_section<R, S, F>(loader: F) -> S
///   where R: Reader, S: Section<R>, F: FnOnce(&'static str) -> R
/// {
///   let data = loader(S::section_name());
///   S::from(data)
/// }
///
/// let buf = [0x00, 0x01, 0x02, 0x03];
/// let reader = EndianBuf::new(&buf, LittleEndian);
///
/// let debug_info: DebugInfo<_> = load_section(|_: &'static str| reader);
/// ```
pub trait Section<R: Reader>: From<R> {
    /// Returns the ELF section name for this type.
    fn section_name() -> &'static str;
}
