//! A lazy, zero-copy parser for the DWARF debugging information format.
//!
//! * **Zero-copy:** everything is just a reference to the original input
//!   buffer. No copies of the input data ever get made.
//!
//! * **Lazy:** only the compilation units' entries that you iterate over get
//!   parsed, and only as deep as you ask. Skip over a compilation unit and its
//!   entries don't get parsed.
//!
//! * **Cross-platform:** `gimli` isn't coupled to any platform or object file
//!   format. Use your own ELF parser on Linux or a Mach-O parser on OSX.
//!
//!   * Unsure which object file parser to use? Try the cross-platform
//!   [`object`](https://github.com/gimli-rs/object) crate.
//!
//! This library primarily targets the fourth edition of the standard (the most
//! recent, at time of writing).
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
//! let debug_info = gimli::DebugInfo::<gimli::LittleEndian>::new(read_debug_info());
//! let debug_abbrev = gimli::DebugAbbrev::<gimli::LittleEndian>::new(read_debug_abbrev());
//!
//! // Iterate over all compilation units.
//! let mut iter = debug_info.units();
//! while let Some(unit) = try!(iter.next()) {
//!     // Parse the abbreviations for this compilation unit.
//!     let abbrevs = try!(unit.abbreviations(debug_abbrev));
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
//! # Ok(())
//! # }
//! ```
//!
//! See the [example
//! programs](https://github.com/gimli-rs/gimli/blob/master/examples/) for
//! complete examples.
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
//!   * [`DebugPubNames`](./type.DebugPubNames.html): The `.debug_pubnames`
//!   section.
//!
//!   * [`DebugPubTypes`](./type.DebugPubTypes.html): The `.debug_pubtypes`
//!   section.
//!
//!   * [`DebugStr`](./struct.DebugStr.html): The `.debug_str` section.
//!
//!   * [`DebugTypes`](./struct.DebugTypes.html): The `.debug_types` section.
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
//! use gimli::{DebugAranges, LittleEndian, ParseResult};
//!
//! fn find_sum_of_address_range_lengths(aranges: DebugAranges<LittleEndian>)
//!     -> ParseResult<u64>
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

#![deny(missing_docs)]

extern crate byteorder;
extern crate fallible_iterator;
extern crate leb128;

mod cfi;
pub use cfi::*;

mod constants;
pub use constants::*;

mod endianity;
pub use endianity::{Endianity, EndianBuf, LittleEndian, BigEndian, NativeEndian};

mod parser;
pub use parser::{Error, ParseResult, Format};
pub use parser::{DebugLocOffset, DebugMacinfoOffset, DebugRangesOffset};

mod abbrev;
pub use abbrev::{DebugAbbrev, DebugAbbrevOffset, Abbreviations, Abbreviation,
                 AttributeSpecification};

mod aranges;
pub use aranges::{DebugAranges, ArangeEntryIter, ArangeEntry};

mod line;
pub use line::*;

mod lookup;

mod op;
pub use op::*;

mod pubnames;
pub use pubnames::{DebugPubNames, PubNamesEntryIter, PubNamesEntry};

mod pubtypes;
pub use pubtypes::{DebugPubTypes, PubTypesEntryIter, PubTypesEntry};

mod section;
pub use section::{SectionData, SectionOffset};

mod str;
pub use str::*;

mod unit;
pub use unit::{DebugInfo, DebugInfoOffset, UnitHeadersIter, UnitHeader, UnitOffset};
pub use unit::{DebugTypes, DebugTypesOffset, DebugTypeSignature, TypeUnitHeadersIter,
               TypeUnitHeader};
pub use unit::{EntriesCursor, DebuggingInformationEntry, AttrsIter, Attribute, AttributeValue};
