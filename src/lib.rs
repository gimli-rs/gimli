//! A lazy, zero-copy parser for the DWARF debugging information format.
//!
//! * Zero-copy: everything is just a reference to the original input buffer. No
//!   copies of the input data ever get made.
//!
//! * Lazy: only the compilation units' entries that you iterate over get
//!   parsed, and only as deep as you ask. Skip over a compilation unit and its
//!   entries don't get parsed.
//!
//! * Bring your own object file parser: `gimli` isn't coupled to any platform
//!   or object file format. Use your own ELF parser on Linux or a Mach-O parser
//!   on OSX.
//!
//! This library primarily targets the fourth edition of the standard (the most
//! recent, at time of writing).
//!
//! ## Example Usage
//!
//! Print out all of the functions in a compilation unit.
//!
//! ```rust,no_run
//! use gimli;
//!
//! # let debug_info_buf = [];
//! # let debug_abbrev_buf = [];
//! # let read_debug_info = || &debug_info_buf;
//! # let read_debug_abbrev = || &debug_abbrev_buf;
//! // Read the .debug_info and .debug_abbrev sections with whatever object
//! // loader you're using.
//! let debug_info = gimli::DebugInfo::<gimli::LittleEndian>::new(read_debug_info());
//! let debug_abbrev = gimli::DebugAbbrev::<gimli::LittleEndian>::new(read_debug_abbrev());
//!
//! // Grab the first compilation unit.
//! let unit = debug_info.units().next()
//!     .expect("Should have at least one unit")
//!     .expect("and it should parse OK");
//!
//! // Parse the abbreviations for this compilation unit.
//! let abbrevs = unit.abbreviations(debug_abbrev)
//!     .expect("Should parse the abbreviations OK");
//!
//! // Get a cursor for iterating over this unit's entries.
//! let mut entries = unit.entries(&abbrevs);
//!
//! // Keep iterating entries while the cursor is not exhausted.
//! while let Some((_, entry)) = entries.next_dfs().expect("Should parse next entry") {
//!     // If we find an entry for a function, print it.
//!     if entry.tag() == gimli::DW_TAG_subprogram {
//!         println!("Found a function: {:?}", entry);
//!     }
//! }
//! ```
//!
//! See the [example
//! programs](https://github.com/gimli-rs/gimli/blob/master/examples/) for
//! complete examples.
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
//! // Add the `fallinle-iterator` crate. Don't forget to add it to your
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

mod constants;
pub use constants::*;

mod endianity;
pub use endianity::{Endianity, EndianBuf, LittleEndian, BigEndian, NativeEndian};

mod parser;
pub use parser::{Error, ParseResult, Format};
pub use parser::{DebugLocOffset, DebugMacinfoOffset, DebugRangesOffset, UnitOffset};
pub use parser::{DebugInfo, DebugInfoOffset, UnitHeadersIter, UnitHeader};
pub use parser::{DebugTypes, DebugTypesOffset, TypeUnitHeadersIter, TypeUnitHeader};
pub use parser::{EntriesCursor, DebuggingInformationEntry, AttrsIter, Attribute, AttributeValue};

mod abbrev;
pub use abbrev::{DebugAbbrev, DebugAbbrevOffset, Abbreviations, Abbreviation,
                 AttributeSpecification};

mod aranges;
pub use aranges::{DebugAranges, ArangeEntryIter, ArangeEntry};

mod line;
pub use line::*;

mod lookup;

mod pubnames;
pub use pubnames::{DebugPubNames, PubNamesEntryIter, PubNamesEntry};

mod pubtypes;
pub use pubtypes::{DebugPubTypes, PubTypesEntryIter, PubTypesEntry};

mod str;
pub use str::*;
