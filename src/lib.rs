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
//! while let Some(_) = entries.next_dfs().expect("Should parse next entry") {
//!     let entry = entries.current()
//!         .expect("Should have a current entry")
//!         .expect("And should parse that entry OK");
//!     // If we find an entry for a function, print it.
//!     if entry.tag() == gimli::DW_TAG_subprogram {
//!         println!("Found a function: {:?}", entry);
//!     }
//! }
//! ```
//!
//! See the
//! [`examples/dwarfdump.rs`](https://github.com/fitzgen/gimli/blob/master/examples/dwarfdump.rs)
//! program for a complete example program.

#![deny(missing_docs)]

extern crate byteorder;
extern crate leb128;

mod constants;
pub use constants::*;

mod endianity;
pub use endianity::{Endianity, LittleEndian, BigEndian};

mod parser;
pub use parser::{Error, ParseResult, Format};
pub use parser::{DebugStrOffset, DebugLineOffset, DebugLocOffset, DebugMacinfoOffset, UnitOffset};
pub use parser::{DebugInfo, DebugInfoOffset, UnitHeadersIter, UnitHeader};
pub use parser::{DebugTypes, DebugTypesOffset, TypeUnitHeadersIter, TypeUnitHeader};
pub use parser::{EntriesCursor, DebuggingInformationEntry, AttrsIter, Attribute, AttributeValue};

mod abbrev;
pub use abbrev::{DebugAbbrev, DebugAbbrevOffset, Abbreviations, Abbreviation,
                 AttributeSpecification};
