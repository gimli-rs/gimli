//! A parser for the DWARF debugging information format.
//!
//! This library targets the fourth edition of the standard (the most recent, at
//! time of writing).
//!
//! TODO FITZGEN: example usage here!

#![deny(missing_docs)]

extern crate byteorder;
extern crate leb128;

mod constants;
pub use constants::*;

mod parser;
pub use parser::{Endianity, LittleEndian, BigEndian};
pub use parser::{Error, ParseResult, Format};
pub use parser::{DebugStrOffset, DebugLineOffset, DebugLocOffset, DebugMacinfoOffset, UnitOffset};
pub use parser::{DebugInfo, DebugInfoOffset, UnitHeadersIter, UnitHeader};
pub use parser::{DebugTypes, DebugTypesOffset, TypeUnitHeadersIter, TypeUnitHeader};
pub use parser::{EntriesCursor, DebuggingInformationEntry, AttrsIter, Attribute, AttributeValue};

mod abbrev;
pub use abbrev::{DebugAbbrev, DebugAbbrevOffset, Abbreviations, Abbreviation,
                 AttributeSpecification};
