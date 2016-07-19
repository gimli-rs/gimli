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
pub use parser::*;
