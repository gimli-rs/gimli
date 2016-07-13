//! A parser for the DWARF debugging information format.
//!
//! This library targets the fourth edition of the standard (the most recent, at
//! time of writing).
//!
//! TODO FITZGEN: example usage here!

#![deny(missing_docs)]

extern crate leb128;
#[macro_use]
extern crate nom;

mod parser;
pub use parser::*;
