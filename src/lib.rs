//! A parser for the DWARF debugging information format.
//!
//! This library targets the fourth edition of the standard (the most recent, at
//! time of writing).
//!
//! TODO FITZGEN: example usage here!

#![deny(missing_docs)]

#![cfg_attr(feature = "nightly", feature(plugin))]
#![cfg_attr(feature = "nightly", plugin(clippy))]
#![cfg_attr(feature = "nightly", deny(clippy))]

extern crate leb128;
#[macro_use]
extern crate nom;

mod parser;
pub use parser::*;
