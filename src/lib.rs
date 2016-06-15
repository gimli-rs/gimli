//! A parser for the DWARF debugging information format.
//!
//! This library targets the fourth edition of the standard (the most recent, at
//! time of writing).
//!
//! TODO FITZGEN: example usage here!

#![deny(missing_docs)]

extern crate leb128;
#[macro_use] extern crate nom;

pub mod parser;
mod types;
pub use types::*;


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
