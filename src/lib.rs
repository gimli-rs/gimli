//! TODO FITZGEN

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
