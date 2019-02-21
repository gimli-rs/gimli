//! `gimli` is a library for reading and writing the
//! [DWARF debugging format](http://dwarfstd.org/).
//!
//! See the [read](./read/index.html) and [write](./write/index.html) modules
//! for examples and API documentation.
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
//!
//! * `read`: Enabled by default. Enables the `read` module. Requires
//! either `alloc` or `std` to also be enabled.
//!
//! * `write`: Enabled by default. Enables the `write` module. Automatically
//! enables `std` too.
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]
// Selectively enable rust 2018 warnings
#![warn(bare_trait_objects)]
#![warn(unused_extern_crates)]
#![warn(ellipsis_inclusive_range_patterns)]
//#![warn(elided_lifetimes_in_paths)]
#![warn(explicit_outlives_requirements)]
// Allow clippy warnings when we aren't building with clippy.
#![allow(unknown_lints)]
// False positives with `fallible_iterator`.
#![allow(clippy::should_implement_trait)]
// Many false positives involving `continue`.
#![allow(clippy::never_loop)]
// False positives when block expressions are used inside an assertion.
#![allow(clippy::panic_params)]
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

#[cfg(feature = "std")]
mod imports {
    pub use std::borrow;
    pub use std::boxed;
    pub use std::collections;
    pub use std::rc;
    pub use std::string;
    pub use std::sync::Arc;
    pub use std::vec;
}

#[cfg(not(feature = "std"))]
mod imports {
    pub use alloc::borrow;
    pub use alloc::boxed;
    pub use alloc::collections;
    pub use alloc::rc;
    pub use alloc::string;
    pub use alloc::sync::Arc;
    pub use alloc::vec;
}

use crate::imports::*;

pub use stable_deref_trait::{CloneStableDeref, StableDeref};

mod common;
pub use crate::common::*;

mod arch;
pub use crate::arch::*;

pub mod constants;
// For backwards compat.
pub use crate::constants::*;

mod endianity;
pub use crate::endianity::{BigEndian, Endianity, LittleEndian, NativeEndian, RunTimeEndian};

pub mod leb128;

#[cfg(feature = "read")]
pub mod read;
// For backwards compat.
#[cfg(feature = "read")]
pub use crate::read::*;

#[cfg(feature = "write")]
pub mod write;

#[cfg(test)]
mod test_util;
