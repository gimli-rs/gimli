# `gimli`

[![](http://meritbadge.herokuapp.com/gimli) ![](https://img.shields.io/crates/d/gimli.png)](https://crates.io/crates/gimli) [![Build Status](https://travis-ci.org/fitzgen/gimli.png?branch=master)](https://travis-ci.org/fitzgen/gimli) [![Coverage Status](https://coveralls.io/repos/github/fitzgen/gimli/badge.svg?branch=master)](https://coveralls.io/github/fitzgen/gimli?branch=master)

A lazy, zero-copy parser for the DWARF debugging format.

* Zero copy: everything is just a reference to the original input buffer. No
  copies of the input data get made.

* Lazy: you can iterate compilation units without parsing their
  contents. Parse only as many debugging information entry (DIE) trees as you
  iterate over. `gimli` also uses `DW_AT_sibling` references to avoid parsing a
  DIE's children to find its next sibling, when possible.

* Bring your own object file loader: `gimli` makes no assumptions about what
  kind of object file you're working with. The flipside to that is that it's up
  to you to provide an ELF loader on Linux or Mach-O loader on OSX.

## Install

Either

    $ cargo add gimli

or add this to your `Cargo.toml`:

    [dependencies]
    gimli = "0.2.0"

## Documentation

[Documentation](http://fitzgen.github.io/gimli/gimli/index.html)

## License

Licensed under either of

  * Apache License, Version 2.0 ([`LICENSE-APACHE`](./LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
  * MIT license ([`LICENSE-MIT`](./LICENSE-MIT) or http://op
  ensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

## TODO

* Better documentation and examples

* Gracefully handle all reserved values and vendor extensibility points
    * Might need to support some extensions like DWZ compressor which is used
      heavily for system libraries on at least Fedora.

* Be more future compatible by using "unknown" variants rather than throwing
  parse errors when we find something unexpected

* DWARF expressions and location descriptions

* ~~A CompilationUnitHeader iterator that skips across the DIE tree and just
  yields each header.~~
    * Factor this out and also have a `TypeUnitIterator` -- where do
      `PartialUnit`s fall into this again?

* Cursor-based DIE parsing
    * ~~next_dfs()~~
    * next_sibling()
    * ~~Needs to hold a reference to the current DIE to reuse the attribute parse
      when possible~~
    * implement two iterators on top of this:
        * iterate all DIEs in dfs
        * given a DIE, iterate its direct children

* Make a common `Unit` trait for all `CompilationUnit`, `TypeUnit`, and
  `PartialUnit` so DIEs can just have a fat pointer to their unit rather than be
  generic.

* Examples:
  * Make a `dwarfdump` DIE tree printer clone
  * Make a `atos` symbolizer clone
