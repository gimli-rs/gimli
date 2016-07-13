# `gimli`

[![](http://meritbadge.herokuapp.com/gimli)![](https://img.shields.io/crates/d/gimli.png)](https://crates.io/crates/gimli)

[![Build Status](https://travis-ci.org/fitzgen/gimli.png?branch=master)](https://travis-ci.org/fitzgen/gimli)

[![Coverage Status](https://coveralls.io/repos/github/fitzgen/gimli/badge.svg?branch=master)](https://coveralls.io/github/fitzgen/gimli?branch=master)

A parser for the DWARF debugging format.

## Install

Either

    $ cargo add gimli

or add this to your `Cargo.toml`:

    [dependencies]
    gimli = "0.1.0"

## Documentation

[Documentation](http://fitzgen.github.io/gimli/gimli/index.html)

## TODO

* Better documentation and examples

* For the fixed size integers (ie, not LEB128) figure out how to do endianness
  correctly, and/or whether we are doing it correctly or not right now.
    * Need to be generic across an `Endianness` trait (big or little) which
      should match the endianness of the object file we are being supplied with
      data from.

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
    * Clean up the return types for traversal methods...

* Make a common `Unit` trait for all `CompilationUnit`, `TypeUnit`, and
  `PartialUnit` so DIEs can just have a fat pointer to their unit rather than be
  generic.

* Don't expose ParseResult to the outside world, just re-wrap in a gimli::Result
  type

* Investigate not using `nom` and use `std::io::Cursor` and `byteorder` instead.
