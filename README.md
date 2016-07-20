# `gimli`

[![](http://meritbadge.herokuapp.com/gimli) ![](https://img.shields.io/crates/d/gimli.png)](https://crates.io/crates/gimli) [![Build Status](https://travis-ci.org/fitzgen/gimli.png?branch=master)](https://travis-ci.org/fitzgen/gimli)

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
  * MIT license ([`LICENSE-MIT`](./LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
