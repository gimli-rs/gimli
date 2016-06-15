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

* Finish parsing DIEs

* Better documentation and examples

* For the fixed size integers (ie, not LEB128) figure out how to do endianness
  correctly, and/or whether we are doing it correctly or not right now.

* Support all reserved values and vendor extensibility points

* Be more future compatible by using "unkown" variants rather than throwing
  parse errors when we find something unexpected

* DWARF expressions and location descriptions
