# `gimli` Change Log

--------------------------------------------------------------------------------

## Unreleased

Released YYYY/MM/DD.

### Added

* TODO (or remove section if none)

### Changed

* TODO (or remove section if none)

### Deprecated

* TODO (or remove section if none)

### Removed

* TODO (or remove section if none)

### Fixed

* TODO (or remove section if none)

### Security

* TODO (or remove section if none)

--------------------------------------------------------------------------------

## 0.15.0

Released 2017/12/01.

### Added

* Added the `EndianBuf::to_string()` method. [#233][]

* Added more robust error handling in our example `dwarfdump` clone. [#234][]

* Added `FrameDescriptionEntry::initial_address` method. [#237][]

* Added `FrameDescriptionEntry::len` method. [#237][]

* Added the `FrameDescriptionEntry::entry_len` method. [#241][]

* Added the `CommonInformationEntry::offset` method. [#241][]

* Added the `CommonInformationEntry::entry_len` method. [#241][]

* Added the `CommonInformationEntry::version` method. [#241][]

* Added the `CommonInformationEntry::augmentation` method. [#241][]

* Added the `CommonInformationEntry::code_alignment_factor` method. [#241][]

* Added the `CommonInformationEntry::data_alignment_factor` method. [#241][]

* Added the `CommonInformationEntry::return_address_register` method. [#241][]

* Added support for printing `.eh_frame` sections to our example `dwarfdump`
  clone. [#241][]

* Added support for parsing the `.eh_frame_hdr` section. On Linux, the
  `.eh_frame_hdr` section provides a pointer to the already-mapped-in-memory
  `.eh_frame` data, so that it doesn't need to be duplicated, and a binary
  search table of its entries for faster unwinding information lookups. [#250][]

* Added support for parsing DWARF 5 compilation unit headers. [#257][]

* Added support for DWARF 5's `DW_FORM_implicit_const`. [#257][]

### Changed

* Unwinding methods now give ownership of the unwinding context back to the
  caller if errors are encountered, not just on the success path. This allows
  recovering from errors in signal-safe code, where constructing a new unwinding
  context is not an option because it requires allocation. This is a **breaking
  change** affecting `UnwindSection::unwind_info_for_address` and
  `UninitializedUnwindContext::initialize`. [#241][]

* `CfaRule` and `RegisterRule` now expose their `DW_OP` expressions as
  `Expression`. This is a minor **breaking change**. [#241][]

* The `Error::UnknownVersion` variant now contains the unknown version
  number. This is a minor **breaking change**. [#245][]

* `EvaluationResult::RequiresEntryValue` requires an `Expression` instead of a
  `Reader` now. This is a minor **breaking change**. [#256][]


[#233]: https://github.com/gimli-rs/gimli/pull/233
[#234]: https://github.com/gimli-rs/gimli/pull/234
[#237]: https://github.com/gimli-rs/gimli/pull/237
[#241]: https://github.com/gimli-rs/gimli/pull/241
[#245]: https://github.com/gimli-rs/gimli/pull/245
[#250]: https://github.com/gimli-rs/gimli/pull/250
[#256]: https://github.com/gimli-rs/gimli/pull/256
[#257]: https://github.com/gimli-rs/gimli/pull/257

--------------------------------------------------------------------------------

## 0.14.0

Released 2017/08/08.

### Added

* All `pub` types now `derive(Hash)`. [#192][]

* All the constants from DWARF 5 are now defined. [#193][]

* Added support for the `DW_OP_GNU_parameter_ref` GNU extension to parsing and
  evaluation DWARF opcodes. [#208][]

* Improved LEB128 parsing performance. [#216][]

* Improved `.debug_{aranges,pubnames,pubtypes}` parsing performance. [#218][]

* Added the ability to choose endianity dynamically at run time, rather than
  only statically at compile time. [#219][]

### Changed

* The biggest change of this release is that `gimli` no longer requires the
  object file's section be fully loaded into memory. This enables using `gimli`
  on 32 bit platforms where there often isn't enough contiguous virtual memory
  address space to load debugging information into. The default behavior is
  still geared for 64 bit platforms, where address space overfloweth, and you
  can still load the whole sections of the object file (or the entire object
  file) into memory. This is abstracted over with the `gimli::Reader`
  trait. This manifests as small (but many) breaking changes to much of the
  public API. [#182][]

### Fixed

* The `DW_END_*` constants for defining endianity of a compilation unit were
  previously incorrect. [#193][]

* The `DW_OP_addr` opcode is relative to the base address of the `.text` section
  of the binary, but we were incorrectly treating it as an absolute value. [#210][]

[GitHub]: https://github.com/gimli-rs/gimli
[crates.io]: https://crates.io/crates/gimli
[contributing]: https://github.com/gimli-rs/gimli/blob/master/CONTRIBUTING.md
[easy]: https://github.com/gimli-rs/gimli/issues?q=is%3Aopen+is%3Aissue+label%3Aeasy
[#192]: https://github.com/gimli-rs/gimli/pull/192
[#193]: https://github.com/gimli-rs/gimli/pull/193
[#182]: https://github.com/gimli-rs/gimli/issues/182
[#208]: https://github.com/gimli-rs/gimli/pull/208
[#210]: https://github.com/gimli-rs/gimli/pull/210
[#216]: https://github.com/gimli-rs/gimli/pull/216
[#218]: https://github.com/gimli-rs/gimli/pull/218
[#219]: https://github.com/gimli-rs/gimli/pull/219
