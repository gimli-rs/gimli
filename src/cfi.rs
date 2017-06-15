use arrayvec::ArrayVec;
use constants;
use endianity::{Endianity, EndianBuf};
use fallible_iterator::FallibleIterator;
use parser::{Error, Format, Pointer, Result, parse_address, parse_encoded_pointer,
             parse_initial_length, parse_length_uleb_value, parse_null_terminated_string,
             parse_pointer_encoding, parse_signed_leb, parse_u8, parse_u16, parse_u32,
             parse_u32_as_u64, parse_u64, parse_unsigned_leb, parse_unsigned_leb_as_u8, take,
             u64_to_offset};
use std::cell::RefCell;
use std::fmt::Debug;
use std::iter::FromIterator;
use std::marker::PhantomData;
use std::mem;
use std::str;
use Section;

/// An offset into the `.debug_frame` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DebugFrameOffset(pub usize);

impl Into<usize> for DebugFrameOffset {
    fn into(self) -> usize {
        self.0
    }
}

impl From<usize> for DebugFrameOffset {
    fn from(o: usize) -> Self {
        DebugFrameOffset(o)
    }
}

/// An offset into the `.eh_frame` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EhFrameOffset(pub usize);

impl Into<usize> for EhFrameOffset {
    fn into(self) -> usize {
        self.0
    }
}

impl From<usize> for EhFrameOffset {
    fn from(o: usize) -> Self {
        EhFrameOffset(o)
    }
}

/// `DebugFrame` contains the `.debug_frame` section's frame unwinding
/// information required to unwind to and recover registers from older frames on
/// the stack. For example, this is useful for a debugger that wants to print
/// locals in a backtrace.
///
/// Most interesting methods are defined in the
/// [`UnwindSection`](trait.UnwindSection.html) trait.
///
/// ### Differences between `.debug_frame` and `.eh_frame`
///
/// While the `.debug_frame` section's information has a lot of overlap with the
/// `.eh_frame` section's information, the `.eh_frame` information tends to only
/// encode the subset of information needed for exception handling. Often, only
/// one of `.eh_frame` or `.debug_frame` will be present in an object file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DebugFrame<'input, Endian>(EndianBuf<'input, Endian>) where Endian: Endianity;

impl<'input, Endian> DebugFrame<'input, Endian>
    where Endian: Endianity
{
    /// Construct a new `DebugFrame` instance from the data in the
    /// `.debug_frame` section.
    ///
    /// It is the caller's responsibility to read the section and present it as
    /// a `&[u8]` slice. That means using some ELF loader on Linux, a Mach-O
    /// loader on OSX, etc.
    ///
    /// ```
    /// use gimli::{DebugFrame, NativeEndian};
    ///
    /// // Use with `.debug_frame`
    /// # let buf = [0x00, 0x01, 0x02, 0x03];
    /// # let read_debug_frame_section_somehow = || &buf;
    /// let debug_frame = DebugFrame::<NativeEndian>::new(read_debug_frame_section_somehow());
    /// ```
    pub fn new(section: &'input [u8]) -> DebugFrame<'input, Endian> {
        DebugFrame(EndianBuf::new(section))
    }
}

impl<'input, Endian> Section<'input> for DebugFrame<'input, Endian>
    where Endian: Endianity
{
    fn section_name() -> &'static str {
        ".debug_frame"
    }
}

impl<'input, Endian> From<&'input [u8]> for DebugFrame<'input, Endian>
    where Endian: Endianity
{
    fn from(v: &'input [u8]) -> Self {
        Self::new(v)
    }
}

/// `EhFrame` contains the frame unwinding information needed during exception
/// handling found in the `.eh_frame` section.
///
/// Most interesting methods are defined in the
/// [`UnwindSection`](trait.UnwindSection.html) trait.
///
/// See
/// [`DebugFrame`](./struct.DebugFrame.html#differences-between-debug_frame-and-eh_frame)
/// for some discussion on the differences between `.debug_frame` and
/// `.eh_frame`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EhFrame<'input, Endian>(EndianBuf<'input, Endian>) where Endian: Endianity;

impl<'input, Endian> EhFrame<'input, Endian>
    where Endian: Endianity
{
    /// Construct a new `EhFrame` instance from the data in the
    /// `.debug_frame` section.
    ///
    /// It is the caller's responsibility to read the section and present it as
    /// a `&[u8]` slice. That means using some ELF loader on Linux, a Mach-O
    /// loader on OSX, etc.
    ///
    /// ```
    /// use gimli::{EhFrame, NativeEndian};
    ///
    /// // Use with `.debug_frame`
    /// # let buf = [0x00, 0x01, 0x02, 0x03];
    /// # let read_debug_frame_section_somehow = || &buf;
    /// let debug_frame = EhFrame::<NativeEndian>::new(read_debug_frame_section_somehow());
    /// ```
    pub fn new(section: &'input [u8]) -> EhFrame<'input, Endian> {
        EhFrame(EndianBuf::new(section))
    }
}

impl<'input, Endian> Section<'input> for EhFrame<'input, Endian>
    where Endian: Endianity
{
    fn section_name() -> &'static str {
        ".eh_frame"
    }
}

impl<'input, Endian> From<&'input [u8]> for EhFrame<'input, Endian>
    where Endian: Endianity
{
    fn from(v: &'input [u8]) -> Self {
        Self::new(v)
    }
}

// This has to be `pub` to silence a warning (that is deny(..)'d by default) in
// rustc. Eventually, not having this `pub` will become a hard error.
#[doc(hidden)]
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CieOffsetEncoding {
    U32,
    U64,
}

// Ditto about being `pub`.
#[doc(hidden)]
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReturnAddressRegisterEncoding {
    U8,
    Uleb,
}

/// This trait completely encapsulates everything that is different between
/// `.eh_frame` and `.debug_frame`, as well as all the bits that can change
/// between DWARF versions.
#[doc(hidden)]
pub trait _UnwindSectionPrivate<'input, Endian>
    where Endian: Endianity
{
    /// Get the underlying section data.
    fn section(&self) -> EndianBuf<'input, Endian>;

    /// Returns true if the given length value should be considered an
    /// end-of-entries sentinel.
    fn length_value_is_end_of_entries(length: u64) -> bool;

    /// Return true if the given offset if the CIE sentinel, false otherwise.
    fn is_cie(format: Format, id: u64) -> bool;

    /// Return the CIE offset/ID encoding used by this unwind section with the
    /// given DWARF format.
    fn cie_offset_encoding(format: Format) -> CieOffsetEncoding;

    /// For `.eh_frame`, CIE offsets are relative to the current position. For
    /// `.debug_frame`, they are relative to the start of the section. We always
    /// internally store them relative to the section, so we handle translating
    /// `.eh_frame`'s relative offsets in this method. If the relative offset is
    /// out of bounds of the section, return `None`.
    fn resolve_cie_offset(&self,
                          input_before_offset: EndianBuf<'input, Endian>,
                          offset: usize)
                          -> Option<usize>;

    /// Return true if our parser is compatible with the given version.
    fn compatible_version(version: u8) -> bool;

    /// Does this version of this unwind section encode address and segment
    /// sizes in its CIEs?
    fn has_address_and_segment_sizes(version: u8) -> bool;

    /// What is the encoding used for the return address register in CIEs for
    /// this unwind section?
    fn return_address_register_encoding(version: u8) -> ReturnAddressRegisterEncoding;
}

/// A section holding unwind information: either `.debug_frame` or
/// `.eh_frame`. See [`DebugFrame`](./struct.DebugFrame.html) and
/// [`EhFrame`](./struct.EhFrame.html) respectively.
pub trait UnwindSection<'input, Endian>
    : Copy + Debug + Eq + _UnwindSectionPrivate<'input, Endian>
    where Endian: Endianity
{
    /// The offset type associated with this CFI section. Either
    /// `DebugFrameOffset` or `EhFrameOffset`.
    type Offset: Copy + Debug + Eq + Into<usize> + From<usize>;

    /// Construct a `Self::Offset`.
    fn offset(offset: usize) -> Self::Offset {
        offset.into()
    }

    /// Iterate over the `CommonInformationEntry`s and `FrameDescriptionEntry`s
    /// in this `.debug_frame` section.
    ///
    /// Can be [used with
    /// `FallibleIterator`](./index.html#using-with-fallibleiterator).
    fn entries<'bases>(&self,
                       bases: &'bases BaseAddresses)
                       -> CfiEntriesIter<'bases, 'input, Endian, Self> {
        CfiEntriesIter {
            section: *self,
            bases: bases,
            input: self.section(),
            phantom: PhantomData,
        }
    }

    /// Parse the `CommonInformationEntry` at the given offset.
    fn cie_from_offset<'bases>(&self,
                               bases: &'bases BaseAddresses,
                               offset: Self::Offset)
                               -> Result<CommonInformationEntry<'input, Endian, Self>> {
        let offset = offset.into();
        if self.section().len() < offset {
            return Err(Error::UnexpectedEof);
        }

        let input = &mut self.section().range_from(offset..);
        if let Some(entry) = CommonInformationEntry::parse(bases, *self, input)? {
            Ok(entry)
        } else {
            Err(Error::NoEntryAtGivenOffset)
        }
    }

    /// Find the frame unwind information for the given address.
    ///
    /// If found, the unwind information is returned along with the reset
    /// context in the form `Ok((unwind_info, context))`. If not found,
    /// `Err(gimli::Error::NoUnwindInfoForAddress)` is returned. If parsing or
    /// CFI evaluation fails, the error is returned.
    ///
    /// ```
    /// use gimli::{BaseAddresses, EhFrame, NativeEndian, UninitializedUnwindContext,
    ///             UnwindSection};
    ///
    /// # fn foo() -> gimli::Result<()> {
    /// # let read_eh_frame_section = || unimplemented!();
    /// // Get the `.eh_frame` section from the object file. Alternatively,
    /// // use `EhFrame` with the `.eh_frame` section of the object file.
    /// let eh_frame = EhFrame::<NativeEndian>::new(read_eh_frame_section());
    ///
    /// # let get_frame_pc = || unimplemented!();
    /// // Get the address of the PC for a frame you'd like to unwind.
    /// let address = get_frame_pc();
    ///
    /// // This context is reusable, which cuts down on heap allocations.
    /// let ctx = UninitializedUnwindContext::new();
    ///
    /// // Optionally provide base addresses for any relative pointers. If a
    /// // base address isn't provided and a pointer is found that is relative to
    /// // it, we will return an `Err`.
    /// # let address_of_text_section_in_memory = unimplemented!();
    /// # let address_of_data_section_in_memory = unimplemented!();
    /// let bases = BaseAddresses::default()
    ///     .set_text(address_of_text_section_in_memory)
    ///     .set_data(address_of_data_section_in_memory);
    ///
    /// let (unwind_info, ctx) = try!(eh_frame.unwind_info_for_address(&bases, ctx, address));
    /// # let do_stuff_with = |_| unimplemented!();
    /// do_stuff_with(unwind_info);
    /// # let _ = ctx;
    /// # unreachable!()
    /// # }
    /// ```
    fn unwind_info_for_address<'bases>
        (&self,
         bases: &'bases BaseAddresses,
         ctx: UninitializedUnwindContext<'input, Endian, Self>,
         address: u64)
         -> Result<(UnwindTableRow<'input, Endian>,
                    UninitializedUnwindContext<'input, Endian, Self>)> {
        let mut target_fde = None;

        let mut entries = self.entries(bases);
        while let Some(entry) = entries.next()? {
            match entry {
                CieOrFde::Cie(_) => continue,
                CieOrFde::Fde(partial) => {
                    let fde = partial.parse(|offset| self.cie_from_offset(bases, offset))?;
                    if fde.contains(address) {
                        target_fde = Some(fde);
                        break;
                    }
                }
            }
        }

        if let Some(fde) = target_fde {
            let mut result_row = None;
            let mut ctx = ctx.initialize(fde.cie())?;

            {
                let mut table = UnwindTable::new(&mut ctx, &fde);
                while let Some(row) = table.next_row()? {
                    if row.contains(address) {
                        result_row = Some(row.clone());
                        break;
                    }
                }
            }

            if let Some(row) = result_row {
                return Ok((row, ctx.reset()));
            }
        }

        Err(Error::NoUnwindInfoForAddress)
    }
}

impl<'input, Endian> _UnwindSectionPrivate<'input, Endian> for DebugFrame<'input, Endian>
    where Endian: Endianity
{
    fn section(&self) -> EndianBuf<'input, Endian> {
        self.0
    }

    fn length_value_is_end_of_entries(_: u64) -> bool {
        false
    }

    fn is_cie(format: Format, id: u64) -> bool {
        match format {
            Format::Dwarf32 => id == 0xffffffff,
            Format::Dwarf64 => id == 0xffffffffffffffff,
        }
    }

    fn cie_offset_encoding(format: Format) -> CieOffsetEncoding {
        match format {
            Format::Dwarf32 => CieOffsetEncoding::U32,
            Format::Dwarf64 => CieOffsetEncoding::U64,
        }
    }

    fn resolve_cie_offset(&self, _: EndianBuf<'input, Endian>, offset: usize) -> Option<usize> {
        Some(offset)
    }

    fn compatible_version(version: u8) -> bool {
        // Version 1 of `.debug_frame` corresponds to DWARF 2, and then for
        // DWARF 3 and 4, I think they decided to just match the standard's
        // version.
        match version {
            1 | 3 | 4 => true,
            _ => false,
        }
    }

    fn has_address_and_segment_sizes(version: u8) -> bool {
        version == 4
    }

    fn return_address_register_encoding(version: u8) -> ReturnAddressRegisterEncoding {
        if version == 1 {
            ReturnAddressRegisterEncoding::U8
        } else {
            ReturnAddressRegisterEncoding::Uleb
        }
    }
}

impl<'input, Endian> UnwindSection<'input, Endian> for DebugFrame<'input, Endian>
    where Endian: Endianity
{
    type Offset = DebugFrameOffset;
}

impl<'input, Endian> _UnwindSectionPrivate<'input, Endian> for EhFrame<'input, Endian>
    where Endian: Endianity
{
    fn section(&self) -> EndianBuf<'input, Endian> {
        self.0
    }

    fn length_value_is_end_of_entries(length: u64) -> bool {
        length == 0
    }

    fn is_cie(_: Format, id: u64) -> bool {
        id == 0
    }

    fn cie_offset_encoding(_format: Format) -> CieOffsetEncoding {
        // `.eh_frame` offsets are always 4 bytes, regardless of the DWARF
        // format.
        CieOffsetEncoding::U32
    }

    fn resolve_cie_offset(&self,
                          input_before_offset: EndianBuf<'input, Endian>,
                          input_relative_offset: usize)
                          -> Option<usize> {
        let section = self.section();

        // It would make no sense for any of these slices to be empty, since we
        // have already parsed an offset out of them.
        debug_assert!(section.len() > 0);
        debug_assert!(input_before_offset.len() > 0);

        // Additionally, the input_before_offset slice must be a subset of the
        // section's slice.
        debug_assert!(section.as_ptr() as usize <= input_before_offset.as_ptr() as usize);
        debug_assert!(input_before_offset.as_ptr() as usize + input_before_offset.len() <=
                      section.as_ptr() as usize + section.len());

        let offset_ptr = (input_before_offset.as_ptr() as usize)
            .saturating_sub(input_relative_offset);
        if section.as_ptr() as usize <= offset_ptr &&
           offset_ptr < section.as_ptr() as usize + section.len() {
            let section_relative_offset = offset_ptr - section.as_ptr() as usize;
            Some(section_relative_offset)
        } else {
            None
        }
    }

    fn compatible_version(version: u8) -> bool {
        version == 1
    }

    fn has_address_and_segment_sizes(_version: u8) -> bool {
        false
    }

    fn return_address_register_encoding(_version: u8) -> ReturnAddressRegisterEncoding {
        ReturnAddressRegisterEncoding::Uleb
    }
}

impl<'input, Endian> UnwindSection<'input, Endian> for EhFrame<'input, Endian>
    where Endian: Endianity
{
    type Offset = EhFrameOffset;
}

/// Optional base addresses for the relative `DW_EH_PE_*` encoded pointers.
///
/// During CIE/FDE parsing, if a relative pointer is encountered for a base
/// address that is unknown, an Err will be returned.
///
/// ```
/// use gimli::BaseAddresses;
///
/// # fn foo() {
/// # let address_of_cfi_section_in_memory = unimplemented!();
/// # let address_of_text_section_in_memory = unimplemented!();
/// # let address_of_data_section_in_memory = unimplemented!();
/// # let address_of_the_start_of_current_func = unimplemented!();
/// let bases = BaseAddresses::default()
///     .set_cfi(address_of_cfi_section_in_memory)
///     .set_text(address_of_text_section_in_memory)
///     .set_data(address_of_data_section_in_memory);
/// # let _ = bases;
/// # }
/// ```
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct BaseAddresses {
    /// The address of the current CFI unwind section (`.eh_frame` or
    /// `.debug_frame`) in memory.
    pub cfi: Option<u64>,

    /// The address of the `.text` section in memory.
    pub text: Option<u64>,

    /// The address of the `.data` section in memory.
    pub data: Option<u64>,

    // Unlike the others, the function base is managed internally to the parser
    // as we enter and exit FDE parsing.
    #[doc(hidden)]
    #[allow(missing_docs)]
    pub func: RefCell<Option<u64>>,
}

impl BaseAddresses {
    /// Set the CFI section base address.
    pub fn set_cfi(mut self, addr: u64) -> Self {
        self.cfi = Some(addr);
        self
    }

    /// Set the `.text` section base address.
    pub fn set_text(mut self, addr: u64) -> Self {
        self.text = Some(addr);
        self
    }

    /// Set the `.data` section base address.
    pub fn set_data(mut self, addr: u64) -> Self {
        self.data = Some(addr);
        self
    }
}

/// An iterator over CIE and FDE entries in a `.debug_frame` or `.eh_frame`
/// section.
///
/// Some pointers may be encoded relative to various base addresses. Use the
/// [`BaseAddresses`](./struct.BaseAddresses.html) parameter to provide them. By
/// default, none are provided. If a relative pointer is encountered for a base
/// address that is unknown, an `Err` will be returned and iteration will abort.
///
/// Can be [used with
/// `FallibleIterator`](./index.html#using-with-fallibleiterator).
///
/// ```
/// use gimli::{BaseAddresses, EhFrame, NativeEndian, UnwindSection};
///
/// # fn foo() -> gimli::Result<()> {
/// # let read_eh_frame_somehow = || unimplemented!();
/// let eh_frame = EhFrame::<NativeEndian>::new(read_eh_frame_somehow());
///
/// # let address_of_cfi_section_in_memory = unimplemented!();
/// # let address_of_text_section_in_memory = unimplemented!();
/// # let address_of_data_section_in_memory = unimplemented!();
/// # let address_of_the_start_of_current_func = unimplemented!();
/// // Provide base addresses for relative pointers.
/// let bases = BaseAddresses::default()
///     .set_cfi(address_of_cfi_section_in_memory)
///     .set_text(address_of_text_section_in_memory)
///     .set_data(address_of_data_section_in_memory);
///
/// let mut entries = eh_frame.entries(&bases);
///
/// # let do_stuff_with = |_| unimplemented!();
/// while let Some(entry) = try!(entries.next()) {
///     do_stuff_with(entry)
/// }
/// # unreachable!()
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct CfiEntriesIter<'bases, 'input, Endian, Section>
    where Endian: Endianity,
          Section: UnwindSection<'input, Endian>
{
    section: Section,
    bases: &'bases BaseAddresses,
    input: EndianBuf<'input, Endian>,
    phantom: PhantomData<Section>,
}

impl<'bases, 'input, Endian, Section> CfiEntriesIter<'bases, 'input, Endian, Section>
    where Endian: Endianity,
          Section: UnwindSection<'input, Endian>
{
    /// Advance the iterator to the next entry.
    pub fn next(&mut self) -> Result<Option<CieOrFde<'bases, 'input, Endian, Section>>> {
        if self.input.len() == 0 {
            return Ok(None);
        }

        // Clear any function relative base address, if one was set when parsing
        // the last entry.
        self.bases.func.borrow_mut().take();

        match parse_cfi_entry(self.bases, self.section, &mut self.input) {
            Err(e) => {
                self.input = EndianBuf::new(&[]);
                Err(e)
            }
            Ok(None) => {
                self.input = EndianBuf::new(&[]);
                Ok(None)
            }
            Ok(Some(entry)) => Ok(Some(entry)),
        }
    }
}

impl<'bases, 'input, Endian, Section> FallibleIterator
    for CfiEntriesIter<'bases, 'input, Endian, Section>
    where Endian: Endianity,
          Section: UnwindSection<'input, Endian>
{
    type Item = CieOrFde<'bases, 'input, Endian, Section>;
    type Error = Error;

    fn next(&mut self) -> ::std::result::Result<Option<Self::Item>, Self::Error> {
        CfiEntriesIter::next(self)
    }
}

struct CfiEntryCommon<'input, Endian>
    where Endian: Endianity
{
    length: u64,
    format: Format,
    cie_offset_input: EndianBuf<'input, Endian>,
    cie_id_or_offset: u64,
    rest: EndianBuf<'input, Endian>,
}

/// Parse the common start shared between both CIEs and FDEs. If we find the
/// end-of-entries sentinel, return `Ok(None)`. Otherwise, return
/// `Ok(Some(tuple))`, where `tuple.0` is the start of the next entry and
/// `tuple.1` is the parsed CFI entry data.
fn parse_cfi_entry_common<'input, Endian, Section>
    (input: &mut EndianBuf<'input, Endian>)
     -> Result<Option<CfiEntryCommon<'input, Endian>>>
    where Endian: Endianity,
          Section: UnwindSection<'input, Endian>
{
    let (length, format) = parse_initial_length(input)?;

    if Section::length_value_is_end_of_entries(length) {
        return Ok(None);
    }

    let cie_offset_input = take(length as usize, input)?;

    let mut rest = cie_offset_input;
    let cie_id_or_offset = match Section::cie_offset_encoding(format) {
        CieOffsetEncoding::U32 => parse_u32_as_u64(&mut rest)?,
        CieOffsetEncoding::U64 => parse_u64(&mut rest)?,
    };

    Ok(Some(CfiEntryCommon {
                length: length,
                format: format,
                cie_offset_input: cie_offset_input,
                cie_id_or_offset: cie_id_or_offset,
                rest: rest,
            }))
}

/// Either a `CommonInformationEntry` (CIE) or a `FrameDescriptionEntry` (FDE).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CieOrFde<'bases, 'input, Endian, Section>
    where Endian: Endianity,
          Section: UnwindSection<'input, Endian>
{
    /// This CFI entry is a `CommonInformationEntry`.
    Cie(CommonInformationEntry<'input, Endian, Section>),
    /// This CFI entry is a `FrameDescriptionEntry`, however fully parsing it
    /// requires parsing its CIE first, so it is left in a partially parsed
    /// state.
    Fde(PartialFrameDescriptionEntry<'bases, 'input, Endian, Section>),
}

#[allow(type_complexity)]
fn parse_cfi_entry<'bases, 'input, Endian, Section>
    (bases: &'bases BaseAddresses,
     section: Section,
     input: &mut EndianBuf<'input, Endian>)
     -> Result<Option<CieOrFde<'bases, 'input, Endian, Section>>>
    where Endian: Endianity,
          Section: UnwindSection<'input, Endian>
{
    let CfiEntryCommon {
        length,
        format,
        cie_offset_input,
        cie_id_or_offset,
        rest,
    } = match parse_cfi_entry_common::<Endian, Section>(input)? {
        None => return Ok(None),
        Some(common) => common,
    };

    if Section::is_cie(format, cie_id_or_offset) {
        let cie = CommonInformationEntry::parse_rest(length, format, bases, section, rest)?;
        Ok(Some(CieOrFde::Cie(cie)))
    } else {
        let cie_offset = u64_to_offset(cie_id_or_offset)?;
        let cie_offset = match section.resolve_cie_offset(cie_offset_input, cie_offset) {
            None => return Err(Error::OffsetOutOfBounds),
            Some(offset) => offset,
        };

        let fde = PartialFrameDescriptionEntry {
            length: length,
            format: format,
            cie_offset: Section::offset(cie_offset),
            rest: rest,
            section: section,
            bases: bases,
        };

        Ok(Some(CieOrFde::Fde(fde)))
    }
}

/// We support the z-style augmentation [defined by `.eh_frame`][ehframe].
///
/// [ehframe]: http://refspecs.linuxfoundation.org/LSB_3.0.0/LSB-Core-generic/LSB-Core-generic/ehframechpt.html
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Augmentation {
    /// > A 'L' may be present at any position after the first character of the
    /// > string. This character may only be present if 'z' is the first character
    /// > of the string. If present, it indicates the presence of one argument in
    /// > the Augmentation Data of the CIE, and a corresponding argument in the
    /// > Augmentation Data of the FDE. The argument in the Augmentation Data of
    /// > the CIE is 1-byte and represents the pointer encoding used for the
    /// > argument in the Augmentation Data of the FDE, which is the address of a
    /// > language-specific data area (LSDA). The size of the LSDA pointer is
    /// > specified by the pointer encoding used.
    lsda: Option<constants::DwEhPe>,

    /// > A 'P' may be present at any position after the first character of the
    /// > string. This character may only be present if 'z' is the first character
    /// > of the string. If present, it indicates the presence of two arguments in
    /// > the Augmentation Data of the CIE. The first argument is 1-byte and
    /// > represents the pointer encoding used for the second argument, which is
    /// > the address of a personality routine handler. The size of the
    /// > personality routine pointer is specified by the pointer encoding used.
    personality: Option<Pointer>,

    /// > A 'R' may be present at any position after the first character of the
    /// > string. This character may only be present if 'z' is the first character
    /// > of the string. If present, The Augmentation Data shall include a 1 byte
    /// > argument that represents the pointer encoding for the address pointers
    /// > used in the FDE.
    fde_address_encoding: Option<constants::DwEhPe>,

    /// True if this CIE's FDEs are trampolines for signal handlers.
    is_signal_trampoline: bool,
}

impl Default for Augmentation {
    fn default() -> Augmentation {
        Augmentation {
            lsda: None,
            personality: None,
            fde_address_encoding: None,
            is_signal_trampoline: false,
        }
    }
}

impl Augmentation {
    fn parse<'aug, 'bases, 'input, Endian, Section>(augmentation_str: &'aug str,
                                                    bases: &'bases BaseAddresses,
                                                    address_size: u8,
                                                    section: Section,
                                                    input: &mut EndianBuf<'input, Endian>)
                                                    -> Result<Augmentation>
        where Endian: Endianity,
              Section: UnwindSection<'input, Endian>
    {
        debug_assert!(!augmentation_str.is_empty(),
                      "Augmentation::parse should only be called if we have an augmentation");

        let mut chars = augmentation_str.chars();

        let first = chars
            .next()
            .expect("Is valid UTF-8 and length > 0, so must have at least one char.");
        if first != 'z' {
            return Err(Error::UnknownAugmentation);
        }

        let mut augmentation = Augmentation::default();

        let augmentation_length = parse_unsigned_leb(input)?;
        let rest = &mut take(augmentation_length as usize, input)?;

        for ch in chars {
            match ch {
                'L' => {
                    let encoding = parse_pointer_encoding(rest)?;
                    augmentation.lsda = Some(encoding);
                }
                'P' => {
                    let encoding = parse_pointer_encoding(rest)?;
                    let personality = parse_encoded_pointer(encoding,
                                                            bases,
                                                            address_size,
                                                            section.section(),
                                                            rest)?;
                    augmentation.personality = Some(personality);
                }
                'R' => {
                    let encoding = parse_pointer_encoding(rest)?;
                    augmentation.fde_address_encoding = Some(encoding);
                }
                'S' => augmentation.is_signal_trampoline = true,
                _ => return Err(Error::UnknownAugmentation),
            }
        }

        Ok(augmentation)
    }
}

/// Parsed augmentation data for a `FrameDescriptEntry`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct AugmentationData {
    lsda: Option<Pointer>,
}

impl AugmentationData {
    fn parse<'input, Endian, Section>(augmentation: &Augmentation,
                                      bases: &BaseAddresses,
                                      address_size: u8,
                                      section: Section,
                                      input: &mut EndianBuf<'input, Endian>)
                                      -> Result<AugmentationData>
        where Endian: Endianity,
              Section: UnwindSection<'input, Endian>
    {
        // In theory, we should be iterating over the original augmentation
        // string, interpreting each character, and reading the appropriate bits
        // out of the augmentation data as we go. However, the only character
        // that defines augmentation data in the FDE is the 'L' character, so we
        // can just check for its presence directly.

        let aug_data_len = parse_unsigned_leb(input)?;
        let rest = &mut take(aug_data_len as usize, input)?;
        let mut augmentation_data = AugmentationData::default();
        if let Some(encoding) = augmentation.lsda {
            let lsda =
                parse_encoded_pointer(encoding, bases, address_size, section.section(), rest)?;
            augmentation_data.lsda = Some(lsda);
        }
        Ok(augmentation_data)
    }
}

/// > A Common Information Entry holds information that is shared among many
/// > Frame Description Entries. There is at least one CIE in every non-empty
/// > `.debug_frame` section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommonInformationEntry<'input, Endian, Section>
    where Endian: Endianity,
          Section: UnwindSection<'input, Endian>
{
    /// > A constant that gives the number of bytes of the CIE structure, not
    /// > including the length field itself (see Section 7.2.2). The size of the
    /// > length field plus the value of length must be an integral multiple of
    /// > the address size.
    length: u64,

    format: Format,

    /// > A version number (see Section 7.23). This number is specific to the
    /// > call frame information and is independent of the DWARF version number.
    version: u8,

    /// The parsed augmentation, if any.
    augmentation: Option<Augmentation>,

    /// > The size of a target address in this CIE and any FDEs that use it, in
    /// > bytes. If a compilation unit exists for this frame, its address size
    /// > must match the address size here.
    address_size: u8,

    /// "The size of a segment selector in this CIE and any FDEs that use it, in
    /// bytes."
    segment_size: u8,

    /// "A constant that is factored out of all advance location instructions
    /// (see Section 6.4.2.1)."
    code_alignment_factor: u64,

    /// > A constant that is factored out of certain offset instructions (see
    /// > below). The resulting value is (operand * data_alignment_factor).
    data_alignment_factor: i64,

    /// > An unsigned LEB128 constant that indicates which column in the rule
    /// > table represents the return address of the function. Note that this
    /// > column might not correspond to an actual machine register.
    return_address_register: u64,

    /// > A sequence of rules that are interpreted to create the initial setting
    /// > of each column in the table.
    ///
    /// > The default rule for all columns before interpretation of the initial
    /// > instructions is the undefined rule. However, an ABI authoring body or a
    /// > compilation system authoring body may specify an alternate default
    /// > value for any or all columns.
    ///
    /// This is followed by `DW_CFA_nop` padding until the end of `length` bytes
    /// in the input.
    initial_instructions: EndianBuf<'input, Endian>,

    phantom: PhantomData<Section>,
}

impl<'input, Endian, Section> CommonInformationEntry<'input, Endian, Section>
    where Endian: Endianity,
          Section: UnwindSection<'input, Endian>
{
    #[allow(type_complexity)]
    fn parse<'bases>(bases: &'bases BaseAddresses,
                     section: Section,
                     input: &mut EndianBuf<'input, Endian>)
                     -> Result<Option<CommonInformationEntry<'input, Endian, Section>>> {
        let CfiEntryCommon {
            length,
            format,
            cie_id_or_offset: cie_id,
            rest,
            ..
        } = match parse_cfi_entry_common::<Endian, Section>(input)? {
            None => return Ok(None),
            Some(common) => common,
        };

        if !Section::is_cie(format, cie_id) {
            return Err(Error::NotCieId);
        }

        let entry = Self::parse_rest(length, format, bases, section, rest)?;
        Ok(Some(entry))
    }

    fn parse_rest<'bases>(length: u64,
                          format: Format,
                          bases: &'bases BaseAddresses,
                          section: Section,
                          mut rest: EndianBuf<'input, Endian>)
                          -> Result<CommonInformationEntry<'input, Endian, Section>> {
        let rest = &mut rest;
        let version = parse_u8(rest)?;
        if !Section::compatible_version(version) {
            return Err(Error::UnknownVersion);
        }

        let augmentation_string = parse_null_terminated_string(rest)?;
        let aug_len = augmentation_string.to_bytes().len();

        let (address_size, segment_size) = if Section::has_address_and_segment_sizes(version) {
            let address_size = parse_u8(rest)?;
            let segment_size = parse_u8(rest)?;
            (address_size, segment_size)
        } else {
            // Assume no segments and native word size.
            (mem::size_of::<usize>() as u8, 0)
        };

        let code_alignment_factor = parse_unsigned_leb(rest)?;
        let data_alignment_factor = parse_signed_leb(rest)?;

        let return_address_register = match Section::return_address_register_encoding(version) {
            ReturnAddressRegisterEncoding::U8 => parse_u8(rest)? as u64,
            ReturnAddressRegisterEncoding::Uleb => parse_unsigned_leb(rest)?,
        };

        let augmentation = if aug_len == 0 {
            None
        } else {
            let augmentation_string = str::from_utf8(augmentation_string.to_bytes())
                .map_err(|_| Error::BadUtf8)?;
            Some(Augmentation::parse(augmentation_string, bases, address_size, section, rest)?)
        };

        let entry = CommonInformationEntry {
            length: length,
            format: format,
            version: version,
            augmentation: augmentation,
            address_size: address_size,
            segment_size: segment_size,
            code_alignment_factor: code_alignment_factor,
            data_alignment_factor: data_alignment_factor,
            return_address_register: return_address_register,
            initial_instructions: *rest,
            phantom: PhantomData,
        };

        Ok(entry)
    }
}

/// # Signal Safe Methods
///
/// These methods are guaranteed not to allocate, acquire locks, or perform any
/// other signal-unsafe operations.
impl<'input, Endian, Section> CommonInformationEntry<'input, Endian, Section>
    where Endian: Endianity,
          Section: UnwindSection<'input, Endian>
{
    /// Iterate over this CIE's initial instructions.
    ///
    /// Can be [used with
    /// `FallibleIterator`](./index.html#using-with-fallibleiterator).
    pub fn instructions(&self) -> CallFrameInstructionIter<'input, Endian> {
        CallFrameInstructionIter { input: self.initial_instructions }
    }
}

/// A partially parsed `FrameDescriptionEntry`.
///
/// Fully parsing this FDE requires first parsing its CIE.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartialFrameDescriptionEntry<'bases, 'input, Endian, Section>
    where Endian: Endianity,
          Section: UnwindSection<'input, Endian>
{
    length: u64,
    format: Format,
    cie_offset: Section::Offset,
    rest: EndianBuf<'input, Endian>,
    section: Section,
    bases: &'bases BaseAddresses,
}

impl<'bases, 'input, Endian, Section> PartialFrameDescriptionEntry<'bases, 'input, Endian, Section>
    where Endian: Endianity,
          Section: UnwindSection<'input, Endian>
{
    /// Fully parse this FDE.
    ///
    /// You must provide a function get its associated CIE (either by parsing it
    /// on demand, or looking it up in some table mapping offsets to CIEs that
    /// you've already parsed, etc.)
    pub fn parse<F>(&self, get_cie: F) -> Result<FrameDescriptionEntry<'input, Endian, Section>>
        where F: FnMut(Section::Offset) -> Result<CommonInformationEntry<'input, Endian, Section>>
    {
        FrameDescriptionEntry::parse_rest(self.length,
                                          self.format,
                                          self.cie_offset,
                                          self.rest,
                                          self.section,
                                          self.bases,
                                          get_cie)
    }
}

/// A `FrameDescriptionEntry` is a set of CFA instructions for an address range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameDescriptionEntry<'input, Endian, Section>
    where Endian: Endianity,
          Section: UnwindSection<'input, Endian>
{
    /// > A constant that gives the number of bytes of the header and
    /// > instruction stream for this function, not including the length field
    /// > itself (see Section 7.2.2). The size of the length field plus the value
    /// > of length must be an integral multiple of the address size.
    length: u64,

    format: Format,

    /// "A constant offset into the .debug_frame section that denotes the CIE
    /// that is associated with this FDE."
    ///
    /// This is the CIE at that offset.
    cie: CommonInformationEntry<'input, Endian, Section>,

    /// > The address of the first location associated with this table entry. If
    /// > the segment_size field of this FDE's CIE is non-zero, the initial
    /// > location is preceded by a segment selector of the given length.
    initial_segment: u64,
    initial_address: u64,

    /// "The number of bytes of program instructions described by this entry."
    address_range: u64,

    /// The parsed augmentation data, if we have any.
    augmentation: Option<AugmentationData>,

    /// "A sequence of table defining instructions that are described below."
    ///
    /// This is followed by `DW_CFA_nop` padding until `length` bytes of the
    /// input are consumed.
    instructions: EndianBuf<'input, Endian>,
}

impl<'input, Endian, Section> FrameDescriptionEntry<'input, Endian, Section>
    where Endian: Endianity,
          Section: UnwindSection<'input, Endian>
{
    fn parse_rest<F>(length: u64,
                     format: Format,
                     cie_pointer: Section::Offset,
                     mut rest: EndianBuf<'input, Endian>,
                     section: Section,
                     bases: &BaseAddresses,
                     mut get_cie: F)
                     -> Result<FrameDescriptionEntry<'input, Endian, Section>>
        where F: FnMut(Section::Offset) -> Result<CommonInformationEntry<'input, Endian, Section>>
    {
        let rest = &mut rest;

        {
            let mut func = bases.func.borrow_mut();
            let offset = rest.as_ptr() as usize - section.section().as_ptr() as usize;
            *func = Some(offset as u64);
        }

        let cie = get_cie(cie_pointer)?;

        let initial_segment = if cie.segment_size > 0 {
            parse_address(rest, cie.segment_size)?
        } else {
            0
        };

        let (initial_address, address_range) = Self::parse_addresses(rest, &cie, bases, section)?;

        let aug_data = if let Some(ref augmentation) = cie.augmentation {
            Some(AugmentationData::parse(augmentation, bases, cie.address_size, section, rest)?)
        } else {
            None
        };

        let entry = FrameDescriptionEntry {
            length: length,
            format: format,
            cie: cie,
            initial_segment: initial_segment,
            initial_address: initial_address,
            address_range: address_range,
            augmentation: aug_data,
            instructions: *rest,
        };

        Ok(entry)
    }

    fn parse_addresses(input: &mut EndianBuf<'input, Endian>,
                       cie: &CommonInformationEntry<'input, Endian, Section>,
                       bases: &BaseAddresses,
                       section: Section)
                       -> Result<(u64, u64)> {
        let encoding = cie.augmentation
            .as_ref()
            .and_then(|a| a.fde_address_encoding);
        if let Some(encoding) = encoding {
            let initial_address =
                parse_encoded_pointer(encoding, bases, cie.address_size, section.section(), input)?;

            // Ignore indirection.
            let initial_address = initial_address.into();

            // Address ranges cannot be relative to anything, so just grab the
            // data format bits from the encoding.
            let address_range = parse_encoded_pointer(encoding.format(),
                                                      bases,
                                                      cie.address_size,
                                                      section.section(),
                                                      input)?;
            Ok((initial_address, address_range.into()))
        } else {
            let initial_address = parse_address(input, cie.address_size)?;
            let address_range = parse_address(input, cie.address_size)?;
            Ok((initial_address, address_range))
        }
    }

    /// Get a reference to this FDE's CIE.
    pub fn cie<'me>(&'me self) -> &'me CommonInformationEntry<'input, Endian, Section> {
        &self.cie
    }

    /// Iterate over this FDE's instructions.
    ///
    /// Will not include the CIE's initial instructions, if you want those do
    /// `fde.cie().instructions()` first.
    ///
    /// Can be [used with
    /// `FallibleIterator`](./index.html#using-with-fallibleiterator).
    pub fn instructions(&self) -> CallFrameInstructionIter<'input, Endian> {
        CallFrameInstructionIter { input: self.instructions }
    }

    /// Return `true` if the given address is within this FDE, `false`
    /// otherwise.
    pub fn contains(&self, address: u64) -> bool {
        let start = self.initial_address;
        let end = start + self.address_range;
        start <= address && address < end
    }

    /// The address of this FDE's language-specific data area (LSDA), if it has
    /// any.
    pub fn lsda(&self) -> Option<Pointer> {
        self.augmentation.as_ref().and_then(|a| a.lsda)
    }

    /// Return true if this FDE's function is a trampoline for a signal handler.
    pub fn is_signal_trampoline(&self) -> bool {
        self.cie()
            .augmentation
            .map_or(false, |a| a.is_signal_trampoline)
    }

    /// Return the address of the FDE's function's personality routine
    /// handler. The personality routine does language-specific clean up when
    /// unwinding the stack frames with the intent to not run them again.
    pub fn personality(&self) -> Option<Pointer> {
        self.cie().augmentation.as_ref().and_then(|a| a.personality)
    }
}

/// Common context needed when evaluating the call frame unwinding information.
///
/// To avoid re-allocating the context multiple times when evaluating multiple
/// CFI programs, it can be reused. At first, a context is uninitialized
/// (`UninitializedUnwindContext`). It can be initialized by providing the
/// `CommonInformationEntry` for the CFI program about to be evaluated and
/// calling `UninitializedUnwindContext::initialize`. The result is an
/// `InitializedUnwindContext`, which can be used to evaluate and run a
/// `FrameDescriptionEntry`'s CFI program. When the CFI program is complete, the
/// context can be de-initialized by calling `InitializedUnwindContext::reset`.
///
/// ```
/// use gimli::{UninitializedUnwindContext, UnwindTable};
///
/// # fn foo<'a>(some_fde: gimli::FrameDescriptionEntry<'a, gimli::LittleEndian, gimli::DebugFrame<'a, gimli::LittleEndian>>)
/// #            -> gimli::Result<()> {
/// // An uninitialized context.
/// let ctx = UninitializedUnwindContext::new();
///
/// // Initialize the context by evaluating the CIE's initial instruction program.
/// let mut ctx = try!(ctx.initialize(some_fde.cie()));
///
/// {
///     // The initialized context can now be used to generate the unwind table.
///     let mut table = UnwindTable::new(&mut ctx, &some_fde);
///     while let Some(row) = try!(table.next_row()) {
///         // Do stuff with each row...
/// #       let _ = row;
///     }
/// }
///
/// // Reset the context to the uninitialized state and re-use it with other CFI
/// // programs.
/// let ctx = ctx.reset();
/// # let _ = ctx;
/// # unreachable!()
/// # }
/// ```
///
/// In general, the states will flow from one to the other in accordance to the
/// following diagram:
///
/// ```text
///         +-------+
///         | Start |
///         +-------+
///             |
///             |
/// UninitializedUnwindContext::new()
///             |
///             |
///             V
/// +----------------------------+
/// | UninitializedUnwindContext |<---------------.
/// +----------------------------+                |
///             |                                 |
///             |                                 |
///    ctx.initialize(&cie)              Use with UnwindTable,
///             |                        and then do ctx.reset()
///             |                                 |
///             V                                 |
///  +--------------------------+                 |
///  | InitializedUnwindContext |-----------------'
///  +--------------------------+
///             |
///             |
///            Drop
///             |
///             |
///             V
///          +-----+
///          | End |
///          +-----+
/// ```
#[derive(Clone, Debug)]
pub struct UninitializedUnwindContext<'input, Endian, Section>(Box<UnwindContext<'input,
                                                                                  Endian,
                                                                                  Section>>)
    where Endian: Endianity,
          Section: UnwindSection<'input, Endian>;

impl<'input, Endian, Section> UninitializedUnwindContext<'input, Endian, Section>
    where Endian: Endianity,
          Section: UnwindSection<'input, Endian>
{
    /// Construct a new call frame unwinding context.
    pub fn new() -> UninitializedUnwindContext<'input, Endian, Section> {
        UninitializedUnwindContext(Box::new(UnwindContext::new()))
    }
}

/// # Signal Safe Methods
///
/// These methods are guaranteed not to allocate, acquire locks, or perform any
/// other signal-unsafe operations.
impl<'input, Endian, Section> UninitializedUnwindContext<'input, Endian, Section>
    where Endian: Endianity,
          Section: UnwindSection<'input, Endian>
{
    /// Run the CIE's initial instructions, creating an
    /// `InitializedUnwindContext`.
    pub fn initialize(mut self,
                      cie: &CommonInformationEntry<'input, Endian, Section>)
                      -> Result<InitializedUnwindContext<'input, Endian, Section>> {
        self.0.assert_fully_uninitialized();

        {
            let mut table = UnwindTable::new_internal(&mut self.0, cie, None);
            while let Some(_) = table.next_row()? {}
        }

        self.0.save_initial_rules();
        Ok(InitializedUnwindContext(self.0))
    }
}

/// An initialized unwinding context.
///
/// See the documentation for
/// [`UninitializedUnwindContext`](./struct.UninitializedUnwindContext.html) for
/// more details.
#[derive(Clone, Debug)]
pub struct InitializedUnwindContext<'input, Endian, Section>(Box<UnwindContext<'input,
                                                                                Endian,
                                                                                Section>>)
    where Endian: Endianity,
          Section: UnwindSection<'input, Endian>;

impl<'input, Endian, Section> InitializedUnwindContext<'input, Endian, Section>
    where Endian: Endianity,
          Section: UnwindSection<'input, Endian>
{
    /// Reset this context to the uninitialized state.
    pub fn reset(mut self) -> UninitializedUnwindContext<'input, Endian, Section> {
        self.0.reset();
        UninitializedUnwindContext(self.0)
    }
}

const MAX_UNWIND_STACK_DEPTH: usize = 4;
type UnwindContextStack<'input, Endian> = ArrayVec<[UnwindTableRow<'input, Endian>;
                                                    MAX_UNWIND_STACK_DEPTH]>;

#[derive(Clone, Debug, PartialEq, Eq)]
struct UnwindContext<'input, Endian, Section>
    where Endian: Endianity,
          Section: UnwindSection<'input, Endian>
{
    // Stack of rows. The last row is the row currently being built by the
    // program. There is always at least one row. The vast majority of CFI
    // programs will only ever have one row on the stack.
    stack: UnwindContextStack<'input, Endian>,

    // If we are evaluating an FDE's instructions, then `is_initialized` will be
    // `true` and `initial_rules` will contain the initial register rules
    // described by the CIE's initial instructions. These rules are used by
    // `DW_CFA_restore`. Otherwise, when we are currently evaluating a CIE's
    // initial instructions, `is_initialized` will be `false` and
    // `initial_rules` is not to be read from.
    initial_rules: RegisterRuleMap<'input, Endian>,
    is_initialized: bool,

    phantom: PhantomData<Section>,
}

/// # Signal Safe Methods
///
/// These methods are guaranteed not to allocate, acquire locks, or perform any
/// other signal-unsafe operations.
impl<'input, Endian, Section> UnwindContext<'input, Endian, Section>
    where Endian: Endianity,
          Section: UnwindSection<'input, Endian>
{
    fn new() -> UnwindContext<'input, Endian, Section> {
        let mut ctx = UnwindContext {
            stack: Default::default(),
            is_initialized: false,
            initial_rules: Default::default(),
            phantom: PhantomData,
        };
        ctx.reset();
        ctx
    }

    fn reset(&mut self) {
        self.stack.clear();
        let res = self.stack.push(UnwindTableRow::default());
        debug_assert!(res.is_none());

        self.initial_rules.clear();
        self.is_initialized = false;

        self.assert_fully_uninitialized();
    }

    // Asserts that we are fully uninitialized, ie not initialized *and* not in
    // the process of initializing.
    #[inline]
    fn assert_fully_uninitialized(&self) {
        assert_eq!(self.is_initialized, false);
        assert_eq!(self.initial_rules.rules.len(), 0);
        assert_eq!(self.stack.len(), 1);
        assert_eq!(self.stack[0], UnwindTableRow::default());
    }

    fn row(&self) -> &UnwindTableRow<'input, Endian> {
        self.stack.last().unwrap()
    }

    fn row_mut(&mut self) -> &mut UnwindTableRow<'input, Endian> {
        self.stack.last_mut().unwrap()
    }

    fn save_initial_rules(&mut self) {
        assert_eq!(self.is_initialized, false);
        self.initial_rules
            .clone_from(&self.stack.last().unwrap().registers);
        self.is_initialized = true;
    }

    fn start_address(&self) -> u64 {
        self.row().start_address
    }

    fn set_start_address(&mut self, start_address: u64) {
        let row = self.row_mut();
        row.start_address = start_address;
    }

    fn set_register_rule(&mut self,
                         register: u8,
                         rule: RegisterRule<'input, Endian>)
                         -> Result<()> {
        let row = self.row_mut();
        row.registers.set(register, rule)
    }

    /// Returns `None` if we have not completed evaluation of a CIE's initial
    /// instructions.
    fn get_initial_rule(&self, register: u8) -> Option<RegisterRule<'input, Endian>> {
        if !self.is_initialized {
            return None;
        }

        Some(self.initial_rules.get(register))
    }

    fn set_cfa(&mut self, cfa: CfaRule<'input, Endian>) {
        self.row_mut().cfa = cfa;
    }

    fn cfa_mut(&mut self) -> &mut CfaRule<'input, Endian> {
        &mut self.row_mut().cfa
    }

    fn push_row(&mut self) -> Result<()> {
        let new_row = self.row().clone();
        if self.stack.push(new_row).is_some() {
            Err(Error::CfiStackFull)
        } else {
            Ok(())
        }
    }

    fn pop_row(&mut self) {
        assert!(self.stack.len() > 1);
        self.stack.pop();
    }
}

/// The `UnwindTable` iteratively evaluates a `FrameDescriptionEntry`'s
/// `CallFrameInstruction` program, yielding the each row one at a time.
///
/// > 6.4.1 Structure of Call Frame Information
/// >
/// > DWARF supports virtual unwinding by defining an architecture independent
/// > basis for recording how procedures save and restore registers during their
/// > lifetimes. This basis must be augmented on some machines with specific
/// > information that is defined by an architecture specific ABI authoring
/// > committee, a hardware vendor, or a compiler producer. The body defining a
/// > specific augmentation is referred to below as the “augmenter.”
/// >
/// > Abstractly, this mechanism describes a very large table that has the
/// > following structure:
/// >
/// > <table>
/// >   <tr>
/// >     <th>LOC</th><th>CFA</th><th>R0</th><th>R1</th><td>...</td><th>RN</th>
/// >   </tr>
/// >   <tr>
/// >     <th>L0</th> <td></td>   <td></td>  <td></td>  <td></td>   <td></td>
/// >   </tr>
/// >   <tr>
/// >     <th>L1</th> <td></td>   <td></td>  <td></td>  <td></td>   <td></td>
/// >   </tr>
/// >   <tr>
/// >     <td>...</td><td></td>   <td></td>  <td></td>  <td></td>   <td></td>
/// >   </tr>
/// >   <tr>
/// >     <th>LN</th> <td></td>   <td></td>  <td></td>  <td></td>   <td></td>
/// >   </tr>
/// > </table>
/// >
/// > The first column indicates an address for every location that contains code
/// > in a program. (In shared objects, this is an object-relative offset.) The
/// > remaining columns contain virtual unwinding rules that are associated with
/// > the indicated location.
/// >
/// > The CFA column defines the rule which computes the Canonical Frame Address
/// > value; it may be either a register and a signed offset that are added
/// > together, or a DWARF expression that is evaluated.
/// >
/// > The remaining columns are labeled by register number. This includes some
/// > registers that have special designation on some architectures such as the PC
/// > and the stack pointer register. (The actual mapping of registers for a
/// > particular architecture is defined by the augmenter.) The register columns
/// > contain rules that describe whether a given register has been saved and the
/// > rule to find the value for the register in the previous frame.
/// >
/// > ...
/// >
/// > This table would be extremely large if actually constructed as
/// > described. Most of the entries at any point in the table are identical to
/// > the ones above them. The whole table can be represented quite compactly by
/// > recording just the differences starting at the beginning address of each
/// > subroutine in the program.
#[derive(Debug)]
pub struct UnwindTable<'input, 'cie, 'fde, 'ctx, Endian, Section>
    where Endian: 'cie + 'fde + 'ctx + Endianity,
          Section: 'cie + 'fde + 'ctx + UnwindSection<'input, Endian>,
          'input: 'cie + 'fde + 'ctx
{
    cie: &'cie CommonInformationEntry<'input, Endian, Section>,
    next_start_address: u64,
    returned_last_row: bool,
    instructions: CallFrameInstructionIter<'input, Endian>,
    ctx: &'ctx mut UnwindContext<'input, Endian, Section>,
    // If this is `None`, then we are executing a CIE's initial_instructions. If
    // this is `Some`, then we are executing an FDE's instructions.
    fde: Option<&'fde FrameDescriptionEntry<'input, Endian, Section>>,
}

/// # Signal Safe Methods
///
/// These methods are guaranteed not to allocate, acquire locks, or perform any
/// other signal-unsafe operations.
impl<'input, 'fde, 'ctx, Endian, Section> UnwindTable<'input, 'fde, 'fde, 'ctx, Endian, Section>
    where Endian: Endianity,
          Section: UnwindSection<'input, Endian>
{
    /// Construct a new `UnwindTable` for the given
    /// `FrameDescriptionEntry`'s CFI unwinding program.
    pub fn new(ctx: &'ctx mut InitializedUnwindContext<'input, Endian, Section>,
               fde: &'fde FrameDescriptionEntry<'input, Endian, Section>)
               -> UnwindTable<'input, 'fde, 'fde, 'ctx, Endian, Section> {
        assert!(ctx.0.is_initialized);
        Self::new_internal(&mut ctx.0, fde.cie(), Some(fde))
    }
}


/// # Signal Safe Methods
///
/// These methods are guaranteed not to allocate, acquire locks, or perform any
/// other signal-unsafe operations.
impl<'input, 'cie, 'fde, 'ctx, Endian, Section>
    UnwindTable<'input, 'cie, 'fde, 'ctx, Endian, Section>
    where Endian: Endianity,
          Section: UnwindSection<'input, Endian>
{
    fn new_internal(ctx: &'ctx mut UnwindContext<'input, Endian, Section>,
                    cie: &'cie CommonInformationEntry<'input, Endian, Section>,
                    fde: Option<&'fde FrameDescriptionEntry<'input, Endian, Section>>)
                    -> UnwindTable<'input, 'cie, 'fde, 'ctx, Endian, Section> {
        assert!(ctx.stack.len() >= 1);
        let next_start_address = fde.map_or(0, |fde| fde.initial_address);
        let instructions = fde.map_or_else(|| cie.instructions(), |fde| fde.instructions());
        UnwindTable {
            ctx: ctx,
            cie: cie,
            next_start_address: next_start_address,
            returned_last_row: false,
            instructions: instructions,
            fde: fde,
        }
    }

    /// Evaluate call frame instructions until the next row of the table is
    /// completed, and return it.
    ///
    /// Unfortunately, this cannot be used with `FallibleIterator` because of
    /// the restricted lifetime of the yielded item.
    pub fn next_row(&mut self) -> Result<Option<&UnwindTableRow<'input, Endian>>> {
        assert!(self.ctx.stack.len() >= 1);
        self.ctx.set_start_address(self.next_start_address);

        loop {
            match self.instructions.next() {
                Err(e) => return Err(e),

                Ok(None) => {
                    if self.returned_last_row {
                        return Ok(None);
                    }

                    let row = self.ctx.row_mut();
                    row.end_address = if let Some(fde) = self.fde {
                        fde.initial_address + fde.address_range
                    } else {
                        0
                    };

                    self.returned_last_row = true;
                    return Ok(Some(row));
                }

                Ok(Some(instruction)) => {
                    if self.evaluate(instruction)? {
                        return Ok(Some(self.ctx.row()));
                    }
                }
            };
        }
    }

    /// Evaluate one call frame instruction. Return `Ok(true)` if the row is
    /// complete, `Ok(false)` otherwise.
    fn evaluate(&mut self, instruction: CallFrameInstruction<'input, Endian>) -> Result<bool> {
        use CallFrameInstruction::*;

        match instruction {
            // Instructions that complete the current row and advance the
            // address for the next row.
            SetLoc { address } => {
                if address < self.ctx.start_address() {
                    return Err(Error::InvalidAddressRange);
                }

                self.next_start_address = address;
                self.ctx.row_mut().end_address = self.next_start_address;
                return Ok(true);
            }
            AdvanceLoc { delta } => {
                self.next_start_address = self.ctx.start_address() + delta as u64;
                self.ctx.row_mut().end_address = self.next_start_address;
                return Ok(true);
            }

            // Instructions that modify the CFA.
            DefCfa { register, offset } => {
                self.ctx.set_cfa(CfaRule::RegisterAndOffset {
                                     register: register,
                                     offset: offset as i64,
                                 });
            }
            DefCfaSf {
                register,
                factored_offset,
            } => {
                let data_align = self.cie.data_alignment_factor as i64;
                self.ctx.set_cfa(CfaRule::RegisterAndOffset {
                                     register: register,
                                     offset: factored_offset * data_align,
                                 });
            }
            DefCfaRegister { register } => {
                if let CfaRule::RegisterAndOffset { register: ref mut reg, .. } =
                    *self.ctx.cfa_mut() {
                    *reg = register;
                } else {
                    return Err(Error::CfiInstructionInInvalidContext);
                }
            }
            DefCfaOffset { offset } => {
                if let CfaRule::RegisterAndOffset { offset: ref mut off, .. } =
                    *self.ctx.cfa_mut() {
                    *off = offset as i64;
                } else {
                    return Err(Error::CfiInstructionInInvalidContext);
                }
            }
            DefCfaOffsetSf { factored_offset } => {
                if let CfaRule::RegisterAndOffset { offset: ref mut off, .. } =
                    *self.ctx.cfa_mut() {
                    let data_align = self.cie.data_alignment_factor as i64;
                    *off = factored_offset * data_align;
                } else {
                    return Err(Error::CfiInstructionInInvalidContext);
                }
            }
            DefCfaExpression { expression } => {
                self.ctx.set_cfa(CfaRule::Expression(expression));
            }

            // Instructions that define register rules.
            Undefined { register } => {
                self.ctx
                    .set_register_rule(register, RegisterRule::Undefined)?;
            }
            SameValue { register } => {
                self.ctx
                    .set_register_rule(register, RegisterRule::SameValue)?;
            }
            Offset {
                register,
                factored_offset,
            } => {
                let offset = factored_offset as i64 * self.cie.data_alignment_factor;
                self.ctx
                    .set_register_rule(register, RegisterRule::Offset(offset))?;
            }
            OffsetExtendedSf {
                register,
                factored_offset,
            } => {
                let offset = factored_offset * self.cie.data_alignment_factor;
                self.ctx
                    .set_register_rule(register, RegisterRule::Offset(offset))?;
            }
            ValOffset {
                register,
                factored_offset,
            } => {
                let offset = factored_offset as i64 * self.cie.data_alignment_factor;
                self.ctx
                    .set_register_rule(register, RegisterRule::ValOffset(offset))?;
            }
            ValOffsetSf {
                register,
                factored_offset,
            } => {
                let offset = factored_offset * self.cie.data_alignment_factor;
                self.ctx
                    .set_register_rule(register, RegisterRule::ValOffset(offset))?;
            }
            Register {
                dest_register,
                src_register,
            } => {
                self.ctx
                    .set_register_rule(dest_register, RegisterRule::Register(src_register))?;
            }
            Expression {
                register,
                expression,
            } => {
                let expression = RegisterRule::Expression(expression);
                self.ctx.set_register_rule(register, expression)?;
            }
            ValExpression {
                register,
                expression,
            } => {
                let expression = RegisterRule::ValExpression(expression);
                self.ctx.set_register_rule(register, expression)?;
            }
            Restore { register } => {
                let initial_rule = if let Some(rule) = self.ctx.get_initial_rule(register) {
                    rule
                } else {
                    // Can't restore the initial rule when we are
                    // evaluating the initial rules!
                    return Err(Error::CfiInstructionInInvalidContext);
                };

                self.ctx.set_register_rule(register, initial_rule)?;
            }

            // Row push and pop instructions.
            RememberState => {
                self.ctx.push_row()?;
            }
            RestoreState => {
                assert!(self.ctx.stack.len() > 0);
                if self.ctx.stack.len() == 1 {
                    return Err(Error::PopWithEmptyStack);
                }
                self.ctx.pop_row();
            }

            // No operation.
            Nop => {}
        };

        Ok(false)
    }
}

// We tend to have very few register rules: usually only a couple. Even if we
// have a rule for every register, on x86-64 with SSE and everything we're
// talking about ~100 rules. So rather than keeping the rules in a hash map, or
// a vector indexed by register number (which would lead to filling lots of
// empty entries), we store them as a vec of (register number, register rule)
// pairs.
//
// Additionally, because every register's default rule is implicitly
// `RegisterRule::Undefined`, we never store a register's rule in this vec if it
// is undefined and save a little bit more space and do a little fewer
// comparisons that way.
#[derive(Clone, Debug, Default)]
struct RegisterRuleMap<'input, Endian>
    where Endian: Endianity
{
    rules: ArrayVec<[(u8, RegisterRule<'input, Endian>); 32]>,
}

/// # Signal Safe Methods
///
/// These methods are guaranteed not to allocate, acquire locks, or perform any
/// other signal-unsafe operations.
impl<'input, Endian> RegisterRuleMap<'input, Endian>
    where Endian: Endianity
{
    fn get(&self, register: u8) -> RegisterRule<'input, Endian> {
        self.rules
            .iter()
            .find(|rule| rule.0 == register)
            .map(|r| {
                     debug_assert_ne!(r.1, RegisterRule::Undefined);
                     r.1.clone()
                 })
            .unwrap_or(RegisterRule::Undefined)
    }

    fn set(&mut self, register: u8, rule: RegisterRule<'input, Endian>) -> Result<()> {
        if rule == RegisterRule::Undefined {
            let idx = self.rules
                .iter()
                .enumerate()
                .find(|&(_, r)| r.0 == register)
                .map(|(i, _)| i);
            if let Some(idx) = idx {
                self.rules.swap_remove(idx);
            }
            return Ok(());
        }

        for &mut (reg, ref mut old_rule) in &mut self.rules {
            debug_assert_ne!(*old_rule, RegisterRule::Undefined);
            if reg == register {
                mem::replace(old_rule, rule);
                return Ok(());
            }
        }

        if self.rules.push((register, rule)).is_some() {
            Err(Error::TooManyRegisterRules)
        } else {
            Ok(())
        }
    }

    fn clear(&mut self) {
        self.rules.clear();
    }

    fn iter<'me>(&'me self) -> RegisterRuleIter<'me, 'input, Endian> {
        RegisterRuleIter(self.rules.iter())
    }
}

impl<'a, 'input, Endian> FromIterator<&'a (u8, RegisterRule<'input, Endian>)>
    for RegisterRuleMap<'input, Endian>
    where Endian: 'a + Endianity,
          'input: 'a
{
    fn from_iter<T>(iter: T) -> RegisterRuleMap<'input, Endian>
        where T: IntoIterator<Item = &'a (u8, RegisterRule<'input, Endian>)>
    {
        let iter = iter.into_iter();
        let mut rules = RegisterRuleMap::default();
        for &(reg, ref rule) in iter.filter(|r| r.1 != RegisterRule::Undefined) {
            rules
                .set(reg, rule.clone())
                .expect("This is only used in tests, impl isn't exposed publicly.
                         If you trip this, fix your test");
        }
        rules
    }
}

impl<'input, Endian> PartialEq for RegisterRuleMap<'input, Endian>
    where Endian: Endianity
{
    fn eq(&self, rhs: &Self) -> bool {
        for &(reg, ref rule) in &self.rules {
            debug_assert_ne!(*rule, RegisterRule::Undefined);
            if *rule != rhs.get(reg) {
                return false;
            }
        }

        for &(reg, ref rhs_rule) in &rhs.rules {
            debug_assert_ne!(*rhs_rule, RegisterRule::Undefined);
            if *rhs_rule != self.get(reg) {
                return false;
            }
        }

        true
    }
}

impl<'input, Endian> Eq for RegisterRuleMap<'input, Endian> where Endian: Endianity {}

/// An unordered iterator for register rules.
#[derive(Debug, Clone)]
pub struct RegisterRuleIter<'iter, 'input, Endian>(::std::slice::Iter<'iter,
                                                                       (u8,
                                                                        RegisterRule<'input,
                                                                                     Endian>)>)
    where Endian: 'iter + Endianity,
          'input: 'iter;

impl<'iter, 'input, Endian> Iterator for RegisterRuleIter<'iter, 'input, Endian>
    where Endian: Endianity
{
    type Item = &'iter (u8, RegisterRule<'input, Endian>);

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

/// A row in the virtual unwind table that describes how to find the values of
/// the registers in the *previous* frame for a range of PC addresses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnwindTableRow<'input, Endian>
    where Endian: Endianity
{
    start_address: u64,
    end_address: u64,
    cfa: CfaRule<'input, Endian>,
    registers: RegisterRuleMap<'input, Endian>,
}

impl<'input, Endian> Default for UnwindTableRow<'input, Endian>
    where Endian: Endianity
{
    fn default() -> Self {
        UnwindTableRow {
            start_address: 0,
            end_address: 0,
            cfa: Default::default(),
            registers: Default::default(),
        }
    }
}

impl<'input, Endian> UnwindTableRow<'input, Endian>
    where Endian: Endianity
{
    /// Get the starting PC address that this row applies to.
    pub fn start_address(&self) -> u64 {
        self.start_address
    }

    /// Get the end PC address where this row's register rules become
    /// unapplicable.
    ///
    /// In other words, this row describes how to recover the last frame's
    /// registers for all PCs where `row.start_address() <= PC <
    /// row.end_address()`. This row does NOT describe how to recover registers
    /// when `PC == row.end_address()`.
    pub fn end_address(&self) -> u64 {
        self.end_address
    }

    /// Return `true` if the given `address` is within this row's address range,
    /// `false` otherwise.
    pub fn contains(&self, address: u64) -> bool {
        self.start_address <= address && address < self.end_address
    }

    /// Get the canonical frame address (CFA) recovery rule for this row.
    pub fn cfa(&self) -> &CfaRule<'input, Endian> {
        &self.cfa
    }

    /// Get the register recovery rule for the given register number.
    ///
    /// The register number mapping is architecture dependent. For example, in
    /// the x86-64 ABI the register number mapping is defined in Figure 3.36:
    ///
    /// > Figure 3.36: DWARF Register Number Mapping
    /// >
    /// > <table>
    /// >   <tr><th>Register Name</th>                    <th>Number</th>  <th>Abbreviation</th></tr>
    /// >   <tr><td>General Purpose Register RAX</td>     <td>0</td>       <td>%rax</td></tr>
    /// >   <tr><td>General Purpose Register RDX</td>     <td>1</td>       <td>%rdx</td></tr>
    /// >   <tr><td>General Purpose Register RCX</td>     <td>2</td>       <td>%rcx</td></tr>
    /// >   <tr><td>General Purpose Register RBX</td>     <td>3</td>       <td>%rbx</td></tr>
    /// >   <tr><td>General Purpose Register RSI</td>     <td>4</td>       <td>%rsi</td></tr>
    /// >   <tr><td>General Purpose Register RDI</td>     <td>5</td>       <td>%rdi</td></tr>
    /// >   <tr><td>General Purpose Register RBP</td>     <td>6</td>       <td>%rbp</td></tr>
    /// >   <tr><td>Stack Pointer Register RSP</td>       <td>7</td>       <td>%rsp</td></tr>
    /// >   <tr><td>Extended Integer Registers 8-15</td>  <td>8-15</td>    <td>%r8-%r15</td></tr>
    /// >   <tr><td>Return Address RA</td>                <td>16</td>      <td></td></tr>
    /// >   <tr><td>Vector Registers 0–7</td>             <td>17-24</td>   <td>%xmm0–%xmm7</td></tr>
    /// >   <tr><td>Extended Vector Registers 8–15</td>   <td>25-32</td>   <td>%xmm8–%xmm15</td></tr>
    /// >   <tr><td>Floating Point Registers 0–7</td>     <td>33-40</td>   <td>%st0–%st7</td></tr>
    /// >   <tr><td>MMX Registers 0–7</td>                <td>41-48</td>   <td>%mm0–%mm7</td></tr>
    /// >   <tr><td>Flag Register</td>                    <td>49</td>      <td>%rFLAGS</td></tr>
    /// >   <tr><td>Segment Register ES</td>              <td>50</td>      <td>%es</td></tr>
    /// >   <tr><td>Segment Register CS</td>              <td>51</td>      <td>%cs</td></tr>
    /// >   <tr><td>Segment Register SS</td>              <td>52</td>      <td>%ss</td></tr>
    /// >   <tr><td>Segment Register DS</td>              <td>53</td>      <td>%ds</td></tr>
    /// >   <tr><td>Segment Register FS</td>              <td>54</td>      <td>%fs</td></tr>
    /// >   <tr><td>Segment Register GS</td>              <td>55</td>      <td>%gs</td></tr>
    /// >   <tr><td>Reserved</td>                         <td>56-57</td>   <td></td></tr>
    /// >   <tr><td>FS Base address</td>                  <td>58</td>      <td>%fs.base</td></tr>
    /// >   <tr><td>GS Base address</td>                  <td>59</td>      <td>%gs.base</td></tr>
    /// >   <tr><td>Reserved</td>                         <td>60-61</td>   <td></td></tr>
    /// >   <tr><td>Task Register</td>                    <td>62</td>      <td>%tr</td></tr>
    /// >   <tr><td>LDT Register</td>                     <td>63</td>      <td>%ldtr</td></tr>
    /// >   <tr><td>128-bit Media Control and Status</td> <td>64</td>      <td>%mxcsr</td></tr>
    /// >   <tr><td>x87 Control Word</td>                 <td>65</td>      <td>%fcw</td></tr>
    /// >   <tr><td>x87 Status Word</td>                  <td>66</td>      <td>%fsw</td></tr>
    /// >   <tr><td>Upper Vector Registers 16–31</td>     <td>67-82</td>   <td>%xmm16–%xmm31</td></tr>
    /// >   <tr><td>Reserved</td>                         <td>83-117</td>  <td></td></tr>
    /// >   <tr><td>Vector Mask Registers 0–7</td>        <td>118-125</td> <td>%k0–%k7</td></tr>
    /// >   <tr><td>Reserved</td>                         <td>126-129</td> <td></td></tr>
    /// > </table>
    pub fn register(&self, register: u8) -> RegisterRule<'input, Endian> {
        self.registers.get(register)
    }

    /// Iterate over all defined register `(number, rule)` pairs.
    ///
    /// The rules are not iterated in any guaranteed order. Any register that
    /// does not make an appearance in the iterator implicitly has the rule
    /// `RegisterRule::Undefined`.
    ///
    /// ```
    /// # use gimli::{LittleEndian, UnwindTableRow};
    /// # fn foo<'input>(unwind_table_row: UnwindTableRow<'input, LittleEndian>) {
    /// for &(register, ref rule) in unwind_table_row.registers() {
    ///     // ...
    ///     # drop(register); drop(rule);
    /// }
    /// # }
    /// ```
    pub fn registers<'me>(&'me self) -> RegisterRuleIter<'me, 'input, Endian> {
        self.registers.iter()
    }
}

/// The canonical frame address (CFA) recovery rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CfaRule<'input, Endian>
    where Endian: Endianity
{
    /// The CFA is given offset from the given register's value.
    RegisterAndOffset {
        /// The register containing the base value.
        register: u8,
        /// The offset from the register's base value.
        offset: i64,
    },
    /// The CFA is obtained by evaluating this `EndianBuf` as a DWARF expression
    /// program.
    Expression(EndianBuf<'input, Endian>),
}

impl<'input, Endian> Default for CfaRule<'input, Endian>
    where Endian: Endianity
{
    fn default() -> Self {
        CfaRule::RegisterAndOffset {
            register: 0,
            offset: 0,
        }
    }
}

/// An entry in the abstract CFI table that describes how to find the value of a
/// register.
///
/// "The register columns contain rules that describe whether a given register
/// has been saved and the rule to find the value for the register in the
/// previous frame."
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegisterRule<'input, Endian>
    where Endian: Endianity
{
    /// > A register that has this rule has no recoverable value in the previous
    /// > frame. (By convention, it is not preserved by a callee.)
    Undefined,

    /// > This register has not been modified from the previous frame. (By
    /// > convention, it is preserved by the callee, but the callee has not
    /// > modified it.)
    SameValue,

    /// "The previous value of this register is saved at the address CFA+N where
    /// CFA is the current CFA value and N is a signed offset."
    Offset(i64),

    /// "The previous value of this register is the value CFA+N where CFA is the
    /// current CFA value and N is a signed offset."
    ValOffset(i64),

    /// "The previous value of this register is stored in another register
    /// numbered R."
    Register(u8),

    /// "The previous value of this register is located at the address produced
    /// by executing the DWARF expression."
    Expression(EndianBuf<'input, Endian>),

    /// "The previous value of this register is the value produced by executing
    /// the DWARF expression."
    ValExpression(EndianBuf<'input, Endian>),

    /// "The rule is defined externally to this specification by the augmenter."
    Architectural,
}

/// A parsed call frame instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallFrameInstruction<'input, Endian>
    where Endian: Endianity
{
    // 6.4.2.1 Row Creation Methods
    /// > 1. DW_CFA_set_loc
    /// >
    /// > The DW_CFA_set_loc instruction takes a single operand that represents
    /// > a target address. The required action is to create a new table row
    /// > using the specified address as the location. All other values in the
    /// > new row are initially identical to the current row. The new location
    /// > value is always greater than the current one. If the segment_size
    /// > field of this FDE's CIE is non- zero, the initial location is preceded
    /// > by a segment selector of the given length.
    SetLoc {
        /// The target address.
        address: u64,
    },

    /// The `AdvanceLoc` instruction is used for all of `DW_CFA_advance_loc` and
    /// `DW_CFA_advance_loc{1,2,4}`.
    ///
    /// > 2. DW_CFA_advance_loc
    /// >
    /// > The DW_CFA_advance instruction takes a single operand (encoded with
    /// > the opcode) that represents a constant delta. The required action is
    /// > to create a new table row with a location value that is computed by
    /// > taking the current entry’s location value and adding the value of
    /// > delta * code_alignment_factor. All other values in the new row are
    /// > initially identical to the current row.
    AdvanceLoc {
        /// The delta to be added to the current address.
        delta: u32,
    },

    // 6.4.2.2 CFA Definition Methods
    /// > 1. DW_CFA_def_cfa
    /// >
    /// > The DW_CFA_def_cfa instruction takes two unsigned LEB128 operands
    /// > representing a register number and a (non-factored) offset. The
    /// > required action is to define the current CFA rule to use the provided
    /// > register and offset.
    DefCfa {
        /// The target register's number.
        register: u8,
        /// The non-factored offset.
        offset: u64,
    },

    /// > 2. DW_CFA_def_cfa_sf
    /// >
    /// > The DW_CFA_def_cfa_sf instruction takes two operands: an unsigned
    /// > LEB128 value representing a register number and a signed LEB128
    /// > factored offset. This instruction is identical to DW_CFA_def_cfa
    /// > except that the second operand is signed and factored. The resulting
    /// > offset is factored_offset * data_alignment_factor.
    DefCfaSf {
        /// The target register's number.
        register: u8,
        /// The factored offset.
        factored_offset: i64,
    },

    /// > 3. DW_CFA_def_cfa_register
    /// >
    /// > The DW_CFA_def_cfa_register instruction takes a single unsigned LEB128
    /// > operand representing a register number. The required action is to
    /// > define the current CFA rule to use the provided register (but to keep
    /// > the old offset). This operation is valid only if the current CFA rule
    /// > is defined to use a register and offset.
    DefCfaRegister {
        /// The target register's number.
        register: u8,
    },

    /// > 4. DW_CFA_def_cfa_offset
    /// >
    /// > The DW_CFA_def_cfa_offset instruction takes a single unsigned LEB128
    /// > operand representing a (non-factored) offset. The required action is
    /// > to define the current CFA rule to use the provided offset (but to keep
    /// > the old register). This operation is valid only if the current CFA
    /// > rule is defined to use a register and offset.
    DefCfaOffset {
        /// The non-factored offset.
        offset: u64,
    },

    /// > 5. DW_CFA_def_cfa_offset_sf
    /// >
    /// > The DW_CFA_def_cfa_offset_sf instruction takes a signed LEB128 operand
    /// > representing a factored offset. This instruction is identical to
    /// > DW_CFA_def_cfa_offset except that the operand is signed and
    /// > factored. The resulting offset is factored_offset *
    /// > data_alignment_factor. This operation is valid only if the current CFA
    /// > rule is defined to use a register and offset.
    DefCfaOffsetSf {
        /// The factored offset.
        factored_offset: i64,
    },

    /// > 6. DW_CFA_def_cfa_expression
    /// >
    /// > The DW_CFA_def_cfa_expression instruction takes a single operand
    /// > encoded as a DW_FORM_exprloc value representing a DWARF
    /// > expression. The required action is to establish that expression as the
    /// > means by which the current CFA is computed.
    DefCfaExpression {
        /// The DWARF expression.
        expression: EndianBuf<'input, Endian>,
    },

    // 6.4.2.3 Register Rule Instructions
    /// > 1. DW_CFA_undefined
    /// >
    /// > The DW_CFA_undefined instruction takes a single unsigned LEB128
    /// > operand that represents a register number. The required action is to
    /// > set the rule for the specified register to “undefined.”
    Undefined {
        /// The target register's number.
        register: u8,
    },

    /// > 2. DW_CFA_same_value
    /// >
    /// > The DW_CFA_same_value instruction takes a single unsigned LEB128
    /// > operand that represents a register number. The required action is to
    /// > set the rule for the specified register to “same value.”
    SameValue {
        /// The target register's number.
        register: u8,
    },

    /// The `Offset` instruction represents both `DW_CFA_offset` and
    /// `DW_CFA_offset_extended`.
    ///
    /// > 3. DW_CFA_offset
    /// >
    /// > The DW_CFA_offset instruction takes two operands: a register number
    /// > (encoded with the opcode) and an unsigned LEB128 constant representing
    /// > a factored offset. The required action is to change the rule for the
    /// > register indicated by the register number to be an offset(N) rule
    /// > where the value of N is factored offset * data_alignment_factor.
    Offset {
        /// The target register's number.
        register: u8,
        /// The factored offset.
        factored_offset: u64,
    },

    /// > 5. DW_CFA_offset_extended_sf
    /// >
    /// > The DW_CFA_offset_extended_sf instruction takes two operands: an
    /// > unsigned LEB128 value representing a register number and a signed
    /// > LEB128 factored offset. This instruction is identical to
    /// > DW_CFA_offset_extended except that the second operand is signed and
    /// > factored. The resulting offset is factored_offset *
    /// > data_alignment_factor.
    OffsetExtendedSf {
        /// The target register's number.
        register: u8,
        /// The factored offset.
        factored_offset: i64,
    },

    /// > 6. DW_CFA_val_offset
    /// >
    /// > The DW_CFA_val_offset instruction takes two unsigned LEB128 operands
    /// > representing a register number and a factored offset. The required
    /// > action is to change the rule for the register indicated by the
    /// > register number to be a val_offset(N) rule where the value of N is
    /// > factored_offset * data_alignment_factor.
    ValOffset {
        /// The target register's number.
        register: u8,
        /// The factored offset.
        factored_offset: u64,
    },

    /// > 7. DW_CFA_val_offset_sf
    /// >
    /// > The DW_CFA_val_offset_sf instruction takes two operands: an unsigned
    /// > LEB128 value representing a register number and a signed LEB128
    /// > factored offset. This instruction is identical to DW_CFA_val_offset
    /// > except that the second operand is signed and factored. The resulting
    /// > offset is factored_offset * data_alignment_factor.
    ValOffsetSf {
        /// The target register's number.
        register: u8,
        /// The factored offset.
        factored_offset: i64,
    },

    /// > 8. DW_CFA_register
    /// >
    /// > The DW_CFA_register instruction takes two unsigned LEB128 operands
    /// > representing register numbers. The required action is to set the rule
    /// > for the first register to be register(R) where R is the second
    /// > register.
    Register {
        /// The number of the register whose rule is being changed.
        dest_register: u8,
        /// The number of the register where the other register's value can be
        /// found.
        src_register: u8,
    },

    /// > 9. DW_CFA_expression
    /// >
    /// > The DW_CFA_expression instruction takes two operands: an unsigned
    /// > LEB128 value representing a register number, and a DW_FORM_block value
    /// > representing a DWARF expression. The required action is to change the
    /// > rule for the register indicated by the register number to be an
    /// > expression(E) rule where E is the DWARF expression. That is, the DWARF
    /// > expression computes the address. The value of the CFA is pushed on the
    /// > DWARF evaluation stack prior to execution of the DWARF expression.
    Expression {
        /// The target register's number.
        register: u8,
        /// The DWARF expression.
        expression: EndianBuf<'input, Endian>,
    },

    /// > 10. DW_CFA_val_expression
    /// >
    /// > The DW_CFA_val_expression instruction takes two operands: an unsigned
    /// > LEB128 value representing a register number, and a DW_FORM_block value
    /// > representing a DWARF expression. The required action is to change the
    /// > rule for the register indicated by the register number to be a
    /// > val_expression(E) rule where E is the DWARF expression. That is, the
    /// > DWARF expression computes the value of the given register. The value
    /// > of the CFA is pushed on the DWARF evaluation stack prior to execution
    /// > of the DWARF expression.
    ValExpression {
        /// The target register's number.
        register: u8,
        /// The DWARF expression.
        expression: EndianBuf<'input, Endian>,
    },

    /// The `Restore` instruction represents both `DW_CFA_restore` and
    /// `DW_CFA_restore_extended`.
    ///
    /// > 11. DW_CFA_restore
    /// >
    /// > The DW_CFA_restore instruction takes a single operand (encoded with
    /// > the opcode) that represents a register number. The required action is
    /// > to change the rule for the indicated register to the rule assigned it
    /// > by the initial_instructions in the CIE.
    Restore {
        /// The register to be reset.
        register: u8,
    },

    // 6.4.2.4 Row State Instructions
    /// > 1. DW_CFA_remember_state
    /// >
    /// > The DW_CFA_remember_state instruction takes no operands. The required
    /// > action is to push the set of rules for every register onto an implicit
    /// > stack.
    RememberState,

    /// > 2. DW_CFA_restore_state
    /// >
    /// > The DW_CFA_restore_state instruction takes no operands. The required
    /// > action is to pop the set of rules off the implicit stack and place
    /// > them in the current row.
    RestoreState,

    // 6.4.2.5 Padding Instruction
    /// > 1. DW_CFA_nop
    /// >
    /// > The DW_CFA_nop instruction has no operands and no required actions. It
    /// > is used as padding to make a CIE or FDE an appropriate size.
    Nop,
}

const CFI_INSTRUCTION_HIGH_BITS_MASK: u8 = 0b11000000;
const CFI_INSTRUCTION_LOW_BITS_MASK: u8 = !CFI_INSTRUCTION_HIGH_BITS_MASK;

impl<'input, Endian> CallFrameInstruction<'input, Endian>
    where Endian: Endianity
{
    fn parse(input: &mut EndianBuf<'input, Endian>)
             -> Result<CallFrameInstruction<'input, Endian>> {
        let instruction = parse_u8(input)?;
        let high_bits = instruction & CFI_INSTRUCTION_HIGH_BITS_MASK;

        if high_bits == constants::DW_CFA_advance_loc.0 {
            let delta = instruction & CFI_INSTRUCTION_LOW_BITS_MASK;
            return Ok(CallFrameInstruction::AdvanceLoc { delta: delta as u32 });
        }

        if high_bits == constants::DW_CFA_offset.0 {
            let register = instruction & CFI_INSTRUCTION_LOW_BITS_MASK;
            let offset = parse_unsigned_leb(input)?;
            return Ok(CallFrameInstruction::Offset {
                          register: register,
                          factored_offset: offset,
                      });
        }

        if high_bits == constants::DW_CFA_restore.0 {
            let register = instruction & CFI_INSTRUCTION_LOW_BITS_MASK;
            return Ok(CallFrameInstruction::Restore { register: register });
        }

        debug_assert_eq!(high_bits, 0);
        let instruction = constants::DwCfa(instruction);

        match instruction {
            constants::DW_CFA_nop => Ok(CallFrameInstruction::Nop),

            constants::DW_CFA_set_loc => {
                let address = parse_unsigned_leb(input)?;
                Ok(CallFrameInstruction::SetLoc { address: address })
            }

            constants::DW_CFA_advance_loc1 => {
                let delta = parse_u8(input)?;
                Ok(CallFrameInstruction::AdvanceLoc { delta: delta as u32 })
            }

            constants::DW_CFA_advance_loc2 => {
                let delta = parse_u16(input)?;
                Ok(CallFrameInstruction::AdvanceLoc { delta: delta as u32 })
            }

            constants::DW_CFA_advance_loc4 => {
                let delta = parse_u32(input)?;
                Ok(CallFrameInstruction::AdvanceLoc { delta: delta })
            }

            constants::DW_CFA_offset_extended => {
                let register = parse_unsigned_leb_as_u8(input)?;
                let offset = parse_unsigned_leb(input)?;
                Ok(CallFrameInstruction::Offset {
                       register: register,
                       factored_offset: offset,
                   })
            }

            constants::DW_CFA_restore_extended => {
                let register = parse_unsigned_leb_as_u8(input)?;
                Ok(CallFrameInstruction::Restore { register: register })
            }

            constants::DW_CFA_undefined => {
                let register = parse_unsigned_leb_as_u8(input)?;
                Ok(CallFrameInstruction::Undefined { register: register })
            }

            constants::DW_CFA_same_value => {
                let register = parse_unsigned_leb_as_u8(input)?;
                Ok(CallFrameInstruction::SameValue { register: register })
            }

            constants::DW_CFA_register => {
                let dest = parse_unsigned_leb_as_u8(input)?;
                let src = parse_unsigned_leb_as_u8(input)?;
                Ok(CallFrameInstruction::Register {
                       dest_register: dest,
                       src_register: src,
                   })
            }

            constants::DW_CFA_remember_state => Ok(CallFrameInstruction::RememberState),

            constants::DW_CFA_restore_state => Ok(CallFrameInstruction::RestoreState),

            constants::DW_CFA_def_cfa => {
                let register = parse_unsigned_leb_as_u8(input)?;
                let offset = parse_unsigned_leb(input)?;
                Ok(CallFrameInstruction::DefCfa {
                       register: register,
                       offset: offset,
                   })
            }

            constants::DW_CFA_def_cfa_register => {
                let register = parse_unsigned_leb_as_u8(input)?;
                Ok(CallFrameInstruction::DefCfaRegister { register: register })
            }

            constants::DW_CFA_def_cfa_offset => {
                let offset = parse_unsigned_leb(input)?;
                Ok(CallFrameInstruction::DefCfaOffset { offset: offset })
            }

            constants::DW_CFA_def_cfa_expression => {
                let expression = parse_length_uleb_value(input)?;
                Ok(CallFrameInstruction::DefCfaExpression { expression: expression })
            }

            constants::DW_CFA_expression => {
                let register = parse_unsigned_leb_as_u8(input)?;
                let expression = parse_length_uleb_value(input)?;
                Ok(CallFrameInstruction::Expression {
                       register: register,
                       expression: expression,
                   })
            }

            constants::DW_CFA_offset_extended_sf => {
                let register = parse_unsigned_leb_as_u8(input)?;
                let offset = parse_signed_leb(input)?;
                Ok(CallFrameInstruction::OffsetExtendedSf {
                       register: register,
                       factored_offset: offset,
                   })
            }

            constants::DW_CFA_def_cfa_sf => {
                let register = parse_unsigned_leb_as_u8(input)?;
                let offset = parse_signed_leb(input)?;
                Ok(CallFrameInstruction::DefCfaSf {
                       register: register,
                       factored_offset: offset,
                   })
            }

            constants::DW_CFA_def_cfa_offset_sf => {
                let offset = parse_signed_leb(input)?;
                Ok(CallFrameInstruction::DefCfaOffsetSf { factored_offset: offset })
            }

            constants::DW_CFA_val_offset => {
                let register = parse_unsigned_leb_as_u8(input)?;
                let offset = parse_unsigned_leb(input)?;
                Ok(CallFrameInstruction::ValOffset {
                       register: register,
                       factored_offset: offset,
                   })
            }

            constants::DW_CFA_val_offset_sf => {
                let register = parse_unsigned_leb_as_u8(input)?;
                let offset = parse_signed_leb(input)?;
                Ok(CallFrameInstruction::ValOffsetSf {
                       register: register,
                       factored_offset: offset,
                   })
            }

            constants::DW_CFA_val_expression => {
                let register = parse_unsigned_leb_as_u8(input)?;
                let expression = parse_length_uleb_value(input)?;
                Ok(CallFrameInstruction::ValExpression {
                       register: register,
                       expression: expression,
                   })
            }

            otherwise => Err(Error::UnknownCallFrameInstruction(otherwise)),
        }
    }
}

/// A lazy iterator parsing call frame instructions.
///
/// Can be [used with
/// `FallibleIterator`](./index.html#using-with-fallibleiterator).
#[derive(Clone, Debug)]
pub struct CallFrameInstructionIter<'input, Endian>
    where Endian: Endianity
{
    input: EndianBuf<'input, Endian>,
}

impl<'input, Endian> CallFrameInstructionIter<'input, Endian>
    where Endian: Endianity
{
    /// Parse the next call frame instruction.
    pub fn next(&mut self) -> Result<Option<CallFrameInstruction<'input, Endian>>> {
        if self.input.len() == 0 {
            return Ok(None);
        }

        match CallFrameInstruction::parse(&mut self.input) {
            Ok(instruction) => Ok(Some(instruction)),
            Err(e) => {
                self.input = EndianBuf::new(&[]);
                Err(e)
            }
        }
    }
}

impl<'input, Endian> FallibleIterator for CallFrameInstructionIter<'input, Endian>
    where Endian: Endianity
{
    type Item = CallFrameInstruction<'input, Endian>;
    type Error = Error;

    fn next(&mut self) -> ::std::result::Result<Option<Self::Item>, Self::Error> {
        CallFrameInstructionIter::next(self)
    }
}

#[cfg(test)]
mod tests {
    extern crate test_assembler;

    use super::*;
    use super::{AugmentationData, parse_cfi_entry, RegisterRuleMap, UnwindContext};
    use constants;
    use endianity::{BigEndian, Endianity, EndianBuf, LittleEndian, NativeEndian};
    use parser::{Error, Format, Pointer, Result};
    use self::test_assembler::{Endian, Label, LabelMaker, LabelOrNum, Section, ToLabelOrNum};
    use std::fmt::Debug;
    use std::marker::PhantomData;
    use std::mem;
    use std::u64;
    use test_util::GimliSectionMethods;

    type DebugFrameCie<'input, Endian> = CommonInformationEntry<'input,
                                                                Endian,
                                                                DebugFrame<'input, Endian>>;
    type DebugFrameFde<'input, Endian> = FrameDescriptionEntry<'input,
                                                               Endian,
                                                               DebugFrame<'input, Endian>>;
    type EhFrameFde<'input, Endian> = FrameDescriptionEntry<'input,
                                                            Endian,
                                                            EhFrame<'input, Endian>>;

    fn parse_fde<'input, Endian, Section, O, F>
        (section: Section,
         input: &mut EndianBuf<'input, Endian>,
         get_cie: F)
         -> Result<FrameDescriptionEntry<'input, Endian, Section>>
        where Endian: Endianity,
              Section: UnwindSection<'input, Endian, Offset = O>,
              O: Copy + Debug + Eq + Into<usize> + From<usize>,
              F: FnMut(O) -> Result<CommonInformationEntry<'input, Endian, Section>>
    {
        let bases = Default::default();
        match parse_cfi_entry(&bases, section, input) {
            Ok(Some(CieOrFde::Fde(partial))) => partial.parse(get_cie),
            Ok(_) => Err(Error::NoEntryAtGivenOffset),
            Err(e) => Err(e),
        }
    }

    // Mixin methods for `Section` to help define binary test data.

    trait CfiSectionMethods: GimliSectionMethods {
        fn cie<'aug, 'input, E, T>(self,
                                   endian: Endian,
                                   augmentation: Option<&'aug str>,
                                   cie: &mut CommonInformationEntry<'input, E, T>)
                                   -> Self
            where E: Endianity,
                  T: UnwindSection<'input, E>;
        fn fde<'a, 'input, E, T, L>(self,
                                    endian: Endian,
                                    cie_offset: L,
                                    fde: &mut FrameDescriptionEntry<'input, E, T>)
                                    -> Self
            where E: Endianity,
                  T: UnwindSection<'input, E>,
                  L: ToLabelOrNum<'a, u64>;
    }

    impl CfiSectionMethods for Section {
        fn cie<'aug, 'input, E, T>(self,
                                   endian: Endian,
                                   augmentation: Option<&'aug str>,
                                   cie: &mut CommonInformationEntry<'input, E, T>)
                                   -> Self
            where E: Endianity,
                  T: UnwindSection<'input, E>
        {
            let length = Label::new();
            let start = Label::new();
            let end = Label::new();

            let section = match cie.format {
                Format::Dwarf32 => {
                    self.e32(endian, &length)
                        .mark(&start)
                        .e32(endian, 0xffffffff)
                }
                Format::Dwarf64 => {
                    let section = self.e32(endian, 0xffffffff);
                    section
                        .e64(endian, &length)
                        .mark(&start)
                        .e64(endian, 0xffffffffffffffff)
                }
            };

            let mut section = section.D8(cie.version);

            if let Some(augmentation) = augmentation {
                section = section.append_bytes(augmentation.as_bytes());
            }

            // Null terminator for augmentation string.
            let section = section.D8(0);

            let section = if T::has_address_and_segment_sizes(cie.version) {
                section.D8(cie.address_size).D8(cie.segment_size)
            } else {
                section
            };

            let section = section
                .uleb(cie.code_alignment_factor)
                .sleb(cie.data_alignment_factor)
                .uleb(cie.return_address_register)
                .append_bytes(cie.initial_instructions.into())
                .mark(&end);

            cie.length = (&end - &start) as u64;
            length.set_const(cie.length);

            section
        }

        fn fde<'a, 'input, E, T, L>(self,
                                    endian: Endian,
                                    cie_offset: L,
                                    fde: &mut FrameDescriptionEntry<'input, E, T>)
                                    -> Self
            where E: Endianity,
                  T: UnwindSection<'input, E>,
                  L: ToLabelOrNum<'a, u64>
        {
            let length = Label::new();
            let start = Label::new();
            let end = Label::new();

            assert_eq!(fde.format, fde.cie.format);

            let section = match T::cie_offset_encoding(fde.format) {
                CieOffsetEncoding::U32 => {
                    let section = self.e32(endian, &length).mark(&start);
                    match cie_offset.to_labelornum() {
                        LabelOrNum::Label(ref l) => section.e32(endian, l),
                        LabelOrNum::Num(o) => section.e32(endian, o as u32),
                    }
                }
                CieOffsetEncoding::U64 => {
                    let section = self.e32(endian, 0xffffffff);
                    section
                        .e64(endian, &length)
                        .mark(&start)
                        .e64(endian, cie_offset)
                }
            };

            let section = match fde.cie.segment_size {
                0 => section,
                4 => section.e32(endian, fde.initial_segment as u32),
                8 => section.e64(endian, fde.initial_segment),
                x => panic!("Unsupported test segment size: {}", x),
            };

            let section = match fde.cie.address_size {
                4 => {
                    section
                        .e32(endian, fde.initial_address as u32)
                        .e32(endian, fde.address_range as u32)
                }
                8 => {
                    section
                        .e64(endian, fde.initial_address)
                        .e64(endian, fde.address_range)
                }
                x => panic!("Unsupported address size: {}", x),
            };

            let section = if let Some(ref augmentation) = fde.augmentation {
                let cie_aug = fde.cie
                    .augmentation
                    .expect("FDE has augmentation, but CIE doesn't");

                if let Some(lsda) = augmentation.lsda {
                    // We only support writing `DW_EH_PE_absptr` here.
                    assert_eq!(cie_aug
                                   .lsda
                                   .expect("FDE has lsda, but CIE doesn't")
                                   .format(),
                               constants::DW_EH_PE_absptr);

                    // Augmentation data length
                    let section = section.uleb(fde.cie.address_size as u64);
                    match fde.cie.address_size {
                        4 => {
                            section.e32(endian, {
                                let x: u64 = lsda.into();
                                x as u32
                            })
                        }
                        8 => {
                            section.e64(endian, {
                                let x: u64 = lsda.into();
                                x
                            })
                        }
                        x => panic!("Unsupported address size: {}", x),
                    }
                } else {
                    // Even if we don't have any augmentation data, if there is
                    // an augmentation defined, we need to put the length in.
                    section.uleb(0)
                }
            } else {
                section
            };

            let section = section.append_bytes(fde.instructions.into()).mark(&end);

            fde.length = (&end - &start) as u64;
            length.set_const(fde.length);

            section
        }
    }

    fn assert_parse_cie<E>(section: Section,
                           expected: Result<Option<(EndianBuf<E>, DebugFrameCie<E>)>>)
        where E: Endianity
    {
        let section = section.get_contents().unwrap();
        let debug_frame = DebugFrame::<E>::new(&section);
        let input = &mut EndianBuf::<E>::new(&section);
        let bases = Default::default();
        let result = DebugFrameCie::parse(&bases, debug_frame, input);
        let result = result.map(|option| option.map(|cie| (*input, cie)));
        assert_eq!(result, expected);
    }

    #[test]
    fn test_parse_cie_incomplete_length_32() {
        let section = Section::with_endian(Endian::Little).L16(5);
        assert_parse_cie::<LittleEndian>(section, Err(Error::UnexpectedEof));
    }

    #[test]
    fn test_parse_cie_incomplete_length_64() {
        let section = Section::with_endian(Endian::Little)
            .L32(0xffffffff)
            .L32(12345);
        assert_parse_cie::<LittleEndian>(section, Err(Error::UnexpectedEof));
    }

    #[test]
    fn test_parse_cie_incomplete_id_32() {
        let section = Section::with_endian(Endian::Big)
            // The length is not large enough to contain the ID.
            .B32(3)
            .B32(0xffffffff);
        assert_parse_cie::<BigEndian>(section, Err(Error::UnexpectedEof));
    }

    #[test]
    fn test_parse_cie_bad_id_32() {
        let section = Section::with_endian(Endian::Big)
            // Initial length
            .B32(4)
            // Not the CIE Id.
            .B32(0xbad1bad2);
        assert_parse_cie::<BigEndian>(section, Err(Error::NotCieId));
    }

    #[test]
    fn test_parse_cie_32_bad_version() {
        let mut cie = DebugFrameCie {
            length: 0,
            format: Format::Dwarf32,
            version: 99,
            augmentation: None,
            address_size: 4,
            segment_size: 0,
            code_alignment_factor: 1,
            data_alignment_factor: 2,
            return_address_register: 3,
            initial_instructions: EndianBuf::<LittleEndian>::new(&[]),
            phantom: PhantomData,
        };

        let section = Section::with_endian(Endian::Little).cie(Endian::Little, None, &mut cie);
        assert_parse_cie::<LittleEndian>(section, Err(Error::UnknownVersion));
    }

    #[test]
    fn test_parse_cie_unknown_augmentation() {
        let length = Label::new();
        let start = Label::new();
        let end = Label::new();

        let augmentation = Some("replicant");
        let expected_rest = [1, 2, 3];

        let section = Section::with_endian(Endian::Little)
            // Initial length
            .L32(&length)
            .mark(&start)
            // CIE Id
            .L32(0xffffffff)
            // Version
            .D8(4)
            // Augmentation
            .append_bytes(augmentation.unwrap().as_bytes())
            // Null terminator
            .D8(0)
            // Extra augmented data that we can't understand.
            .L32(1)
            .L32(2)
            .L32(3)
            .L32(4)
            .L32(5)
            .L32(6)
            .mark(&end)
            .append_bytes(&expected_rest);

        let expected_length = (&end - &start) as u64;
        length.set_const(expected_length);

        assert_parse_cie::<LittleEndian>(section, Err(Error::UnknownAugmentation));
    }

    #[test]
    fn test_parse_cie_32_ok() {
        let expected_rest = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        let expected_instrs: Vec<_> = (0..4).map(|_| constants::DW_CFA_nop.0).collect();

        let mut cie: DebugFrameCie<LittleEndian> = DebugFrameCie {
            length: 0,
            format: Format::Dwarf32,
            version: 4,
            augmentation: None,
            address_size: 4,
            segment_size: 0,
            code_alignment_factor: 16,
            data_alignment_factor: 32,
            return_address_register: 1,
            initial_instructions: EndianBuf::new(&expected_instrs),
            phantom: PhantomData,
        };

        let section = Section::with_endian(Endian::Little)
            .cie(Endian::Little, None, &mut cie)
            .append_bytes(&expected_rest);

        assert_parse_cie::<LittleEndian>(section, Ok(Some((EndianBuf::new(&expected_rest), cie))));
    }

    #[test]
    fn test_parse_cie_64_ok() {
        let expected_rest = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        let expected_instrs: Vec<_> = (0..5).map(|_| constants::DW_CFA_nop.0).collect();

        let mut cie: DebugFrameCie<BigEndian> = DebugFrameCie {
            length: 0,
            format: Format::Dwarf64,
            version: 4,
            augmentation: None,
            address_size: 4,
            segment_size: 0,
            code_alignment_factor: 16,
            data_alignment_factor: 32,
            return_address_register: 7,
            initial_instructions: EndianBuf::new(&expected_instrs),
            phantom: PhantomData,
        };

        let section = Section::with_endian(Endian::Big)
            .cie(Endian::Big, None, &mut cie)
            .append_bytes(&expected_rest);

        assert_parse_cie(section, Ok(Some((EndianBuf::new(&expected_rest), cie))));
    }

    #[test]
    fn test_parse_cie_length_too_big() {
        let expected_instrs: Vec<_> = (0..13).map(|_| constants::DW_CFA_nop.0).collect();

        let mut cie = DebugFrameCie {
            length: 0,
            format: Format::Dwarf32,
            version: 4,
            augmentation: None,
            address_size: 4,
            segment_size: 0,
            code_alignment_factor: 0,
            data_alignment_factor: 0,
            return_address_register: 3,
            initial_instructions: EndianBuf::<LittleEndian>::new(&expected_instrs),
            phantom: PhantomData,
        };

        let section = Section::with_endian(Endian::Little).cie(Endian::Little, None, &mut cie);

        let mut contents = section.get_contents().unwrap();

        // Overwrite the length to be too big.
        contents[0] = 0;
        contents[1] = 0;
        contents[2] = 0;
        contents[3] = 255;

        let bases = Default::default();
        assert_eq!(DebugFrameCie::parse(&bases,
                                        DebugFrame::new(&contents),
                                        &mut EndianBuf::<LittleEndian>::new(&contents)),
                   Err(Error::UnexpectedEof));
    }

    #[test]
    fn test_parse_fde_incomplete_length_32() {
        let section = Section::with_endian(Endian::Little).L16(5);
        let section = section.get_contents().unwrap();
        let rest = &mut EndianBuf::<LittleEndian>::new(&section);
        assert_eq!(parse_fde(DebugFrame::new(&*section), rest, |_| unreachable!()),
                   Err(Error::UnexpectedEof));
    }

    #[test]
    fn test_parse_fde_incomplete_length_64() {
        let section = Section::with_endian(Endian::Little)
            .L32(0xffffffff)
            .L32(12345);
        let section = section.get_contents().unwrap();
        let rest = &mut EndianBuf::<LittleEndian>::new(&section);
        assert_eq!(parse_fde(DebugFrame::new(&*section), rest, |_| unreachable!()),
                   Err(Error::UnexpectedEof));
    }

    #[test]
    fn test_parse_fde_incomplete_cie_pointer_32() {
        let section = Section::with_endian(Endian::Big)
            // The length is not large enough to contain the CIE pointer.
            .B32(3)
            .B32(1994);
        let section = section.get_contents().unwrap();
        let rest = &mut EndianBuf::<BigEndian>::new(&section);
        assert_eq!(parse_fde(DebugFrame::new(&*section), rest, |_| unreachable!()),
                   Err(Error::UnexpectedEof));
    }

    #[test]
    fn test_parse_fde_32_ok() {
        let expected_rest = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        let cie_offset = 0xbad0bad1;
        let expected_instrs: Vec<_> = (0..7).map(|_| constants::DW_CFA_nop.0).collect();

        let cie = DebugFrameCie {
            length: 100,
            format: Format::Dwarf32,
            version: 4,
            augmentation: None,
            // DWARF32 with a 64 bit address size! Holy moly!
            address_size: 8,
            segment_size: 0,
            code_alignment_factor: 3,
            data_alignment_factor: 2,
            return_address_register: 1,
            initial_instructions: EndianBuf::new(&[]),
            phantom: PhantomData,
        };

        let mut fde = DebugFrameFde {
            length: 0,
            format: Format::Dwarf32,
            cie: cie.clone(),
            initial_segment: 0,
            initial_address: 0xfeedbeef,
            address_range: 39,
            augmentation: None,
            instructions: EndianBuf::<LittleEndian>::new(&expected_instrs),
        };

        let section = Section::with_endian(Endian::Little)
            .fde(Endian::Little, cie_offset, &mut fde)
            .append_bytes(&expected_rest);

        let section = section.get_contents().unwrap();
        let rest = &mut EndianBuf::<LittleEndian>::new(&section);

        let get_cie = |offset| {
            assert_eq!(offset, DebugFrameOffset(cie_offset as usize));
            Ok(cie.clone())
        };

        assert_eq!(parse_fde(DebugFrame::new(&*section), rest, get_cie),
                   Ok(fde));
        assert_eq!(*rest, EndianBuf::new(&expected_rest));
    }

    #[test]
    fn test_parse_fde_32_with_segment_ok() {
        let expected_rest = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        let cie_offset = 0xbad0bad1;
        let expected_instrs: Vec<_> = (0..92).map(|_| constants::DW_CFA_nop.0).collect();

        let cie = DebugFrameCie {
            length: 100,
            format: Format::Dwarf32,
            version: 4,
            augmentation: None,
            address_size: 4,
            segment_size: 4,
            code_alignment_factor: 3,
            data_alignment_factor: 2,
            return_address_register: 1,
            initial_instructions: EndianBuf::new(&[]),
            phantom: PhantomData,
        };

        let mut fde = DebugFrameFde {
            length: 0,
            format: Format::Dwarf32,
            cie: cie.clone(),
            initial_segment: 0xbadbad11,
            initial_address: 0xfeedbeef,
            address_range: 999,
            augmentation: None,
            instructions: EndianBuf::new(&expected_instrs),
        };

        let section = Section::with_endian(Endian::Little)
            .fde(Endian::Little, cie_offset, &mut fde)
            .append_bytes(&expected_rest);

        let section = section.get_contents().unwrap();
        let rest = &mut EndianBuf::<LittleEndian>::new(&section);

        let get_cie = |offset| {
            assert_eq!(offset, DebugFrameOffset(cie_offset as usize));
            Ok(cie.clone())
        };

        assert_eq!(parse_fde(DebugFrame::new(&*section), rest, get_cie),
                   Ok(fde));
        assert_eq!(*rest, EndianBuf::new(&expected_rest));
    }

    #[test]
    fn test_parse_fde_64_ok() {
        let expected_rest = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        let cie_offset = 0xbad0bad1;
        let expected_instrs: Vec<_> = (0..7).map(|_| constants::DW_CFA_nop.0).collect();

        let cie = DebugFrameCie {
            length: 100,
            format: Format::Dwarf64,
            version: 4,
            augmentation: None,
            address_size: 8,
            segment_size: 0,
            code_alignment_factor: 3,
            data_alignment_factor: 2,
            return_address_register: 1,
            initial_instructions: EndianBuf::new(&[]),
            phantom: PhantomData,
        };

        let mut fde = DebugFrameFde {
            length: 0,
            format: Format::Dwarf64,
            cie: cie.clone(),
            initial_segment: 0,
            initial_address: 0xfeedbeef,
            address_range: 999,
            augmentation: None,
            instructions: EndianBuf::new(&expected_instrs),
        };

        let section = Section::with_endian(Endian::Little)
            .fde(Endian::Little, cie_offset, &mut fde)
            .append_bytes(&expected_rest);

        let section = section.get_contents().unwrap();
        let rest = &mut EndianBuf::<LittleEndian>::new(&section);

        let get_cie = |offset| {
            assert_eq!(offset, DebugFrameOffset(cie_offset as usize));
            Ok(cie.clone())
        };

        assert_eq!(parse_fde(DebugFrame::new(&*section), rest, get_cie),
                   Ok(fde));
        assert_eq!(*rest, EndianBuf::new(&expected_rest));
    }

    #[test]
    fn test_parse_cfi_entry_on_cie_32_ok() {
        let expected_rest = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        let expected_instrs: Vec<_> = (0..4).map(|_| constants::DW_CFA_nop.0).collect();

        let mut cie = DebugFrameCie {
            length: 0,
            format: Format::Dwarf32,
            version: 4,
            augmentation: None,
            address_size: 4,
            segment_size: 0,
            code_alignment_factor: 16,
            data_alignment_factor: 32,
            return_address_register: 1,
            initial_instructions: EndianBuf::new(&expected_instrs),
            phantom: PhantomData,
        };

        let section = Section::with_endian(Endian::Big)
            .cie(Endian::Big, None, &mut cie)
            .append_bytes(&expected_rest);
        let section = section.get_contents().unwrap();
        let rest = &mut EndianBuf::<BigEndian>::new(&section);

        let bases = Default::default();
        assert_eq!(parse_cfi_entry(&bases, DebugFrame::new(&*section), rest),
                   Ok(Some(CieOrFde::Cie(cie))));
        assert_eq!(*rest, EndianBuf::new(&expected_rest));
    }

    #[test]
    fn test_parse_cfi_entry_on_fde_32_ok() {
        let cie_offset = 0x12345678;
        let expected_rest = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        let expected_instrs: Vec<_> = (0..4).map(|_| constants::DW_CFA_nop.0).collect();

        let cie = DebugFrameCie {
            length: 0,
            format: Format::Dwarf32,
            version: 4,
            augmentation: None,
            address_size: 4,
            segment_size: 0,
            code_alignment_factor: 16,
            data_alignment_factor: 32,
            return_address_register: 1,
            initial_instructions: EndianBuf::new(&[]),
            phantom: PhantomData,
        };

        let mut fde = DebugFrameFde {
            length: 0,
            format: Format::Dwarf32,
            cie: cie.clone(),
            initial_segment: 0,
            initial_address: 0xfeedbeef,
            address_range: 39,
            augmentation: None,
            instructions: EndianBuf::<BigEndian>::new(&expected_instrs),
        };

        let section = Section::with_endian(Endian::Big)
            .fde(Endian::Big, cie_offset, &mut fde)
            .append_bytes(&expected_rest);

        let section = section.get_contents().unwrap();
        let rest = &mut EndianBuf::<BigEndian>::new(&section);

        let bases = Default::default();
        match parse_cfi_entry(&bases, DebugFrame::new(&*section), rest) {
            Ok(Some(CieOrFde::Fde(partial))) => {
                assert_eq!(*rest, EndianBuf::new(&expected_rest));

                assert_eq!(partial.length, fde.length);
                assert_eq!(partial.format, fde.format);
                assert_eq!(partial.cie_offset, DebugFrameOffset(cie_offset as usize));

                let get_cie = |offset| {
                    assert_eq!(offset, DebugFrameOffset(cie_offset as usize));
                    Ok(cie.clone())
                };

                assert_eq!(partial.parse(get_cie), Ok(fde));
            }
            otherwise => panic!("Unexpected result: {:#?}", otherwise),
        }
    }

    #[test]
    fn test_cfi_entries_iter() {
        let expected_instrs1: Vec<_> = (0..4).map(|_| constants::DW_CFA_nop.0).collect();

        let expected_instrs2: Vec<_> = (0..8).map(|_| constants::DW_CFA_nop.0).collect();

        let expected_instrs3: Vec<_> = (0..12).map(|_| constants::DW_CFA_nop.0).collect();

        let expected_instrs4: Vec<_> = (0..16).map(|_| constants::DW_CFA_nop.0).collect();

        let mut cie1 = DebugFrameCie {
            length: 0,
            format: Format::Dwarf32,
            version: 4,
            augmentation: None,
            address_size: 4,
            segment_size: 0,
            code_alignment_factor: 1,
            data_alignment_factor: 2,
            return_address_register: 3,
            initial_instructions: EndianBuf::new(&expected_instrs1),
            phantom: PhantomData,
        };

        let mut cie2 = DebugFrameCie {
            length: 0,
            format: Format::Dwarf32,
            version: 4,
            augmentation: None,
            address_size: 4,
            segment_size: 0,
            code_alignment_factor: 3,
            data_alignment_factor: 2,
            return_address_register: 1,
            initial_instructions: EndianBuf::new(&expected_instrs2),
            phantom: PhantomData,
        };

        let cie1_location = Label::new();
        let cie2_location = Label::new();

        // Write the CIEs first so that their length gets set before we clone
        // them into the FDEs and our equality assertions down the line end up
        // with all the CIEs always having he correct length.
        let section = Section::with_endian(Endian::Big)
            .mark(&cie1_location)
            .cie(Endian::Big, None, &mut cie1)
            .mark(&cie2_location)
            .cie(Endian::Big, None, &mut cie2);

        let mut fde1 = DebugFrameFde {
            length: 0,
            format: Format::Dwarf32,
            cie: cie1.clone(),
            initial_segment: 0,
            initial_address: 0xfeedbeef,
            address_range: 39,
            augmentation: None,
            instructions: EndianBuf::<BigEndian>::new(&expected_instrs3),
        };

        let mut fde2 = DebugFrameFde {
            length: 0,
            format: Format::Dwarf32,
            cie: cie2.clone(),
            initial_segment: 0,
            initial_address: 0xfeedface,
            address_range: 9000,
            augmentation: None,
            instructions: EndianBuf::<BigEndian>::new(&expected_instrs4),
        };

        let section = section
            .fde(Endian::Big, &cie1_location, &mut fde1)
            .fde(Endian::Big, &cie2_location, &mut fde2);

        section.start().set_const(0);

        let cie1_offset = cie1_location.value().unwrap() as usize;
        let cie2_offset = cie2_location.value().unwrap() as usize;

        let contents = section.get_contents().unwrap();
        let debug_frame = DebugFrame::<BigEndian>::new(&contents);

        let bases = Default::default();
        let mut entries = debug_frame.entries(&bases);

        assert_eq!(entries.next(), Ok(Some(CieOrFde::Cie(cie1.clone()))));
        assert_eq!(entries.next(), Ok(Some(CieOrFde::Cie(cie2.clone()))));

        match entries.next() {
            Ok(Some(CieOrFde::Fde(partial))) => {
                assert_eq!(partial.length, fde1.length);
                assert_eq!(partial.format, fde1.format);
                assert_eq!(partial.cie_offset, DebugFrameOffset(cie1_offset));

                let get_cie = |offset| {
                    assert_eq!(offset, DebugFrameOffset(cie1_offset));
                    Ok(cie1.clone())
                };
                assert_eq!(partial.parse(get_cie), Ok(fde1));
            }
            otherwise => panic!("Unexpected result: {:#?}", otherwise),
        }

        match entries.next() {
            Ok(Some(CieOrFde::Fde(partial))) => {
                assert_eq!(partial.length, fde2.length);
                assert_eq!(partial.format, fde2.format);
                assert_eq!(partial.cie_offset, DebugFrameOffset(cie2_offset));

                let get_cie = |offset| {
                    assert_eq!(offset, DebugFrameOffset(cie2_offset));
                    Ok(cie2.clone())
                };
                assert_eq!(partial.parse(get_cie), Ok(fde2));
            }
            otherwise => panic!("Unexpected result: {:#?}", otherwise),
        }

        assert_eq!(entries.next(), Ok(None));
    }

    #[test]
    fn test_parse_cie_from_offset() {
        let filler = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        let instrs: Vec<_> = (0..5).map(|_| constants::DW_CFA_nop.0).collect();

        let mut cie = DebugFrameCie {
            length: 0,
            format: Format::Dwarf64,
            version: 4,
            augmentation: None,
            address_size: 4,
            segment_size: 0,
            code_alignment_factor: 4,
            data_alignment_factor: 8,
            return_address_register: 12,
            initial_instructions: EndianBuf::new(&instrs),
            phantom: PhantomData,
        };

        let cie_location = Label::new();

        let section = Section::with_endian(Endian::Little)
            .append_bytes(&filler)
            .mark(&cie_location)
            .cie(Endian::Little, None, &mut cie)
            .append_bytes(&filler);

        section.start().set_const(0);

        let cie_offset = DebugFrameOffset(cie_location.value().unwrap() as usize);

        let contents = section.get_contents().unwrap();
        let debug_frame = DebugFrame::<LittleEndian>::new(&contents);
        let bases = Default::default();

        assert_eq!(debug_frame.cie_from_offset(&bases, cie_offset), Ok(cie));
    }

    #[test]
    fn test_parse_cfi_instruction_advance_loc() {
        let expected_rest = [1, 2, 3, 4];
        let expected_delta = 42;
        let section = Section::with_endian(Endian::Little)
            .D8(constants::DW_CFA_advance_loc.0 | expected_delta)
            .append_bytes(&expected_rest);
        let contents = section.get_contents().unwrap();
        let input = &mut EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok(CallFrameInstruction::AdvanceLoc { delta: expected_delta as u32 }));
        assert_eq!(*input, EndianBuf::new(&expected_rest));
    }

    #[test]
    fn test_parse_cfi_instruction_offset() {
        let expected_rest = [1, 2, 3, 4];
        let expected_reg = 3;
        let expected_offset = 1997;
        let section = Section::with_endian(Endian::Little)
            .D8(constants::DW_CFA_offset.0 | expected_reg)
            .uleb(expected_offset)
            .append_bytes(&expected_rest);
        let contents = section.get_contents().unwrap();
        let input = &mut EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok(CallFrameInstruction::Offset {
                          register: expected_reg as u8,
                          factored_offset: expected_offset,
                      }));
        assert_eq!(*input, EndianBuf::new(&expected_rest));
    }

    #[test]
    fn test_parse_cfi_instruction_restore() {
        let expected_rest = [1, 2, 3, 4];
        let expected_reg = 3;
        let section = Section::with_endian(Endian::Little)
            .D8(constants::DW_CFA_restore.0 | expected_reg)
            .append_bytes(&expected_rest);
        let contents = section.get_contents().unwrap();
        let input = &mut EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok(CallFrameInstruction::Restore { register: expected_reg as u8 }));
        assert_eq!(*input, EndianBuf::new(&expected_rest));
    }

    #[test]
    fn test_parse_cfi_instruction_nop() {
        let expected_rest = [1, 2, 3, 4];
        let section = Section::with_endian(Endian::Little)
            .D8(constants::DW_CFA_nop.0)
            .append_bytes(&expected_rest);
        let contents = section.get_contents().unwrap();
        let input = &mut EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok(CallFrameInstruction::Nop));
        assert_eq!(*input, EndianBuf::new(&expected_rest));
    }

    #[test]
    fn test_parse_cfi_instruction_set_loc() {
        let expected_rest = [1, 2, 3, 4];
        let expected_addr = 0xdeadbeef;
        let section = Section::with_endian(Endian::Little)
            .D8(constants::DW_CFA_set_loc.0)
            .uleb(expected_addr)
            .append_bytes(&expected_rest);
        let contents = section.get_contents().unwrap();
        let input = &mut EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok(CallFrameInstruction::SetLoc { address: expected_addr }));
        assert_eq!(*input, EndianBuf::new(&expected_rest));
    }

    #[test]
    fn test_parse_cfi_instruction_advance_loc1() {
        let expected_rest = [1, 2, 3, 4];
        let expected_delta = 8;
        let section = Section::with_endian(Endian::Little)
            .D8(constants::DW_CFA_advance_loc1.0)
            .D8(expected_delta)
            .append_bytes(&expected_rest);
        let contents = section.get_contents().unwrap();
        let input = &mut EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok(CallFrameInstruction::AdvanceLoc { delta: expected_delta as u32 }));
        assert_eq!(*input, EndianBuf::new(&expected_rest));
    }

    #[test]
    fn test_parse_cfi_instruction_advance_loc2() {
        let expected_rest = [1, 2, 3, 4];
        let expected_delta = 500;
        let section = Section::with_endian(Endian::Little)
            .D8(constants::DW_CFA_advance_loc2.0)
            .L16(expected_delta)
            .append_bytes(&expected_rest);
        let contents = section.get_contents().unwrap();
        let input = &mut EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok(CallFrameInstruction::AdvanceLoc { delta: expected_delta as u32 }));
        assert_eq!(*input, EndianBuf::new(&expected_rest));
    }

    #[test]
    fn test_parse_cfi_instruction_advance_loc4() {
        let expected_rest = [1, 2, 3, 4];
        let expected_delta = 1 << 20;
        let section = Section::with_endian(Endian::Little)
            .D8(constants::DW_CFA_advance_loc4.0)
            .L32(expected_delta)
            .append_bytes(&expected_rest);
        let contents = section.get_contents().unwrap();
        let input = &mut EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok(CallFrameInstruction::AdvanceLoc { delta: expected_delta }));
        assert_eq!(*input, EndianBuf::new(&expected_rest));
    }

    #[test]
    fn test_parse_cfi_instruction_offset_extended() {
        let expected_rest = [1, 2, 3, 4];
        let expected_reg = 7;
        let expected_offset = 33;
        let section = Section::with_endian(Endian::Little)
            .D8(constants::DW_CFA_offset_extended.0)
            .uleb(expected_reg)
            .uleb(expected_offset)
            .append_bytes(&expected_rest);
        let contents = section.get_contents().unwrap();
        let input = &mut EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok(CallFrameInstruction::Offset {
                          register: expected_reg as u8,
                          factored_offset: expected_offset,
                      }));
        assert_eq!(*input, EndianBuf::new(&expected_rest));
    }

    #[test]
    fn test_parse_cfi_instruction_restore_extended() {
        let expected_rest = [1, 2, 3, 4];
        let expected_reg = 7;
        let section = Section::with_endian(Endian::Little)
            .D8(constants::DW_CFA_restore_extended.0)
            .uleb(expected_reg)
            .append_bytes(&expected_rest);
        let contents = section.get_contents().unwrap();
        let input = &mut EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok(CallFrameInstruction::Restore { register: expected_reg as u8 }));
        assert_eq!(*input, EndianBuf::new(&expected_rest));
    }

    #[test]
    fn test_parse_cfi_instruction_undefined() {
        let expected_rest = [1, 2, 3, 4];
        let expected_reg = 7;
        let section = Section::with_endian(Endian::Little)
            .D8(constants::DW_CFA_undefined.0)
            .uleb(expected_reg)
            .append_bytes(&expected_rest);
        let contents = section.get_contents().unwrap();
        let input = &mut EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok(CallFrameInstruction::Undefined { register: expected_reg as u8 }));
        assert_eq!(*input, EndianBuf::new(&expected_rest));
    }

    #[test]
    fn test_parse_cfi_instruction_same_value() {
        let expected_rest = [1, 2, 3, 4];
        let expected_reg = 7;
        let section = Section::with_endian(Endian::Little)
            .D8(constants::DW_CFA_same_value.0)
            .uleb(expected_reg)
            .append_bytes(&expected_rest);
        let contents = section.get_contents().unwrap();
        let input = &mut EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok(CallFrameInstruction::SameValue { register: expected_reg as u8 }));
        assert_eq!(*input, EndianBuf::new(&expected_rest));
    }

    #[test]
    fn test_parse_cfi_instruction_register() {
        let expected_rest = [1, 2, 3, 4];
        let expected_dest_reg = 7;
        let expected_src_reg = 8;
        let section = Section::with_endian(Endian::Little)
            .D8(constants::DW_CFA_register.0)
            .uleb(expected_dest_reg)
            .uleb(expected_src_reg)
            .append_bytes(&expected_rest);
        let contents = section.get_contents().unwrap();
        let input = &mut EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok(CallFrameInstruction::Register {
                          dest_register: expected_dest_reg as u8,
                          src_register: expected_src_reg as u8,
                      }));
        assert_eq!(*input, EndianBuf::new(&expected_rest));
    }

    #[test]
    fn test_parse_cfi_instruction_remember_state() {
        let expected_rest = [1, 2, 3, 4];
        let section = Section::with_endian(Endian::Little)
            .D8(constants::DW_CFA_remember_state.0)
            .append_bytes(&expected_rest);
        let contents = section.get_contents().unwrap();
        let input = &mut EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok(CallFrameInstruction::RememberState));
        assert_eq!(*input, EndianBuf::new(&expected_rest));
    }

    #[test]
    fn test_parse_cfi_instruction_restore_state() {
        let expected_rest = [1, 2, 3, 4];
        let section = Section::with_endian(Endian::Little)
            .D8(constants::DW_CFA_restore_state.0)
            .append_bytes(&expected_rest);
        let contents = section.get_contents().unwrap();
        let input = &mut EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok(CallFrameInstruction::RestoreState));
        assert_eq!(*input, EndianBuf::new(&expected_rest));
    }

    #[test]
    fn test_parse_cfi_instruction_def_cfa() {
        let expected_rest = [1, 2, 3, 4];
        let expected_reg = 2;
        let expected_offset = 0;
        let section = Section::with_endian(Endian::Little)
            .D8(constants::DW_CFA_def_cfa.0)
            .uleb(expected_reg)
            .uleb(expected_offset)
            .append_bytes(&expected_rest);
        let contents = section.get_contents().unwrap();
        let input = &mut EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok(CallFrameInstruction::DefCfa {
                          register: expected_reg as u8,
                          offset: expected_offset,
                      }));
        assert_eq!(*input, EndianBuf::new(&expected_rest));
    }

    #[test]
    fn test_parse_cfi_instruction_def_cfa_register() {
        let expected_rest = [1, 2, 3, 4];
        let expected_reg = 2;
        let section = Section::with_endian(Endian::Little)
            .D8(constants::DW_CFA_def_cfa_register.0)
            .uleb(expected_reg)
            .append_bytes(&expected_rest);
        let contents = section.get_contents().unwrap();
        let input = &mut EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok(CallFrameInstruction::DefCfaRegister { register: expected_reg as u8 }));
        assert_eq!(*input, EndianBuf::new(&expected_rest));
    }

    #[test]
    fn test_parse_cfi_instruction_def_cfa_offset() {
        let expected_rest = [1, 2, 3, 4];
        let expected_offset = 23;
        let section = Section::with_endian(Endian::Little)
            .D8(constants::DW_CFA_def_cfa_offset.0)
            .uleb(expected_offset)
            .append_bytes(&expected_rest);
        let contents = section.get_contents().unwrap();
        let input = &mut EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok(CallFrameInstruction::DefCfaOffset { offset: expected_offset }));
        assert_eq!(*input, EndianBuf::new(&expected_rest));
    }

    #[test]
    fn test_parse_cfi_instruction_def_cfa_expression() {
        let expected_rest = [1, 2, 3, 4];
        let expected_expr = [10, 9, 8, 7, 6, 5, 4, 3, 2, 1];

        let length = Label::new();
        let start = Label::new();
        let end = Label::new();

        let section = Section::with_endian(Endian::Little)
            .D8(constants::DW_CFA_def_cfa_expression.0)
            .D8(&length)
            .mark(&start)
            .append_bytes(&expected_expr)
            .mark(&end)
            .append_bytes(&expected_rest);

        length.set_const((&end - &start) as u64);
        let contents = section.get_contents().unwrap();
        let input = &mut EndianBuf::<LittleEndian>::new(&contents);

        assert_eq!(CallFrameInstruction::parse(input),
                   Ok(CallFrameInstruction::DefCfaExpression {
                          expression: EndianBuf::new(&expected_expr),
                      }));
        assert_eq!(*input, EndianBuf::new(&expected_rest));
    }

    #[test]
    fn test_parse_cfi_instruction_expression() {
        let expected_rest = [1, 2, 3, 4];
        let expected_reg = 99;
        let expected_expr = [10, 9, 8, 7, 6, 5, 4, 3, 2, 1];

        let length = Label::new();
        let start = Label::new();
        let end = Label::new();

        let section = Section::with_endian(Endian::Little)
            .D8(constants::DW_CFA_expression.0)
            .uleb(expected_reg)
            .D8(&length)
            .mark(&start)
            .append_bytes(&expected_expr)
            .mark(&end)
            .append_bytes(&expected_rest);

        length.set_const((&end - &start) as u64);
        let contents = section.get_contents().unwrap();
        let input = &mut EndianBuf::<LittleEndian>::new(&contents);

        assert_eq!(CallFrameInstruction::parse(input),
                   Ok(CallFrameInstruction::Expression {
                          register: expected_reg as u8,
                          expression: EndianBuf::new(&expected_expr),
                      }));
        assert_eq!(*input, EndianBuf::new(&expected_rest));
    }

    #[test]
    fn test_parse_cfi_instruction_offset_extended_sf() {
        let expected_rest = [1, 2, 3, 4];
        let expected_reg = 7;
        let expected_offset = -33;
        let section = Section::with_endian(Endian::Little)
            .D8(constants::DW_CFA_offset_extended_sf.0)
            .uleb(expected_reg)
            .sleb(expected_offset)
            .append_bytes(&expected_rest);
        let contents = section.get_contents().unwrap();
        let input = &mut EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok(CallFrameInstruction::OffsetExtendedSf {
                          register: expected_reg as u8,
                          factored_offset: expected_offset,
                      }));
        assert_eq!(*input, EndianBuf::new(&expected_rest));
    }

    #[test]
    fn test_parse_cfi_instruction_def_cfa_sf() {
        let expected_rest = [1, 2, 3, 4];
        let expected_reg = 2;
        let expected_offset = -9999;
        let section = Section::with_endian(Endian::Little)
            .D8(constants::DW_CFA_def_cfa_sf.0)
            .uleb(expected_reg)
            .sleb(expected_offset)
            .append_bytes(&expected_rest);
        let contents = section.get_contents().unwrap();
        let input = &mut EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok(CallFrameInstruction::DefCfaSf {
                          register: expected_reg as u8,
                          factored_offset: expected_offset,
                      }));
        assert_eq!(*input, EndianBuf::new(&expected_rest));
    }

    #[test]
    fn test_parse_cfi_instruction_def_cfa_offset_sf() {
        let expected_rest = [1, 2, 3, 4];
        let expected_offset = -123;
        let section = Section::with_endian(Endian::Little)
            .D8(constants::DW_CFA_def_cfa_offset_sf.0)
            .sleb(expected_offset)
            .append_bytes(&expected_rest);
        let contents = section.get_contents().unwrap();
        let input = &mut EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok(CallFrameInstruction::DefCfaOffsetSf { factored_offset: expected_offset }));
        assert_eq!(*input, EndianBuf::new(&expected_rest));
    }

    #[test]
    fn test_parse_cfi_instruction_val_offset() {
        let expected_rest = [1, 2, 3, 4];
        let expected_reg = 50;
        let expected_offset = 23;
        let section = Section::with_endian(Endian::Little)
            .D8(constants::DW_CFA_val_offset.0)
            .uleb(expected_reg)
            .uleb(expected_offset)
            .append_bytes(&expected_rest);
        let contents = section.get_contents().unwrap();
        let input = &mut EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok(CallFrameInstruction::ValOffset {
                          register: expected_reg as u8,
                          factored_offset: expected_offset,
                      }));
        assert_eq!(*input, EndianBuf::new(&expected_rest));
    }

    #[test]
    fn test_parse_cfi_instruction_val_offset_sf() {
        let expected_rest = [1, 2, 3, 4];
        let expected_reg = 50;
        let expected_offset = -23;
        let section = Section::with_endian(Endian::Little)
            .D8(constants::DW_CFA_val_offset_sf.0)
            .uleb(expected_reg)
            .sleb(expected_offset)
            .append_bytes(&expected_rest);
        let contents = section.get_contents().unwrap();
        let input = &mut EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok(CallFrameInstruction::ValOffsetSf {
                          register: expected_reg as u8,
                          factored_offset: expected_offset,
                      }));
        assert_eq!(*input, EndianBuf::new(&expected_rest));
    }

    #[test]
    fn test_parse_cfi_instruction_val_expression() {
        let expected_rest = [1, 2, 3, 4];
        let expected_reg = 50;
        let expected_expr = [2, 2, 1, 1, 5, 5];

        let length = Label::new();
        let start = Label::new();
        let end = Label::new();

        let section = Section::with_endian(Endian::Little)
            .D8(constants::DW_CFA_val_expression.0)
            .uleb(expected_reg)
            .D8(&length)
            .mark(&start)
            .append_bytes(&expected_expr)
            .mark(&end)
            .append_bytes(&expected_rest);

        length.set_const((&end - &start) as u64);
        let contents = section.get_contents().unwrap();
        let input = &mut EndianBuf::<LittleEndian>::new(&contents);

        assert_eq!(CallFrameInstruction::parse(input),
                   Ok(CallFrameInstruction::ValExpression {
                          register: expected_reg as u8,
                          expression: EndianBuf::new(&expected_expr),
                      }));
        assert_eq!(*input, EndianBuf::new(&expected_rest));
    }

    #[test]
    fn test_parse_cfi_instruction_unknown_instruction() {
        let expected_rest = [1, 2, 3, 4];
        let unknown_instr = constants::DwCfa(0b00111111);
        let section = Section::with_endian(Endian::Little)
            .D8(unknown_instr.0)
            .append_bytes(&expected_rest);
        let contents = section.get_contents().unwrap();
        let input = &mut EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Err(Error::UnknownCallFrameInstruction(unknown_instr)));
    }

    #[test]
    fn test_call_frame_instruction_iter_ok() {
        let expected_reg = 50;
        let expected_expr = [2, 2, 1, 1, 5, 5];
        let expected_delta = 230;

        let length = Label::new();
        let start = Label::new();
        let end = Label::new();

        let section = Section::with_endian(Endian::Big)
            .D8(constants::DW_CFA_val_expression.0)
            .uleb(expected_reg)
            .D8(&length)
            .mark(&start)
            .append_bytes(&expected_expr)
            .mark(&end)
            .D8(constants::DW_CFA_advance_loc1.0)
            .D8(expected_delta);

        length.set_const((&end - &start) as u64);
        let contents = section.get_contents().unwrap();
        let input = EndianBuf::<BigEndian>::new(&contents);
        let mut iter = CallFrameInstructionIter { input: input };

        assert_eq!(iter.next(),
                   Ok(Some(CallFrameInstruction::ValExpression {
                               register: expected_reg as u8,
                               expression: EndianBuf::new(&expected_expr),
                           })));

        assert_eq!(iter.next(),
                   Ok(Some(CallFrameInstruction::AdvanceLoc { delta: expected_delta as u32 })));

        assert_eq!(iter.next(), Ok(None));
    }

    #[test]
    fn test_call_frame_instruction_iter_err() {
        // DW_CFA_advance_loc1 without an operand.
        let section = Section::with_endian(Endian::Big).D8(constants::DW_CFA_advance_loc1.0);

        let contents = section.get_contents().unwrap();
        let input = EndianBuf::<BigEndian>::new(&contents);
        let mut iter = CallFrameInstructionIter { input: input };

        assert_eq!(iter.next(), Err(Error::UnexpectedEof));
        assert_eq!(iter.next(), Ok(None));
    }

    fn assert_eval<'a, I, T>(mut initial_ctx: UnwindContext<'a, LittleEndian, T>,
                             expected_ctx: UnwindContext<'a, LittleEndian, T>,
                             cie: CommonInformationEntry<'a, LittleEndian, T>,
                             fde: Option<FrameDescriptionEntry<'a, LittleEndian, T>>,
                             instructions: I)
        where I: AsRef<[(Result<bool>, CallFrameInstruction<'a, LittleEndian>)]>,
              T: UnwindSection<'a, LittleEndian>
    {
        {
            let mut table = UnwindTable::new_internal(&mut initial_ctx, &cie, fde.as_ref());
            for &(ref expected_result, ref instruction) in instructions.as_ref() {
                assert_eq!(*expected_result, table.evaluate(instruction.clone()));
            }
        }

        assert_eq!(expected_ctx, initial_ctx);
    }

    fn make_test_cie<'a, Section>() -> CommonInformationEntry<'a, LittleEndian, Section>
        where Section: UnwindSection<'a, LittleEndian>
    {
        CommonInformationEntry {
            format: Format::Dwarf64,
            length: 0,
            return_address_register: 0,
            version: 4,
            address_size: mem::size_of::<usize>() as u8,
            initial_instructions: EndianBuf::new(&[]),
            augmentation: None,
            segment_size: 0,
            data_alignment_factor: 2,
            code_alignment_factor: 3,
            phantom: PhantomData,
        }
    }

    #[test]
    fn test_eval_set_loc() {
        let cie: DebugFrameCie<_> = make_test_cie();
        let ctx = UnwindContext::new();
        let mut expected = ctx.clone();
        expected.row_mut().end_address = 42;
        let instructions = [(Ok(true), CallFrameInstruction::SetLoc { address: 42 })];
        assert_eval(ctx, expected, cie, None, instructions);
    }

    #[test]
    fn test_eval_set_loc_backwards() {
        let cie: DebugFrameCie<_> = make_test_cie();
        let mut ctx = UnwindContext::new();
        ctx.row_mut().start_address = 999;
        let expected = ctx.clone();
        let instructions = [(Err(Error::InvalidAddressRange),
                             CallFrameInstruction::SetLoc { address: 42 })];
        assert_eval(ctx, expected, cie, None, instructions);
    }

    #[test]
    fn test_eval_advance_loc() {
        let cie: DebugFrameCie<_> = make_test_cie();
        let mut ctx = UnwindContext::new();
        ctx.row_mut().start_address = 3;
        let mut expected = ctx.clone();
        expected.row_mut().end_address = 4;
        let instructions = [(Ok(true), CallFrameInstruction::AdvanceLoc { delta: 1 })];
        assert_eval(ctx, expected, cie, None, instructions);
    }

    #[test]
    fn test_eval_def_cfa() {
        let cie: DebugFrameCie<_> = make_test_cie();
        let ctx = UnwindContext::new();
        let mut expected = ctx.clone();
        expected.set_cfa(CfaRule::RegisterAndOffset {
                             register: 42,
                             offset: 36,
                         });
        let instructions = [(Ok(false),
                             CallFrameInstruction::DefCfa {
                                 register: 42,
                                 offset: 36,
                             })];
        assert_eval(ctx, expected, cie, None, instructions);
    }

    #[test]
    fn test_eval_def_cfa_sf() {
        let cie: DebugFrameCie<_> = make_test_cie();
        let ctx = UnwindContext::new();
        let mut expected = ctx.clone();
        expected.set_cfa(CfaRule::RegisterAndOffset {
                             register: 42,
                             offset: 36 * cie.data_alignment_factor as i64,
                         });
        let instructions = [(Ok(false),
                             CallFrameInstruction::DefCfaSf {
                                 register: 42,
                                 factored_offset: 36,
                             })];
        assert_eval(ctx, expected, cie, None, instructions);
    }

    #[test]
    fn test_eval_def_cfa_register() {
        let cie: DebugFrameCie<_> = make_test_cie();
        let mut ctx = UnwindContext::new();
        ctx.set_cfa(CfaRule::RegisterAndOffset {
                        register: 3,
                        offset: 8,
                    });
        let mut expected = ctx.clone();
        expected.set_cfa(CfaRule::RegisterAndOffset {
                             register: 42,
                             offset: 8,
                         });
        let instructions = [(Ok(false), CallFrameInstruction::DefCfaRegister { register: 42 })];
        assert_eval(ctx, expected, cie, None, instructions);
    }

    #[test]
    fn test_eval_def_cfa_register_invalid_context() {
        let cie: DebugFrameCie<_> = make_test_cie();
        let mut ctx = UnwindContext::new();
        ctx.set_cfa(CfaRule::Expression(EndianBuf::new(&[])));
        let expected = ctx.clone();
        let instructions = [(Err(Error::CfiInstructionInInvalidContext),
                             CallFrameInstruction::DefCfaRegister { register: 42 })];
        assert_eval(ctx, expected, cie, None, instructions);
    }

    #[test]
    fn test_eval_def_cfa_offset() {
        let cie: DebugFrameCie<_> = make_test_cie();
        let mut ctx = UnwindContext::new();
        ctx.set_cfa(CfaRule::RegisterAndOffset {
                        register: 3,
                        offset: 8,
                    });
        let mut expected = ctx.clone();
        expected.set_cfa(CfaRule::RegisterAndOffset {
                             register: 3,
                             offset: 42,
                         });
        let instructions = [(Ok(false), CallFrameInstruction::DefCfaOffset { offset: 42 })];
        assert_eval(ctx, expected, cie, None, instructions);
    }

    #[test]
    fn test_eval_def_cfa_offset_invalid_context() {
        let cie: DebugFrameCie<_> = make_test_cie();
        let mut ctx = UnwindContext::new();
        ctx.set_cfa(CfaRule::Expression(EndianBuf::new(&[])));
        let expected = ctx.clone();
        let instructions = [(Err(Error::CfiInstructionInInvalidContext),
                             CallFrameInstruction::DefCfaOffset { offset: 1993 })];
        assert_eval(ctx, expected, cie, None, instructions);
    }

    #[test]
    fn test_eval_def_cfa_expression() {
        let expr = [1, 2, 3, 4];
        let cie: DebugFrameCie<_> = make_test_cie();
        let ctx = UnwindContext::new();
        let mut expected = ctx.clone();
        expected.set_cfa(CfaRule::Expression(EndianBuf::new(&expr)));
        let instructions =
            [(Ok(false),
              CallFrameInstruction::DefCfaExpression { expression: EndianBuf::new(&expr) })];
        assert_eval(ctx, expected, cie, None, instructions);
    }

    #[test]
    fn test_eval_undefined() {
        let cie: DebugFrameCie<_> = make_test_cie();
        let ctx = UnwindContext::new();
        let mut expected = ctx.clone();
        expected
            .set_register_rule(5, RegisterRule::Undefined)
            .unwrap();
        let instructions = [(Ok(false), CallFrameInstruction::Undefined { register: 5 })];
        assert_eval(ctx, expected, cie, None, instructions);
    }

    #[test]
    fn test_eval_same_value() {
        let cie: DebugFrameCie<_> = make_test_cie();
        let ctx = UnwindContext::new();
        let mut expected = ctx.clone();
        expected
            .set_register_rule(0, RegisterRule::SameValue)
            .unwrap();
        let instructions = [(Ok(false), CallFrameInstruction::SameValue { register: 0 })];
        assert_eval(ctx, expected, cie, None, instructions);
    }

    #[test]
    fn test_eval_offset() {
        let cie: DebugFrameCie<_> = make_test_cie();
        let ctx = UnwindContext::new();
        let mut expected = ctx.clone();
        expected
            .set_register_rule(2, RegisterRule::Offset(3 * cie.data_alignment_factor))
            .unwrap();
        let instructions = [(Ok(false),
                             CallFrameInstruction::Offset {
                                 register: 2,
                                 factored_offset: 3,
                             })];
        assert_eval(ctx, expected, cie, None, instructions);
    }

    #[test]
    fn test_eval_offset_extended_sf() {
        let cie: DebugFrameCie<_> = make_test_cie();
        let ctx = UnwindContext::new();
        let mut expected = ctx.clone();
        expected
            .set_register_rule(4, RegisterRule::Offset(-3 * cie.data_alignment_factor))
            .unwrap();
        let instructions = [(Ok(false),
                             CallFrameInstruction::OffsetExtendedSf {
                                 register: 4,
                                 factored_offset: -3,
                             })];
        assert_eval(ctx, expected, cie, None, instructions);
    }

    #[test]
    fn test_eval_val_offset() {
        let cie: DebugFrameCie<_> = make_test_cie();
        let ctx = UnwindContext::new();
        let mut expected = ctx.clone();
        expected
            .set_register_rule(5, RegisterRule::ValOffset(7 * cie.data_alignment_factor))
            .unwrap();
        let instructions = [(Ok(false),
                             CallFrameInstruction::ValOffset {
                                 register: 5,
                                 factored_offset: 7,
                             })];
        assert_eval(ctx, expected, cie, None, instructions);
    }

    #[test]
    fn test_eval_val_offset_sf() {
        let cie: DebugFrameCie<_> = make_test_cie();
        let ctx = UnwindContext::new();
        let mut expected = ctx.clone();
        expected
            .set_register_rule(5, RegisterRule::ValOffset(-7 * cie.data_alignment_factor))
            .unwrap();
        let instructions = [(Ok(false),
                             CallFrameInstruction::ValOffsetSf {
                                 register: 5,
                                 factored_offset: -7,
                             })];
        assert_eval(ctx, expected, cie, None, instructions);
    }

    #[test]
    fn test_eval_expression() {
        let expr = [1, 2, 3, 4];
        let cie: DebugFrameCie<_> = make_test_cie();
        let ctx = UnwindContext::new();
        let mut expected = ctx.clone();
        expected
            .set_register_rule(9, RegisterRule::Expression(EndianBuf::new(&expr)))
            .unwrap();
        let instructions = [(Ok(false),
                             CallFrameInstruction::Expression {
                                 register: 9,
                                 expression: EndianBuf::new(&expr),
                             })];
        assert_eval(ctx, expected, cie, None, instructions);
    }

    #[test]
    fn test_eval_val_expression() {
        let expr = [1, 2, 3, 4];
        let cie: DebugFrameCie<_> = make_test_cie();
        let ctx = UnwindContext::new();
        let mut expected = ctx.clone();
        expected
            .set_register_rule(9, RegisterRule::ValExpression(EndianBuf::new(&expr)))
            .unwrap();
        let instructions = [(Ok(false),
                             CallFrameInstruction::ValExpression {
                                 register: 9,
                                 expression: EndianBuf::new(&expr),
                             })];
        assert_eval(ctx, expected, cie, None, instructions);
    }

    #[test]
    fn test_eval_restore() {
        let cie: DebugFrameCie<_> = make_test_cie();
        let fde = DebugFrameFde {
            format: Format::Dwarf64,
            length: 0,
            address_range: 0,
            augmentation: None,
            initial_address: 0,
            initial_segment: 0,
            cie: cie.clone(),
            instructions: EndianBuf::new(&[]),
        };

        let mut ctx = UnwindContext::new();
        ctx.set_register_rule(0, RegisterRule::Offset(1)).unwrap();
        ctx.save_initial_rules();
        let expected = ctx.clone();
        ctx.set_register_rule(0, RegisterRule::Offset(2)).unwrap();

        let instructions = [(Ok(false), CallFrameInstruction::Restore { register: 0 })];
        assert_eval(ctx, expected, cie, Some(fde), instructions);
    }

    #[test]
    fn test_eval_restore_havent_saved_initial_context() {
        let cie: DebugFrameCie<_> = make_test_cie();
        let ctx = UnwindContext::new();
        let expected = ctx.clone();
        let instructions = [(Err(Error::CfiInstructionInInvalidContext),
                             CallFrameInstruction::Restore { register: 0 })];
        assert_eval(ctx, expected, cie, None, instructions);
    }

    #[test]
    fn test_eval_remember_state() {
        let cie: DebugFrameCie<_> = make_test_cie();
        let ctx = UnwindContext::new();
        let mut expected = ctx.clone();
        expected.push_row().unwrap();
        let instructions = [(Ok(false), CallFrameInstruction::RememberState)];
        assert_eval(ctx, expected, cie, None, instructions);
    }

    #[test]
    fn test_eval_restore_state() {
        let cie: DebugFrameCie<_> = make_test_cie();

        let mut ctx = UnwindContext::new();
        ctx.set_register_rule(0, RegisterRule::SameValue).unwrap();
        let expected = ctx.clone();
        ctx.push_row().unwrap();
        ctx.set_register_rule(0, RegisterRule::Offset(16)).unwrap();

        let instructions = [// First one pops just fine.
                            (Ok(false), CallFrameInstruction::RestoreState),
                            // Second pop would try to pop out of bounds.
                            (Err(Error::PopWithEmptyStack), CallFrameInstruction::RestoreState)];

        assert_eval(ctx, expected, cie, None, instructions);
    }

    #[test]
    fn test_eval_nop() {
        let cie: DebugFrameCie<_> = make_test_cie();
        let ctx = UnwindContext::new();
        let expected = ctx.clone();
        let instructions = [(Ok(false), CallFrameInstruction::Nop)];
        assert_eval(ctx, expected, cie, None, instructions);
    }

    #[test]
    fn test_unwind_table_next_row() {
        let initial_instructions = Section::with_endian(Endian::Little)
            // The CFA is -12 from register 4.
            .D8(constants::DW_CFA_def_cfa_sf.0)
            .uleb(4)
            .sleb(-12)
            // Register 0 is 8 from the CFA.
            .D8(constants::DW_CFA_offset.0 | 0)
            .uleb(8)
            // Register 3 is 4 from the CFA.
            .D8(constants::DW_CFA_offset.0 | 3)
            .uleb(4)
            .append_repeated(constants::DW_CFA_nop.0, 4);
        let initial_instructions = initial_instructions.get_contents().unwrap();

        let cie = DebugFrameCie {
            length: 0,
            format: Format::Dwarf32,
            version: 4,
            augmentation: None,
            address_size: 4,
            segment_size: 0,
            code_alignment_factor: 1,
            data_alignment_factor: 1,
            return_address_register: 3,
            initial_instructions: EndianBuf::<LittleEndian>::new(&initial_instructions),
            phantom: PhantomData,
        };

        let instructions = Section::with_endian(Endian::Little)
            // Initial instructions form a row, advance the address by 1.
            .D8(constants::DW_CFA_advance_loc1.0)
            .D8(1)
            // Register 0 is -16 from the CFA.
            .D8(constants::DW_CFA_offset_extended_sf.0)
            .uleb(0)
            .sleb(-16)
            // Finish this row, advance the address by 32.
            .D8(constants::DW_CFA_advance_loc1.0)
            .D8(32)
            // Register 3 is -4 from the CFA.
            .D8(constants::DW_CFA_offset_extended_sf.0)
            .uleb(3)
            .sleb(-4)
            // Finish this row, advance the address by 64.
            .D8(constants::DW_CFA_advance_loc1.0)
            .D8(64)
            // Register 5 is 4 from the CFA.
            .D8(constants::DW_CFA_offset.0 | 5)
            .uleb(4)
            // A bunch of nop padding.
            .append_repeated(constants::DW_CFA_nop.0, 8);
        let instructions = instructions.get_contents().unwrap();

        let fde = DebugFrameFde {
            length: 0,
            format: Format::Dwarf32,
            cie: cie.clone(),
            initial_segment: 0,
            initial_address: 0,
            address_range: 100,
            augmentation: None,
            instructions: EndianBuf::<LittleEndian>::new(&instructions),
        };

        let ctx = UninitializedUnwindContext::new();
        ctx.0.assert_fully_uninitialized();
        let mut ctx = ctx.initialize(&cie).expect("Should run initial program OK");

        assert!(ctx.0.is_initialized);
        let expected_initial_rules: RegisterRuleMap<_> = [(0, RegisterRule::Offset(8)),
                                                          (3, RegisterRule::Offset(4))]
            .into_iter()
            .collect();
        assert_eq!(ctx.0.initial_rules, expected_initial_rules);

        let mut table = UnwindTable::new(&mut ctx, &fde);

        {
            let row = table.next_row().expect("Should evaluate first row OK");
            let expected = UnwindTableRow {
                start_address: 0,
                end_address: 1,
                cfa: CfaRule::RegisterAndOffset {
                    register: 4,
                    offset: -12,
                },
                registers: [(0, RegisterRule::Offset(8)), (3, RegisterRule::Offset(4))]
                    .into_iter()
                    .collect(),
            };
            assert_eq!(Some(&expected), row);
        }

        {
            let row = table.next_row().expect("Should evaluate second row OK");
            let expected = UnwindTableRow {
                start_address: 1,
                end_address: 33,
                cfa: CfaRule::RegisterAndOffset {
                    register: 4,
                    offset: -12,
                },
                registers: [(0, RegisterRule::Offset(-16)), (3, RegisterRule::Offset(4))]
                    .into_iter()
                    .collect(),
            };
            assert_eq!(Some(&expected), row);
        }

        {
            let row = table.next_row().expect("Should evaluate third row OK");
            let expected = UnwindTableRow {
                start_address: 33,
                end_address: 97,
                cfa: CfaRule::RegisterAndOffset {
                    register: 4,
                    offset: -12,
                },
                registers: [(0, RegisterRule::Offset(-16)),
                            (3, RegisterRule::Offset(-4))]
                    .into_iter()
                    .collect(),
            };
            assert_eq!(Some(&expected), row);
        }

        {
            let row = table.next_row().expect("Should evaluate fourth row OK");
            let expected = UnwindTableRow {
                start_address: 97,
                end_address: 100,
                cfa: CfaRule::RegisterAndOffset {
                    register: 4,
                    offset: -12,
                },
                registers: [(0, RegisterRule::Offset(-16)),
                            (3, RegisterRule::Offset(-4)),
                            (5, RegisterRule::Offset(4))]
                    .into_iter()
                    .collect(),
            };
            assert_eq!(Some(&expected), row);
        }

        // All done!
        assert_eq!(Ok(None), table.next_row());
        assert_eq!(Ok(None), table.next_row());
    }

    #[test]
    fn test_unwind_info_for_address_ok() {
        let instrs1 = Section::with_endian(Endian::Big)
            // The CFA is -12 from register 4.
            .D8(constants::DW_CFA_def_cfa_sf.0)
            .uleb(4)
            .sleb(-12);
        let instrs1 = instrs1.get_contents().unwrap();

        let instrs2: Vec<_> = (0..8).map(|_| constants::DW_CFA_nop.0).collect();

        let instrs3 = Section::with_endian(Endian::Big)
            // Initial instructions form a row, advance the address by 100.
            .D8(constants::DW_CFA_advance_loc1.0)
            .D8(100)
            // Register 0 is -16 from the CFA.
            .D8(constants::DW_CFA_offset_extended_sf.0)
            .uleb(0)
            .sleb(-16);
        let instrs3 = instrs3.get_contents().unwrap();

        let instrs4: Vec<_> = (0..16).map(|_| constants::DW_CFA_nop.0).collect();

        let mut cie1 = DebugFrameCie {
            length: 0,
            format: Format::Dwarf32,
            version: 4,
            augmentation: None,
            address_size: 4,
            segment_size: 0,
            code_alignment_factor: 1,
            data_alignment_factor: 1,
            return_address_register: 3,
            initial_instructions: EndianBuf::new(&instrs1),
            phantom: PhantomData,
        };

        let mut cie2 = DebugFrameCie {
            length: 0,
            format: Format::Dwarf32,
            version: 4,
            augmentation: None,
            address_size: 4,
            segment_size: 0,
            code_alignment_factor: 1,
            data_alignment_factor: 1,
            return_address_register: 1,
            initial_instructions: EndianBuf::new(&instrs2),
            phantom: PhantomData,
        };

        let cie1_location = Label::new();
        let cie2_location = Label::new();

        // Write the CIEs first so that their length gets set before we clone
        // them into the FDEs and our equality assertions down the line end up
        // with all the CIEs always having he correct length.
        let section = Section::with_endian(Endian::Big)
            .mark(&cie1_location)
            .cie(Endian::Big, None, &mut cie1)
            .mark(&cie2_location)
            .cie(Endian::Big, None, &mut cie2);

        let mut fde1 = DebugFrameFde {
            length: 0,
            format: Format::Dwarf32,
            cie: cie1.clone(),
            initial_segment: 0,
            initial_address: 0xfeedbeef,
            address_range: 200,
            augmentation: None,
            instructions: EndianBuf::<BigEndian>::new(&instrs3),
        };

        let mut fde2 = DebugFrameFde {
            length: 0,
            format: Format::Dwarf32,
            cie: cie2.clone(),
            initial_segment: 0,
            initial_address: 0xfeedface,
            address_range: 9000,
            augmentation: None,
            instructions: EndianBuf::<BigEndian>::new(&instrs4),
        };

        let section = section
            .fde(Endian::Big, &cie1_location, &mut fde1)
            .fde(Endian::Big, &cie2_location, &mut fde2);
        section.start().set_const(0);

        let contents = section.get_contents().unwrap();
        let debug_frame = DebugFrame::<BigEndian>::new(&contents);

        // Get the second row of the unwind table in `instrs3`.
        let bases = Default::default();
        let ctx = UninitializedUnwindContext::new();
        let result = debug_frame.unwind_info_for_address(&bases, ctx, 0xfeedbeef + 150);
        assert!(result.is_ok());
        let (unwind_info, _) = result.unwrap();

        assert_eq!(unwind_info,
                   UnwindTableRow {
                       start_address: fde1.initial_address + 100,
                       end_address: fde1.initial_address + fde1.address_range,
                       cfa: CfaRule::RegisterAndOffset {
                           register: 4,
                           offset: -12,
                       },
                       registers: [(0, RegisterRule::Offset(-16))].into_iter().collect(),
                   });
    }

    #[test]
    fn test_unwind_info_for_address_not_found() {
        let debug_frame = DebugFrame::<NativeEndian>::new(&[]);
        let bases = Default::default();
        let ctx = UninitializedUnwindContext::new();
        let result = debug_frame.unwind_info_for_address(&bases, ctx, 0xbadbad99);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::NoUnwindInfoForAddress);
    }

    #[test]
    fn test_eh_frame_stops_at_zero_length() {
        let section = Section::with_endian(Endian::Little).L32(0);
        let section = section.get_contents().unwrap();
        let rest = &mut EndianBuf::<LittleEndian>::new(&section);
        let bases = Default::default();

        assert_eq!(parse_cfi_entry(&bases, EhFrame::new(&*section), rest),
                   Ok(None));

        assert_eq!(EhFrame::<LittleEndian>::new(&section)
                       .cie_from_offset(&bases, EhFrameOffset(0)),
                   Err(Error::NoEntryAtGivenOffset));
    }

    #[test]
    fn test_eh_frame_resolve_cie_offset_ok() {
        let buf = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let section = EhFrame::<BigEndian>::new(&buf);
        let subslice = EndianBuf::new(&buf[6..8]);
        assert_eq!(section.resolve_cie_offset(subslice, 4), Some(2));
    }

    #[test]
    fn test_eh_frame_resolve_cie_offset_out_of_bounds() {
        let buf = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let section = EhFrame::<BigEndian>::new(&buf);
        let subslice = EndianBuf::new(&buf[6..8]);
        assert_eq!(section.resolve_cie_offset(subslice, 7), None);
    }

    #[test]
    fn test_eh_frame_resolve_cie_offset_underflow() {
        let buf = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let section = EhFrame::<BigEndian>::new(&buf);
        let subslice = EndianBuf::new(&buf[6..8]);
        assert_eq!(section.resolve_cie_offset(subslice, ::std::usize::MAX),
                   None);
    }

    #[test]
    fn test_eh_frame_fde_ok() {
        let mut cie = make_test_cie();
        cie.format = Format::Dwarf32;
        cie.version = 1;

        let start_of_cie = Label::new();
        let end_of_cie = Label::new();

        // Write the CIE first so that its length gets set before we clone it
        // into the FDE.
        let section = Section::with_endian(Endian::Little)
            .append_repeated(0, 16)
            .mark(&start_of_cie)
            .cie(Endian::Little, None, &mut cie)
            .mark(&end_of_cie);

        let mut fde = EhFrameFde {
            length: 0,
            format: Format::Dwarf32,
            cie: cie.clone(),
            initial_segment: 0,
            initial_address: 0xfeedbeef,
            address_range: 999,
            augmentation: None,
            instructions: EndianBuf::new(&[]),
        };

        let section = section
            // +4 for the FDE length before the CIE offset.
            .fde(Endian::Little, (&end_of_cie - &start_of_cie + 4) as u64, &mut fde);

        section.start().set_const(0);
        let section = section.get_contents().unwrap();
        let section = EndianBuf::<LittleEndian>::new(&section);

        let mut offset = None;
        match parse_fde(EhFrame::new(section.into()),
                        &mut section.range_from(end_of_cie.value().unwrap() as usize..),
                        |o| {
                            offset = Some(o);
                            assert_eq!(o, EhFrameOffset(start_of_cie.value().unwrap() as usize));
                            Ok(cie.clone())
                        }) {
            Ok(actual) => assert_eq!(actual, fde),
            otherwise => panic!("Unexpected result {:?}", otherwise),
        }
        assert!(offset.is_some());
    }

    #[test]
    fn test_eh_frame_fde_out_of_bounds() {
        let mut cie = make_test_cie();
        cie.version = 1;

        let end_of_cie = Label::new();

        let mut fde = EhFrameFde {
            length: 0,
            format: Format::Dwarf64,
            cie: cie.clone(),
            initial_segment: 0,
            initial_address: 0xfeedbeef,
            address_range: 999,
            augmentation: None,
            instructions: EndianBuf::new(&[]),
        };

        let section = Section::with_endian(Endian::Little)
            .cie(Endian::Little, None, &mut cie)
            .mark(&end_of_cie)
            .fde(Endian::Little, 99999999999999, &mut fde);

        section.start().set_const(0);
        let section = section.get_contents().unwrap();
        let section = EndianBuf::<LittleEndian>::new(&section);

        let result = parse_fde(EhFrame::new(section.into()),
                               &mut section.range_from(end_of_cie.value().unwrap() as usize..),
                               |_| unreachable!());
        assert_eq!(result, Err(Error::OffsetOutOfBounds));
    }

    #[test]
    fn test_augmentation_parse_not_z_augmentation() {
        let augmentation = "wtf";
        let bases = Default::default();
        let address_size = 8;
        let section = EhFrame::<NativeEndian>::new(&[]);
        let input = &mut EndianBuf::new(&[]);
        assert_eq!(Augmentation::parse(augmentation, &bases, address_size, section, input),
                   Err(Error::UnknownAugmentation));
    }

    #[test]
    fn test_augmentation_parse_unknown_part_of_z_augmentation() {
        // The 'Z' character is not defined by the z-style augmentation.
        let augmentation = "zZ";
        let bases = Default::default();
        let address_size = 8;
        let section = Section::with_endian(Endian::Little)
            .uleb(4)
            .append_repeated(4, 4)
            .get_contents()
            .unwrap();
        let section = EhFrame::<LittleEndian>::new(&section);
        let input = &mut EndianBuf::new(section.section().into());
        assert_eq!(Augmentation::parse(augmentation, &bases, address_size, section, input),
                   Err(Error::UnknownAugmentation));
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_augmentation_parse_L() {
        let aug_str = "zL";
        let bases = Default::default();
        let address_size = 8;
        let rest = [9, 8, 7, 6, 5, 4, 3, 2, 1];

        let section = Section::with_endian(Endian::Little)
            .uleb(1)
            .D8(constants::DW_EH_PE_uleb128.0)
            .append_bytes(&rest)
            .get_contents()
            .unwrap();
        let section = EhFrame::<LittleEndian>::new(&section);
        let input = &mut EndianBuf::new(section.section().into());

        let mut augmentation = Augmentation::default();
        augmentation.lsda = Some(constants::DW_EH_PE_uleb128);

        assert_eq!(Augmentation::parse(aug_str, &bases, address_size, section, input),
                   Ok(augmentation));
        assert_eq!(*input, EndianBuf::new(&rest));
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_augmentation_parse_P() {
        let aug_str = "zP";
        let bases = Default::default();
        let address_size = 8;
        let rest = [9, 8, 7, 6, 5, 4, 3, 2, 1];

        let section = Section::with_endian(Endian::Little)
            .uleb(9)
            .D8(constants::DW_EH_PE_udata8.0)
            .L64(0xf00df00d)
            .append_bytes(&rest)
            .get_contents()
            .unwrap();
        let section = EhFrame::<LittleEndian>::new(&section);
        let input = &mut EndianBuf::new(section.section().into());

        let mut augmentation = Augmentation::default();
        augmentation.personality = Some(Pointer::Direct(0xf00df00d));

        assert_eq!(Augmentation::parse(aug_str, &bases, address_size, section, input),
                   Ok(augmentation));
        assert_eq!(*input, EndianBuf::new(&rest));
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_augmentation_parse_R() {
        let aug_str = "zR";
        let bases = Default::default();
        let address_size = 8;
        let rest = [9, 8, 7, 6, 5, 4, 3, 2, 1];

        let section = Section::with_endian(Endian::Little)
            .uleb(1)
            .D8(constants::DW_EH_PE_udata4.0)
            .append_bytes(&rest)
            .get_contents()
            .unwrap();
        let section = EhFrame::<LittleEndian>::new(&section);
        let input = &mut EndianBuf::new(section.section().into());

        let mut augmentation = Augmentation::default();
        augmentation.fde_address_encoding = Some(constants::DW_EH_PE_udata4);

        assert_eq!(Augmentation::parse(aug_str, &bases, address_size, section, input),
                   Ok(augmentation));
        assert_eq!(*input, EndianBuf::new(&rest));
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_augmentation_parse_S() {
        let aug_str = "zS";
        let bases = Default::default();
        let address_size = 8;
        let rest = [9, 8, 7, 6, 5, 4, 3, 2, 1];

        let section = Section::with_endian(Endian::Little)
            .uleb(0)
            .append_bytes(&rest)
            .get_contents()
            .unwrap();
        let section = EhFrame::<LittleEndian>::new(&section);
        let input = &mut EndianBuf::new(section.section().into());

        let mut augmentation = Augmentation::default();
        augmentation.is_signal_trampoline = true;

        assert_eq!(Augmentation::parse(aug_str, &bases, address_size, section, input),
                   Ok(augmentation));
        assert_eq!(*input, EndianBuf::new(&rest));
    }

    #[test]
    fn test_augmentation_parse_all() {
        let aug_str = "zLPRS";
        let bases = Default::default();
        let address_size = 8;
        let rest = [9, 8, 7, 6, 5, 4, 3, 2, 1];

        let section = Section::with_endian(Endian::Little)
            .uleb(1 + 9 + 1)
            // L
            .D8(constants::DW_EH_PE_uleb128.0)
            // P
            .D8(constants::DW_EH_PE_udata8.0)
            .L64(0x1badf00d)
            // R
            .D8(constants::DW_EH_PE_uleb128.0)
            .append_bytes(&rest)
            .get_contents()
            .unwrap();
        let section = EhFrame::<LittleEndian>::new(&section);
        let input = &mut EndianBuf::new(section.section().into());

        let augmentation = Augmentation {
            lsda: Some(constants::DW_EH_PE_uleb128),
            personality: Some(Pointer::Direct(0x1badf00d)),
            fde_address_encoding: Some(constants::DW_EH_PE_uleb128),
            is_signal_trampoline: true,
        };

        assert_eq!(Augmentation::parse(aug_str, &bases, address_size, section, input),
                   Ok(augmentation));
        assert_eq!(*input, EndianBuf::new(&rest));
    }

    #[test]
    fn test_eh_frame_fde_no_augmentation() {
        let instrs = [1, 2, 3, 4];
        let cie_offset = 1;

        let mut cie = make_test_cie();
        cie.format = Format::Dwarf32;
        cie.version = 1;

        let mut fde = EhFrameFde {
            length: 0,
            format: Format::Dwarf32,
            cie: cie.clone(),
            initial_segment: 0,
            initial_address: 0xfeedface,
            address_range: 9000,
            augmentation: None,
            instructions: EndianBuf::<LittleEndian>::new(&instrs),
        };

        let rest = [1, 2, 3, 4];

        let section = Section::with_endian(Endian::Little)
            .fde(Endian::Little, cie_offset, &mut fde)
            .append_bytes(&rest)
            .get_contents()
            .unwrap();
        let section = EhFrame::<LittleEndian>::new(&section);
        let input = &mut section.section();

        let result = parse_fde(section, input, |_| Ok(cie.clone()));
        assert_eq!(result, Ok(fde));
        assert_eq!(*input, EndianBuf::new(&rest));
    }

    #[test]
    fn test_eh_frame_fde_empty_augmentation() {
        let instrs = [1, 2, 3, 4];
        let cie_offset = 1;

        let mut cie = make_test_cie();
        cie.format = Format::Dwarf32;
        cie.version = 1;
        cie.augmentation = Some(Augmentation::default());

        let mut fde = EhFrameFde {
            length: 0,
            format: Format::Dwarf32,
            cie: cie.clone(),
            initial_segment: 0,
            initial_address: 0xfeedface,
            address_range: 9000,
            augmentation: Some(AugmentationData::default()),
            instructions: EndianBuf::<LittleEndian>::new(&instrs),
        };

        let rest = [1, 2, 3, 4];

        let section = Section::with_endian(Endian::Little)
            .fde(Endian::Little, cie_offset, &mut fde)
            .append_bytes(&rest)
            .get_contents()
            .unwrap();
        let section = EhFrame::<LittleEndian>::new(&section);
        let input = &mut section.section();

        let result = parse_fde(section, input, |_| Ok(cie.clone()));
        assert_eq!(result, Ok(fde));
        assert_eq!(*input, EndianBuf::new(&rest));
    }

    #[test]
    fn test_eh_frame_fde_lsda_augmentation() {
        let instrs = [1, 2, 3, 4];
        let cie_offset = 1;

        let mut cie = make_test_cie();
        cie.format = Format::Dwarf32;
        cie.version = 1;
        cie.augmentation = Some(Augmentation::default());
        cie.augmentation.as_mut().unwrap().lsda = Some(constants::DW_EH_PE_absptr);

        let mut fde = EhFrameFde {
            length: 0,
            format: Format::Dwarf32,
            cie: cie.clone(),
            initial_segment: 0,
            initial_address: 0xfeedface,
            address_range: 9000,
            augmentation: Some(AugmentationData { lsda: Some(Pointer::Direct(0x11223344)) }),
            instructions: EndianBuf::<LittleEndian>::new(&instrs),
        };

        let rest = [1, 2, 3, 4];

        let section = Section::with_endian(Endian::Little)
            .fde(Endian::Little, cie_offset, &mut fde)
            .append_bytes(&rest)
            .get_contents()
            .unwrap();
        let section = EhFrame::<LittleEndian>::new(&section);
        let input = &mut section.section();

        let result = parse_fde(section, input, |_| Ok(cie.clone()));
        assert_eq!(result, Ok(fde));
        assert_eq!(*input, EndianBuf::new(&rest));
    }

    #[test]
    fn test_eh_frame_fde_lsda_function_relative() {
        let instrs = [1, 2, 3, 4];
        let cie_offset = 1;

        let mut cie = make_test_cie();
        cie.format = Format::Dwarf32;
        cie.version = 1;
        cie.augmentation = Some(Augmentation::default());
        cie.augmentation.as_mut().unwrap().lsda =
            Some(constants::DwEhPe(constants::DW_EH_PE_funcrel.0 | constants::DW_EH_PE_absptr.0));

        let mut fde = EhFrameFde {
            length: 0,
            format: Format::Dwarf32,
            cie: cie.clone(),
            initial_segment: 0,
            initial_address: 0xfeedface,
            address_range: 9000,
            augmentation: Some(AugmentationData { lsda: Some(Pointer::Direct(1)) }),
            instructions: EndianBuf::<LittleEndian>::new(&instrs),
        };

        let rest = [1, 2, 3, 4];

        let section = Section::with_endian(Endian::Little)
            .append_repeated(10, 10)
            .fde(Endian::Little, cie_offset, &mut fde)
            .append_bytes(&rest)
            .get_contents()
            .unwrap();
        let section = EhFrame::<LittleEndian>::new(&section);
        let input = &mut section.section().range_from(10..);

        // Adjust the FDE's augmentation to be relative to the section.
        fde.augmentation.as_mut().unwrap().lsda = Some(Pointer::Direct(19));

        let result = parse_fde(section, input, |_| Ok(cie.clone()));
        assert_eq!(result, Ok(fde));
        assert_eq!(*input, EndianBuf::new(&rest));
    }

    #[test]
    fn test_eh_frame_cie_personality_function_relative_bad_context() {
        let instrs = [1, 2, 3, 4];

        let length = Label::new();
        let start = Label::new();
        let end = Label::new();

        let aug_len = Label::new();
        let aug_start = Label::new();
        let aug_end = Label::new();

        let section = Section::with_endian(Endian::Little)
            // Length
            .L32(&length)
            .mark(&start)
            // CIE ID
            .L32(0)
            // Version
            .D8(1)
            // Augmentation
            .append_bytes(b"zP\0")
            // Code alignment factor
            .uleb(1)
            // Data alignment factor
            .sleb(1)
            // Return address register
            .uleb(1)
            // Augmentation data length. This is a uleb, be we rely on the value
            // being less than 2^7 and therefore a valid uleb (can't use Label
            // with uleb).
            .D8(&aug_len)
            .mark(&aug_start)
            // Augmentation data. Personality encoding and then encoded pointer.
            .D8(constants::DW_EH_PE_funcrel.0 | constants::DW_EH_PE_uleb128.0)
            .uleb(1)
            .mark(&aug_end)
            // Initial instructions
            .append_bytes(&instrs)
            .mark(&end);

        length.set_const((&end - &start) as u64);
        aug_len.set_const((&aug_end - &aug_start) as u64);

        let section = section.get_contents().unwrap();
        let section = EhFrame::<LittleEndian>::new(&section);

        let bases = BaseAddresses::default();
        let mut iter = section.entries(&bases);
        assert_eq!(iter.next(), Err(Error::FuncRelativePointerInBadContext));
    }

    #[test]
    fn register_rule_map_eq() {
        // Different order, but still equal.
        let map1: RegisterRuleMap<LittleEndian> = [(0, RegisterRule::SameValue),
                                                   (3, RegisterRule::Offset(1))]
            .iter()
            .collect();
        let map2: RegisterRuleMap<LittleEndian> = [(3, RegisterRule::Offset(1)),
                                                   (0, RegisterRule::SameValue)]
            .iter()
            .collect();
        assert_eq!(map1, map2);
        assert_eq!(map2, map1);

        // Not equal.
        let map3: RegisterRuleMap<LittleEndian> = [(0, RegisterRule::SameValue),
                                                   (2, RegisterRule::Offset(1))]
            .iter()
            .collect();
        let map4: RegisterRuleMap<LittleEndian> = [(3, RegisterRule::Offset(1)),
                                                   (0, RegisterRule::SameValue)]
            .iter()
            .collect();
        assert!(map3 != map4);
        assert!(map4 != map3);

        // One has undefined explicitly set, other implicitly has undefined.
        let mut map5 = RegisterRuleMap::<LittleEndian>::default();
        map5.set(0, RegisterRule::SameValue).unwrap();
        map5.set(0, RegisterRule::Undefined).unwrap();
        let map6 = RegisterRuleMap::<LittleEndian>::default();
        assert_eq!(map5, map6);
        assert_eq!(map6, map5);
    }

    #[test]
    fn iter_register_rules() {
        let mut row = UnwindTableRow::<LittleEndian>::default();
        row.registers = [(0, RegisterRule::SameValue),
                         (1, RegisterRule::Offset(1)),
                         (2, RegisterRule::ValOffset(2))]
            .iter()
            .collect();

        let mut found0 = false;
        let mut found1 = false;
        let mut found2 = false;

        for &(register, ref rule) in row.registers() {
            match register {
                0 => {
                    assert_eq!(found0, false);
                    found0 = true;
                    assert_eq!(*rule, RegisterRule::SameValue);
                }
                1 => {
                    assert_eq!(found1, false);
                    found1 = true;
                    assert_eq!(*rule, RegisterRule::Offset(1));
                }
                2 => {
                    assert_eq!(found2, false);
                    found2 = true;
                    assert_eq!(*rule, RegisterRule::ValOffset(2));
                }
                x => panic!("Unexpected register rule: ({}, {:?})", x, rule),
            }
        }

        assert_eq!(found0, true);
        assert_eq!(found1, true);
        assert_eq!(found2, true);
    }

    #[test]
    fn size_of_unwind_ctx() {
        use std::mem;
        assert_eq!(mem::size_of::<UnwindContext<NativeEndian, EhFrame<NativeEndian>>>(),
                   5384);
    }

    #[test]
    fn size_of_register_rule_map() {
        use std::mem;
        assert_eq!(mem::size_of::<RegisterRuleMap<NativeEndian>>(), 1040);
    }
}
