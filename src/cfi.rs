use constants;
use endianity::{Endianity, EndianBuf};
use fallible_iterator::FallibleIterator;
use parser::{Error, Format, Result, parse_address, parse_initial_length, parse_length_uleb_value,
             parse_null_terminated_string, parse_signed_leb, parse_signed_lebe, parse_u8,
             parse_u8e, parse_u16, parse_u32, parse_unsigned_leb, parse_unsigned_lebe, parse_word};
use std::marker::PhantomData;
use std::str;

/// An offset into the `.debug_frame` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugFrameOffset(pub u64);

/// The `DebugFrame` struct contains the source location to instruction mapping
/// found in the `.debug_frame` section.
#[derive(Debug, Clone, Copy)]
pub struct DebugFrame<'input, Endian>
    where Endian: Endianity
{
    debug_frame_section: EndianBuf<'input, Endian>,
}

impl<'input, Endian> DebugFrame<'input, Endian>
    where Endian: Endianity
{
    /// Construct a new `DebugFrame` instance from the data in the
    /// `.debug_frame` section.
    ///
    /// It is the caller's responsibility to read the `.debug_frame` section and
    /// present it as a `&[u8]` slice. That means using some ELF loader on
    /// Linux, a Mach-O loader on OSX, etc.
    ///
    /// ```
    /// use gimli::{DebugFrame, LittleEndian};
    ///
    /// # let buf = [0x00, 0x01, 0x02, 0x03];
    /// # let read_debug_frame_section_somehow = || &buf;
    /// let debug_frame = DebugFrame::<LittleEndian>::new(read_debug_frame_section_somehow());
    /// ```
    pub fn new(debug_frame_section: &'input [u8]) -> DebugFrame<'input, Endian> {
        DebugFrame { debug_frame_section: EndianBuf(debug_frame_section, PhantomData) }
    }

    /// Iterate over the `CommonInformationEntry`s and `FrameDescriptionEntry`s
    /// in this `.debug_frame` section.
    ///
    /// Can be [used with
    /// `FallibleIterator`](./index.html#using-with-fallibleiterator).
    pub fn entries(&self) -> CfiEntriesIter<'input, Endian> {
        CfiEntriesIter { input: self.debug_frame_section }
    }

    /// Parse the `CommonInformationEntry` at the given offset.
    pub fn cie_from_offset(&self,
                           offset: DebugFrameOffset)
                           -> Result<CommonInformationEntry<'input, Endian>> {
        let offset = offset.0 as usize;
        if self.debug_frame_section.len() < offset {
            return Err(Error::UnexpectedEof);
        }

        let input = self.debug_frame_section.range_from(offset..);
        let (_, entry) = try!(CommonInformationEntry::parse(input));
        Ok(entry)
    }

    /// Find the frame unwind information for the given address.
    ///
    /// If found, the unwind information is returned along with the reset
    /// context in the form `Ok((unwind_info, context))`. If not found,
    /// `Err(gimli::Error::NoUnwindInfoForAddress)` is returned. If parsing or
    /// CFI evaluation fails, the error is returned.
    ///
    /// ```
    /// use gimli::{DebugFrame, NativeEndian, UninitializedUnwindContext};
    ///
    /// # fn foo() -> gimli::Result<()> {
    /// # let read_debug_frame_section = || unimplemented!();
    /// // Get the `.debug_frame` section from the object file.
    /// let debug_frame = DebugFrame::<NativeEndian>::new(read_debug_frame_section());
    ///
    /// # let get_frame_pc = || unimplemented!();
    /// // Get the address of the PC for a frame you'd like to unwind.
    /// let address = get_frame_pc();
    ///
    /// // This context is reusable, which cuts down on heap allocations.
    /// let ctx = UninitializedUnwindContext::new();
    ///
    /// let (unwind_info, ctx) = try!(debug_frame.unwind_info_for_address(ctx, address));
    /// # let do_stuff_with = |_| unimplemented!();
    /// do_stuff_with(unwind_info);
    /// # let _ = ctx;
    /// # Ok(())
    /// # }
    /// ```
    pub fn unwind_info_for_address
        (&self,
         ctx: UninitializedUnwindContext<'input, Endian>,
         address: u64)
         -> Result<(UnwindTableRow<'input, Endian>, UninitializedUnwindContext<'input, Endian>)> {
        let mut target_fde = None;

        let mut entries = self.entries();
        while let Some(entry) = try!(entries.next()) {
            match entry {
                CieOrFde::Cie(_) => continue,
                CieOrFde::Fde(partial) => {
                    let fde = try!(partial.parse(|offset| self.cie_from_offset(offset)));
                    if fde.contains(address) {
                        target_fde = Some(fde);
                        break;
                    }
                }
            }
        }

        if let Some(fde) = target_fde {
            let mut result_row = None;
            let mut ctx = try!(ctx.initialize(fde.cie()));

            {
                let mut table = UnwindTable::new(&mut ctx, &fde);
                while let Some(row) = try!(table.next_row()) {
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

/// An iterator over CIE and FDE entries in a `.debug_frame` section.
///
/// Can be [used with
/// `FallibleIterator`](./index.html#using-with-fallibleiterator).
#[derive(Clone, Debug)]
pub struct CfiEntriesIter<'input, Endian>
    where Endian: Endianity
{
    input: EndianBuf<'input, Endian>,
}

impl<'input, Endian> CfiEntriesIter<'input, Endian>
    where Endian: Endianity
{
    /// Advance the iterator to the next entry.
    pub fn next(&mut self) -> Result<Option<CieOrFde<'input, Endian>>> {
        if self.input.len() == 0 {
            return Ok(None);
        }

        match parse_cfi_entry(self.input) {
            Err(e) => {
                self.input = EndianBuf::new(&[]);
                Err(e)
            }
            Ok((rest, entry)) => {
                self.input = rest;
                Ok(Some(entry))
            }
        }
    }
}

impl<'input, Endian> FallibleIterator for CfiEntriesIter<'input, Endian>
    where Endian: Endianity
{
    type Item = CieOrFde<'input, Endian>;
    type Error = Error;

    fn next(&mut self) -> ::std::result::Result<Option<Self::Item>, Self::Error> {
        CfiEntriesIter::next(self)
    }
}

/// Parse the common start shared between both CIEs and FDEs. Return a tuple of
/// the form `(next_entry_input, (length, format, cie_id_or_offset,
/// rest_of_this_entry_input))`.
fn parse_cfi_entry_common<'input, Endian>
    (input: EndianBuf<'input, Endian>)
     -> Result<(EndianBuf<'input, Endian>, (u64, Format, u64, EndianBuf<'input, Endian>))>
    where Endian: Endianity
{
    let (rest, (length, format)) = try!(parse_initial_length(input));
    if length as usize > rest.len() {
        return Err(Error::BadLength);
    }

    let rest_rest = rest.range_from(length as usize..);
    let rest = rest.range_to(..length as usize);

    let (rest, cie_id_or_offset) = try!(parse_word(rest, format));

    Ok((rest_rest, (length, format, cie_id_or_offset, rest)))
}

fn is_cie_id(format: Format, id: u64) -> bool {
    match format {
        Format::Dwarf32 => id == 0xffffffff,
        Format::Dwarf64 => id == 0xffffffffffffffff,
    }
}

/// Either a `CommonInformationEntry` (CIE) or a `FrameDescriptionEntry` (FDE).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CieOrFde<'input, Endian>
    where Endian: Endianity
{
    /// This CFI entry is a `CommonInformationEntry`.
    Cie(CommonInformationEntry<'input, Endian>),
    /// This CFI entry is a `FrameDescriptionEntry`, however fully parsing it
    /// requires parsing its CIE first, so it is left in a partially parsed
    /// state.
    Fde(PartialFrameDescriptionEntry<'input, Endian>),
}

fn parse_cfi_entry<'input, Endian>
    (input: EndianBuf<'input, Endian>)
     -> Result<(EndianBuf<'input, Endian>, CieOrFde<'input, Endian>)>
    where Endian: Endianity
{
    let (rest_rest, (length, format, cie_id_or_offset, rest)) = try!(parse_cfi_entry_common(input));
    if is_cie_id(format, cie_id_or_offset) {
        let cie = try!(CommonInformationEntry::parse_rest(length, format, cie_id_or_offset, rest));
        Ok((rest_rest, CieOrFde::Cie(cie)))
    } else {
        let fde = PartialFrameDescriptionEntry {
            length: length,
            format: format,
            cie_offset: DebugFrameOffset(cie_id_or_offset),
            rest: rest,
        };
        Ok((rest_rest, CieOrFde::Fde(fde)))
    }
}

/// > A Common Information Entry holds information that is shared among many
/// > Frame Description Entries. There is at least one CIE in every non-empty
/// > `.debug_frame` section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommonInformationEntry<'input, Endian>
    where Endian: Endianity
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

    /// > A null-terminated UTF-8 string that identifies the augmentation to
    /// > this CIE or to the FDEs that use it. If a reader encounters an
    /// > augmentation string that is unexpected, then only the following fields
    /// > can be read:
    /// >
    /// > * CIE: length, CIE_id, version, augmentation
    /// > * FDE: length, CIE_pointer, initial_location, address_range
    /// >
    /// > If there is no augmentation, this value is a zero byte.
    augmentation: Option<&'input str>,

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

    /// > An unsigned LB128 constant that indicates which column in the rule
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
}

impl<'input, Endian> CommonInformationEntry<'input, Endian>
    where Endian: Endianity
{
    fn parse(input: EndianBuf<'input, Endian>)
             -> Result<(EndianBuf<'input, Endian>, CommonInformationEntry<'input, Endian>)> {
        let (rest_rest, (length, format, cie_id, rest)) = try!(parse_cfi_entry_common(input));
        let entry = try!(Self::parse_rest(length, format, cie_id, rest));
        Ok((rest_rest, entry))
    }

    fn parse_rest(length: u64,
                  format: Format,
                  cie_id: u64,
                  rest: EndianBuf<'input, Endian>)
                  -> Result<CommonInformationEntry<'input, Endian>> {
        if !is_cie_id(format, cie_id) {
            return Err(Error::NotCieId);
        }

        let (rest, version) = try!(parse_u8(rest.into()));
        match version {
            // TODO: Is this parser really backwards compatible with versions 1
            // and 3?
            1 | 3 | 4 => {}
            _ => return Err(Error::UnknownVersion),
        }

        let (rest, augmentation) = try!(parse_null_terminated_string(rest));
        let aug_len = augmentation.to_bytes().len();

        if aug_len > 0 {
            // We don't support any target-specific augmentations, so the best
            // we can do here is enable library consumers to introspect the
            // augmentation.

            let augmentation = try!(str::from_utf8(augmentation.to_bytes())
                .map_err(|_| Error::BadUtf8));

            let entry = CommonInformationEntry {
                length: length,
                format: format,
                version: version,
                augmentation: Some(augmentation),
                address_size: Default::default(),
                segment_size: Default::default(),
                code_alignment_factor: Default::default(),
                data_alignment_factor: Default::default(),
                return_address_register: Default::default(),
                initial_instructions: EndianBuf::new(&[]),
            };

            return Ok(entry);
        }

        let augmentation = None;

        let (rest, address_size) = try!(parse_u8(rest));
        let (rest, segment_size) = try!(parse_u8(rest));
        let (rest, code_alignment_factor) = try!(parse_unsigned_leb(rest));
        let (rest, data_alignment_factor) = try!(parse_signed_leb(rest));
        let (rest, return_address_register) = try!(parse_unsigned_leb(rest));

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
            initial_instructions: EndianBuf::new(rest),
        };

        Ok(entry)
    }

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
pub struct PartialFrameDescriptionEntry<'input, Endian>
    where Endian: Endianity
{
    length: u64,
    format: Format,
    cie_offset: DebugFrameOffset,
    rest: EndianBuf<'input, Endian>,
}

impl<'input, Endian> PartialFrameDescriptionEntry<'input, Endian>
    where Endian: Endianity
{
    /// Fully parse this FDE.
    ///
    /// You must provide a function get its associated CIE (either by parsing it
    /// on demand, or looking it up in some table mapping offsets to CIEs that
    /// you've already parsed, etc.)
    pub fn parse<F>(&self, get_cie: F) -> Result<FrameDescriptionEntry<'input, Endian>>
        where F: FnMut(DebugFrameOffset) -> Result<CommonInformationEntry<'input, Endian>>
    {
        FrameDescriptionEntry::parse_rest(self.length,
                                          self.format,
                                          self.cie_offset.0,
                                          self.rest,
                                          get_cie)
    }
}

/// A `FrameDescriptionEntry` is a set of CFA instructions for an address range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameDescriptionEntry<'input, Endian>
    where Endian: Endianity
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
    cie: CommonInformationEntry<'input, Endian>,

    /// > The address of the first location associated with this table entry. If
    /// > the segment_size field of this FDE's CIE is non-zero, the initial
    /// > location is preceded by a segment selector of the given length.
    initial_segment: u64,
    initial_address: u64,

    /// "The number of bytes of program instructions described by this entry."
    address_range: u64,

    /// "A sequence of table defining instructions that are described below."
    ///
    /// This is followed by `DW_CFA_nop` padding until `length` bytes of the
    /// input are consumed.
    instructions: EndianBuf<'input, Endian>,
}

impl<'input, Endian> FrameDescriptionEntry<'input, Endian>
    where Endian: Endianity
{
    #[allow(dead_code)]
    fn parse<F>(input: EndianBuf<'input, Endian>,
                get_cie: F)
                -> Result<(EndianBuf<'input, Endian>, FrameDescriptionEntry<'input, Endian>)>
        where F: FnMut(DebugFrameOffset) -> Result<CommonInformationEntry<'input, Endian>>
    {
        let (rest_rest, (length, format, cie_pointer, rest)) = try!(parse_cfi_entry_common(input));
        let entry = try!(Self::parse_rest(length, format, cie_pointer, rest, get_cie));
        Ok((rest_rest, entry))
    }

    fn parse_rest<F>(length: u64,
                     format: Format,
                     cie_pointer: u64,
                     rest: EndianBuf<'input, Endian>,
                     mut get_cie: F)
                     -> Result<FrameDescriptionEntry<'input, Endian>>
        where F: FnMut(DebugFrameOffset) -> Result<CommonInformationEntry<'input, Endian>>
    {
        if is_cie_id(format, cie_pointer) {
            return Err(Error::NotCiePointer);
        }

        let cie_pointer = DebugFrameOffset(cie_pointer);
        let cie = try!(get_cie(cie_pointer));

        let (rest, initial_segment) = if cie.segment_size > 0 {
            try!(parse_address(rest, cie.segment_size))
        } else {
            (rest, 0)
        };

        let (rest, initial_address) = try!(parse_address(rest, cie.address_size));
        let (rest, address_range) = try!(parse_address(rest, cie.address_size));

        let entry = FrameDescriptionEntry {
            length: length,
            format: format,
            cie: cie,
            initial_segment: initial_segment,
            initial_address: initial_address,
            address_range: address_range,
            instructions: rest,
        };

        Ok(entry)
    }

    /// Get a reference to this FDE's CIE.
    pub fn cie<'me>(&'me self) -> &'me CommonInformationEntry<'input, Endian> {
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
/// # fn foo<'a>(some_fde: gimli::FrameDescriptionEntry<'a, gimli::LittleEndian>) -> gimli::Result<()> {
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
/// # Ok(())
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
pub struct UninitializedUnwindContext<'input, Endian>(UnwindContext<'input, Endian>)
    where Endian: Endianity;

impl<'input, Endian> UninitializedUnwindContext<'input, Endian>
    where Endian: Endianity
{
    /// Construct a new call frame unwinding context.
    pub fn new() -> UninitializedUnwindContext<'input, Endian> {
        UninitializedUnwindContext(UnwindContext::new())
    }

    /// Run the CIE's initial instructions, creating an
    /// `InitializedUnwindContext`.
    pub fn initialize(mut self,
                      cie: &CommonInformationEntry<'input, Endian>)
                      -> Result<InitializedUnwindContext<'input, Endian>> {
        self.0.assert_fully_uninitialized();

        {
            let mut table = UnwindTable::new_internal(&mut self.0, cie, None);
            while let Some(_) = try!(table.next_row()) {}
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
pub struct InitializedUnwindContext<'input, Endian>(UnwindContext<'input, Endian>)
    where Endian: Endianity;

impl<'input, Endian> InitializedUnwindContext<'input, Endian>
    where Endian: Endianity
{
    /// Reset this context to the uninitialized state.
    pub fn reset(mut self) -> UninitializedUnwindContext<'input, Endian> {
        self.0.reset();
        UninitializedUnwindContext(self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct UnwindContext<'input, Endian>
    where Endian: Endianity
{
    // Stack of rows. The last row is the row currently being built by the
    // program. There is always at least one row. The vast majority of CFI
    // programs will only ever have one row on the stack.
    stack: Vec<UnwindTableRow<'input, Endian>>,

    // If we are evaluating an FDE's instructions, then `is_initialized` will be
    // `true` and `initial_rules` will contain the initial register rules
    // described by the CIE's initial instructions. These rules are used by
    // `DW_CFA_restore`. Otherwise, when we are currently evaluating a CIE's
    // initial instructions, `is_initialized` will be `false` and
    // `initial_rules` is not to be read from.
    is_initialized: bool,
    initial_rules: Vec<RegisterRule<'input, Endian>>,
}

impl<'input, Endian> UnwindContext<'input, Endian>
    where Endian: Endianity
{
    fn new() -> UnwindContext<'input, Endian> {
        let mut ctx = UnwindContext {
            stack: Vec::with_capacity(1),
            is_initialized: false,
            initial_rules: Default::default(),
        };
        ctx.reset();
        ctx
    }

    fn reset(&mut self) {
        self.stack.clear();
        self.stack.push(UnwindTableRow::default());

        self.initial_rules.clear();
        self.is_initialized = false;

        self.assert_fully_uninitialized();
    }

    // Asserts that we are fully uninitialized, ie not initialized *and* not in
    // the process of initializing.
    #[inline]
    fn assert_fully_uninitialized(&self) {
        assert_eq!(self.is_initialized, false);
        assert_eq!(self.initial_rules.len(), 0);
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
        self.initial_rules.clone_from(&self.stack.last().unwrap().registers);
        self.is_initialized = true;
    }

    fn fill_undefined_to(&mut self, idx: usize) {
        let mut row = self.row_mut();
        while row.registers.len() <= idx {
            row.registers.push(RegisterRule::Undefined);
        }
    }

    fn start_address(&self) -> u64 {
        self.row().start_address
    }

    fn set_start_address(&mut self, start_address: u64) {
        let row = self.row_mut();
        row.start_address = start_address;
    }

    fn set_register_rule(&mut self, register: u64, rule: RegisterRule<'input, Endian>) {
        let register = register as usize;
        self.fill_undefined_to(register);
        let row = self.row_mut();
        row.registers[register] = rule;
    }

    /// Returns `None` if we have not completed evaluation of a CIE's initial
    /// instructions.
    fn get_initial_rule(&self, register: u64) -> Option<RegisterRule<'input, Endian>> {
        if !self.is_initialized {
            return None;
        }

        self.initial_rules
            .get(register as usize)
            .map(|r| r.clone())
            .or(Some(RegisterRule::Undefined))
    }

    fn set_cfa(&mut self, cfa: CfaRule<'input, Endian>) {
        self.row_mut().cfa = cfa;
    }

    fn cfa_mut(&mut self) -> &mut CfaRule<'input, Endian> {
        &mut self.row_mut().cfa
    }

    fn push_row(&mut self) {
        let new_row = self.row().clone();
        self.stack.push(new_row);
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
pub struct UnwindTable<'input, 'cie, 'fde, 'ctx, Endian>
    where Endian: 'cie + 'fde + 'ctx + Endianity,
          'input: 'cie + 'fde + 'ctx
{
    cie: &'cie CommonInformationEntry<'input, Endian>,
    next_start_address: u64,
    returned_last_row: bool,
    instructions: CallFrameInstructionIter<'input, Endian>,
    ctx: &'ctx mut UnwindContext<'input, Endian>,
    // If this is `None`, then we are executing a CIE's initial_instructions. If
    // this is `Some`, then we are executing an FDE's instructions.
    fde: Option<&'fde FrameDescriptionEntry<'input, Endian>>,
}

impl<'input, 'fde, 'ctx, Endian> UnwindTable<'input, 'fde, 'fde, 'ctx, Endian>
    where Endian: Endianity
{
    /// Construct a new `UnwindTable` for the given
    /// `FrameDescriptionEntry`'s CFI unwinding program.
    pub fn new(ctx: &'ctx mut InitializedUnwindContext<'input, Endian>,
               fde: &'fde FrameDescriptionEntry<'input, Endian>)
               -> UnwindTable<'input, 'fde, 'fde, 'ctx, Endian> {
        assert!(ctx.0.is_initialized);
        Self::new_internal(&mut ctx.0, fde.cie(), Some(fde))
    }
}

impl<'input, 'cie, 'fde, 'ctx, Endian> UnwindTable<'input, 'cie, 'fde, 'ctx, Endian>
    where Endian: Endianity
{
    fn new_internal(ctx: &'ctx mut UnwindContext<'input, Endian>,
                    cie: &'cie CommonInformationEntry<'input, Endian>,
                    fde: Option<&'fde FrameDescriptionEntry<'input, Endian>>)
                    -> UnwindTable<'input, 'cie, 'fde, 'ctx, Endian> {
        assert!(ctx.stack.len() >= 1);
        let next_start_address = fde.map(|fde| fde.initial_address).unwrap_or(0);
        let instructions = fde.map(|fde| fde.instructions()).unwrap_or_else(|| cie.instructions());
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
                    if try!(self.evaluate(instruction)) {
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
            DefCfaSf { register, factored_offset } => {
                let data_align = self.cie.data_alignment_factor as i64;
                self.ctx.set_cfa(CfaRule::RegisterAndOffset {
                    register: register,
                    offset: factored_offset * data_align,
                });
            }
            DefCfaRegister { register } => {
                if let CfaRule::RegisterAndOffset { register: ref mut reg, .. } = *self.ctx
                    .cfa_mut() {
                    *reg = register;
                } else {
                    return Err(Error::CfiInstructionInInvalidContext);
                }
            }
            DefCfaOffset { offset } => {
                if let CfaRule::RegisterAndOffset { offset: ref mut off, .. } = *self.ctx
                    .cfa_mut() {
                    *off = offset as i64;
                } else {
                    return Err(Error::CfiInstructionInInvalidContext);
                }
            }
            DefCfaOffsetSf { factored_offset } => {
                if let CfaRule::RegisterAndOffset { offset: ref mut off, .. } = *self.ctx
                    .cfa_mut() {
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
                self.ctx.fill_undefined_to(register as usize);
            }
            SameValue { register } => {
                self.ctx.set_register_rule(register, RegisterRule::SameValue);
            }
            Offset { register, factored_offset } => {
                let offset = factored_offset as i64 * self.cie.data_alignment_factor;
                self.ctx.set_register_rule(register, RegisterRule::Offset(offset));
            }
            OffsetExtendedSf { register, factored_offset } => {
                let offset = factored_offset * self.cie.data_alignment_factor;
                self.ctx.set_register_rule(register, RegisterRule::Offset(offset));
            }
            ValOffset { register, factored_offset } => {
                let offset = factored_offset as i64 * self.cie.data_alignment_factor;
                self.ctx.set_register_rule(register, RegisterRule::ValOffset(offset))
            }
            ValOffsetSf { register, factored_offset } => {
                let offset = factored_offset * self.cie.data_alignment_factor;
                self.ctx.set_register_rule(register, RegisterRule::ValOffset(offset));
            }
            Register { dest_register, src_register } => {
                self.ctx.set_register_rule(dest_register, RegisterRule::Register(src_register));
            }
            Expression { register, expression } => {
                self.ctx
                    .set_register_rule(register, RegisterRule::Expression(expression));
            }
            ValExpression { register, expression } => {
                self.ctx.set_register_rule(register, RegisterRule::ValExpression(expression));
            }
            Restore { register } => {
                let initial_rule = if let Some(rule) = self.ctx.get_initial_rule(register) {
                    rule
                } else {
                    // Can't restore the initial rule when we are
                    // evaluating the initial rules!
                    return Err(Error::CfiInstructionInInvalidContext);
                };

                self.ctx.set_register_rule(register, initial_rule);
            }

            // Row push and pop instructions.
            RememberState => {
                self.ctx.push_row();
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

/// A row in the virtual unwind table that describes how to find the values of
/// the registers in the *previous* frame for a range of PC addresses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnwindTableRow<'input, Endian>
    where Endian: Endianity
{
    start_address: u64,
    end_address: u64,
    cfa: CfaRule<'input, Endian>,
    registers: Vec<RegisterRule<'input, Endian>>,
}

impl<'input, Endian> Default for UnwindTableRow<'input, Endian>
    where Endian: Endianity
{
    fn default() -> Self {
        UnwindTableRow {
            start_address: 0,
            end_address: 0,
            cfa: Default::default(),
            registers: Vec::new(),
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

    /// Get the register recovery rules for this row.
    ///
    /// The rule at index `i` of the slice is the rule for register `i`. The
    /// slice is **not** guaranteed to have length equal to the number of
    /// registers on the target architecture. It is only as long as the largest
    /// numbered register for which a recovery rule is defined in this row. All
    /// others are implied to be `Undefined`.
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
    pub fn registers(&self) -> &[RegisterRule<'input, Endian>] {
        &self.registers[..]
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
        register: u64,
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
    Register(u64),

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
        register: u64,
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
        register: u64,
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
        register: u64,
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
        register: u64,
    },

    /// > 2. DW_CFA_same_value
    /// >
    /// > The DW_CFA_same_value instruction takes a single unsigned LEB128
    /// > operand that represents a register number. The required action is to
    /// > set the rule for the specified register to “same value.”
    SameValue {
        /// The target register's number.
        register: u64,
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
        register: u64,
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
        register: u64,
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
        register: u64,
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
        register: u64,
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
        dest_register: u64,
        /// The number of the register where the other register's value can be
        /// found.
        src_register: u64,
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
        register: u64,
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
        register: u64,
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
        register: u64,
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
    fn parse(input: EndianBuf<'input, Endian>)
             -> Result<(EndianBuf<'input, Endian>, CallFrameInstruction<'input, Endian>)> {
        let (rest, instruction) = try!(parse_u8e(input));
        let high_bits = instruction & CFI_INSTRUCTION_HIGH_BITS_MASK;

        if high_bits == constants::DW_CFA_advance_loc.0 {
            let delta = instruction & CFI_INSTRUCTION_LOW_BITS_MASK;
            return Ok((rest, CallFrameInstruction::AdvanceLoc { delta: delta as u32 }));
        }

        if high_bits == constants::DW_CFA_offset.0 {
            let register = instruction & CFI_INSTRUCTION_LOW_BITS_MASK;
            let (rest, offset) = try!(parse_unsigned_lebe(rest));
            return Ok((rest,
                       CallFrameInstruction::Offset {
                register: register as u64,
                factored_offset: offset,
            }));
        }

        if high_bits == constants::DW_CFA_restore.0 {
            let register = instruction & CFI_INSTRUCTION_LOW_BITS_MASK;
            return Ok((rest, CallFrameInstruction::Restore { register: register as u64 }));
        }

        debug_assert!(high_bits == 0);
        let instruction = constants::DwCfa(instruction);

        match instruction {
            constants::DW_CFA_nop => Ok((rest, CallFrameInstruction::Nop)),

            constants::DW_CFA_set_loc => {
                let (rest, address) = try!(parse_unsigned_lebe(rest));
                Ok((rest, CallFrameInstruction::SetLoc { address: address }))
            }

            constants::DW_CFA_advance_loc1 => {
                let (rest, delta) = try!(parse_u8e(rest));
                Ok((rest, CallFrameInstruction::AdvanceLoc { delta: delta as u32 }))
            }

            constants::DW_CFA_advance_loc2 => {
                let (rest, delta) = try!(parse_u16(rest));
                Ok((rest, CallFrameInstruction::AdvanceLoc { delta: delta as u32 }))
            }

            constants::DW_CFA_advance_loc4 => {
                let (rest, delta) = try!(parse_u32(rest));
                Ok((rest, CallFrameInstruction::AdvanceLoc { delta: delta }))
            }

            constants::DW_CFA_offset_extended => {
                let (rest, register) = try!(parse_unsigned_lebe(rest));
                let (rest, offset) = try!(parse_unsigned_lebe(rest));
                Ok((rest,
                    CallFrameInstruction::Offset {
                    register: register,
                    factored_offset: offset,
                }))
            }

            constants::DW_CFA_restore_extended => {
                let (rest, register) = try!(parse_unsigned_lebe(rest));
                Ok((rest, CallFrameInstruction::Restore { register: register }))
            }

            constants::DW_CFA_undefined => {
                let (rest, register) = try!(parse_unsigned_lebe(rest));
                Ok((rest, CallFrameInstruction::Undefined { register: register }))
            }

            constants::DW_CFA_same_value => {
                let (rest, register) = try!(parse_unsigned_lebe(rest));
                Ok((rest, CallFrameInstruction::SameValue { register: register }))
            }

            constants::DW_CFA_register => {
                let (rest, dest) = try!(parse_unsigned_lebe(rest));
                let (rest, src) = try!(parse_unsigned_lebe(rest));
                Ok((rest,
                    CallFrameInstruction::Register {
                    dest_register: dest,
                    src_register: src,
                }))
            }

            constants::DW_CFA_remember_state => Ok((rest, CallFrameInstruction::RememberState)),

            constants::DW_CFA_restore_state => Ok((rest, CallFrameInstruction::RestoreState)),

            constants::DW_CFA_def_cfa => {
                let (rest, register) = try!(parse_unsigned_lebe(rest));
                let (rest, offset) = try!(parse_unsigned_lebe(rest));
                Ok((rest,
                    CallFrameInstruction::DefCfa {
                    register: register,
                    offset: offset,
                }))
            }

            constants::DW_CFA_def_cfa_register => {
                let (rest, register) = try!(parse_unsigned_lebe(rest));
                Ok((rest, CallFrameInstruction::DefCfaRegister { register: register }))
            }

            constants::DW_CFA_def_cfa_offset => {
                let (rest, offset) = try!(parse_unsigned_lebe(rest));
                Ok((rest, CallFrameInstruction::DefCfaOffset { offset: offset }))
            }

            constants::DW_CFA_def_cfa_expression => {
                let (rest, expression) = try!(parse_length_uleb_value(rest));
                Ok((rest, CallFrameInstruction::DefCfaExpression { expression: expression }))
            }

            constants::DW_CFA_expression => {
                let (rest, register) = try!(parse_unsigned_lebe(rest));
                let (rest, expression) = try!(parse_length_uleb_value(rest));
                Ok((rest,
                    CallFrameInstruction::Expression {
                    register: register,
                    expression: expression,
                }))
            }

            constants::DW_CFA_offset_extended_sf => {
                let (rest, register) = try!(parse_unsigned_lebe(rest));
                let (rest, offset) = try!(parse_signed_lebe(rest));
                Ok((rest,
                    CallFrameInstruction::OffsetExtendedSf {
                    register: register,
                    factored_offset: offset,
                }))
            }

            constants::DW_CFA_def_cfa_sf => {
                let (rest, register) = try!(parse_unsigned_lebe(rest));
                let (rest, offset) = try!(parse_signed_lebe(rest));
                Ok((rest,
                    CallFrameInstruction::DefCfaSf {
                    register: register,
                    factored_offset: offset,
                }))
            }

            constants::DW_CFA_def_cfa_offset_sf => {
                let (rest, offset) = try!(parse_signed_lebe(rest));
                Ok((rest, CallFrameInstruction::DefCfaOffsetSf { factored_offset: offset }))
            }

            constants::DW_CFA_val_offset => {
                let (rest, register) = try!(parse_unsigned_lebe(rest));
                let (rest, offset) = try!(parse_unsigned_lebe(rest));
                Ok((rest,
                    CallFrameInstruction::ValOffset {
                    register: register,
                    factored_offset: offset,
                }))
            }

            constants::DW_CFA_val_offset_sf => {
                let (rest, register) = try!(parse_unsigned_lebe(rest));
                let (rest, offset) = try!(parse_signed_lebe(rest));
                Ok((rest,
                    CallFrameInstruction::ValOffsetSf {
                    register: register,
                    factored_offset: offset,
                }))
            }

            constants::DW_CFA_val_expression => {
                let (rest, register) = try!(parse_unsigned_lebe(rest));
                let (rest, expression) = try!(parse_length_uleb_value(rest));
                Ok((rest,
                    CallFrameInstruction::ValExpression {
                    register: register,
                    expression: expression,
                }))
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

        match CallFrameInstruction::parse(self.input) {
            Ok((rest, instruction)) => {
                self.input = rest;
                Ok(Some(instruction))
            }
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
    extern crate leb128;
    extern crate test_assembler;

    use super::*;
    use super::{parse_cfi_entry, UnwindContext};
    use constants;
    use endianity::{BigEndian, Endianity, EndianBuf, LittleEndian, NativeEndian};
    use parser::{Error, Format, Result};
    use self::test_assembler::{Endian, Label, LabelMaker, LabelOrNum, Section, ToLabelOrNum};

    // Mixin methods for `Section` to help define binary test data.

    trait CfiSectionMethods {
        fn e32<'a, T>(self, endian: Endian, val: T) -> Self where T: ToLabelOrNum<'a, u32>;
        fn e64<'a, T>(self, endian: Endian, val: T) -> Self where T: ToLabelOrNum<'a, u64>;
        fn sleb(self, val: i64) -> Self;
        fn uleb(self, val: u64) -> Self;
        fn cie<'input, E>(self,
                          endian: Endian,
                          cie: &mut CommonInformationEntry<'input, E>)
                          -> Self
            where E: Endianity;
        fn fde<'a, 'input, E, T>(self,
                                 endian: Endian,
                                 cie_offset: T,
                                 fde: &mut FrameDescriptionEntry<'input, E>)
                                 -> Self
            where E: Endianity,
                  T: ToLabelOrNum<'a, u64>;
    }

    impl CfiSectionMethods for Section {
        fn e32<'a, T>(self, endian: Endian, val: T) -> Self
            where T: ToLabelOrNum<'a, u32>
        {
            match endian {
                Endian::Little => self.L32(val),
                Endian::Big => self.B32(val),
            }
        }

        fn e64<'a, T>(self, endian: Endian, val: T) -> Self
            where T: ToLabelOrNum<'a, u64>
        {
            match endian {
                Endian::Little => self.L64(val),
                Endian::Big => self.B64(val),
            }
        }

        fn sleb(self, val: i64) -> Self {
            let mut buf = Vec::new();
            let written = leb128::write::signed(&mut buf, val).unwrap();
            self.append_bytes(&buf[0..written])
        }

        fn uleb(self, val: u64) -> Self {
            let mut buf = Vec::new();
            let written = leb128::write::unsigned(&mut buf, val).unwrap();
            self.append_bytes(&buf[0..written])
        }

        fn cie<'input, E>(self, endian: Endian, cie: &mut CommonInformationEntry<'input, E>) -> Self
            where E: Endianity
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
                    section.e64(endian, &length)
                        .mark(&start)
                        .e64(endian, 0xffffffffffffffff)
                }
            };

            let mut section = section.D8(cie.version);

            if let Some(augmentation) = cie.augmentation {
                section = section.append_bytes(augmentation.as_bytes());
            }

            let section = section
                // Null terminator
                .D8(0)
                .D8(cie.address_size)
                .D8(cie.segment_size)
                .uleb(cie.code_alignment_factor)
                .sleb(cie.data_alignment_factor)
                .uleb(cie.return_address_register)
                .append_bytes(cie.initial_instructions.into())
                .mark(&end);

            cie.length = (&end - &start) as u64;
            length.set_const(cie.length);

            section
        }

        fn fde<'a, 'input, E, T>(self,
                                 endian: Endian,
                                 cie_offset: T,
                                 fde: &mut FrameDescriptionEntry<'input, E>)
                                 -> Self
            where E: Endianity,
                  T: ToLabelOrNum<'a, u64>
        {
            let length = Label::new();
            let start = Label::new();
            let end = Label::new();

            assert_eq!(fde.format, fde.cie.format);
            let section = match fde.format {
                Format::Dwarf32 => {
                    let section = self.e32(endian, &length)
                        .mark(&start);
                    match cie_offset.to_labelornum() {
                        LabelOrNum::Label(ref l) => section.e32(endian, l),
                        LabelOrNum::Num(o) => section.e32(endian, o as u32),
                    }
                }
                Format::Dwarf64 => {
                    let section = self.e32(endian, 0xffffffff);
                    section.e64(endian, &length)
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
                    section.e32(endian, fde.initial_address as u32)
                        .e32(endian, fde.address_range as u32)
                }
                8 => {
                    section.e64(endian, fde.initial_address)
                        .e64(endian, fde.address_range)
                }
                x => panic!("Unsupported address size: {}", x),
            };

            let section = section.append_bytes(fde.instructions.into()).mark(&end);

            fde.length = (&end - &start) as u64;
            length.set_const(fde.length);

            section
        }
    }

    #[test]
    fn test_parse_cie_incomplete_length_32() {
        let section = Section::with_endian(Endian::Little).L16(5);
        let contents = section.get_contents().unwrap();
        assert_eq!(CommonInformationEntry::parse(EndianBuf::<LittleEndian>::new(&contents)),
                   Err(Error::UnexpectedEof));
    }

    #[test]
    fn test_parse_cie_incomplete_length_64() {
        let section = Section::with_endian(Endian::Little)
            .L32(0xffffffff)
            .L32(12345);
        let contents = section.get_contents().unwrap();
        assert_eq!(CommonInformationEntry::parse(EndianBuf::<LittleEndian>::new(&contents)),
                   Err(Error::UnexpectedEof));
    }

    #[test]
    fn test_parse_cie_incomplete_id_32() {
        let section = Section::with_endian(Endian::Big)
            // The length is not large enough to contain the ID.
            .B32(3)
            .B32(0xffffffff);
        let contents = section.get_contents().unwrap();
        assert_eq!(CommonInformationEntry::parse(EndianBuf::<BigEndian>::new(&contents)),
                   Err(Error::UnexpectedEof));
    }

    #[test]
    fn test_parse_cie_bad_id_32() {
        let section = Section::with_endian(Endian::Big)
            // Initial length
            .B32(4)
            // Not the CIE Id.
            .B32(0xbad1bad2);
        let contents = section.get_contents().unwrap();
        assert_eq!(CommonInformationEntry::parse(EndianBuf::<BigEndian>::new(&contents)),
                   Err(Error::NotCieId));
    }

    #[test]
    fn test_parse_cie_32_bad_version() {
        let mut cie = CommonInformationEntry {
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
        };

        let section = Section::with_endian(Endian::Little).cie(Endian::Little, &mut cie);

        let contents = section.get_contents().unwrap();

        assert_eq!(CommonInformationEntry::parse(EndianBuf::<LittleEndian>::new(&contents)),
                   Err(Error::UnknownVersion));
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

        let contents = section.get_contents().unwrap();

        match CommonInformationEntry::parse(EndianBuf::<LittleEndian>::new(&contents)) {
            Ok((rest, entry)) => {
                assert_eq!(rest, EndianBuf::new(&expected_rest));
                assert_eq!(entry,
                           CommonInformationEntry {
                               length: expected_length,
                               format: Format::Dwarf32,
                               version: 4,
                               augmentation: augmentation,
                               address_size: 0,
                               segment_size: 0,
                               code_alignment_factor: 0,
                               data_alignment_factor: 0,
                               return_address_register: 0,
                               initial_instructions: EndianBuf::new(&[]),
                           });
            }
            otherwise => panic!("Unexpected result: {:?}", otherwise),
        }
    }

    #[test]
    fn test_parse_cie_32_ok() {
        let expected_rest = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        let expected_instrs: Vec<_> = (0..4)
            .map(|_| constants::DW_CFA_nop.0)
            .collect();

        let mut cie = CommonInformationEntry {
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
        };

        let section = Section::with_endian(Endian::Little)
            .cie(Endian::Little, &mut cie)
            .append_bytes(&expected_rest);

        let contents = section.get_contents().unwrap();

        assert_eq!(CommonInformationEntry::parse(EndianBuf::<LittleEndian>::new(&contents)),
                   Ok((EndianBuf::new(&expected_rest), cie)));
    }

    #[test]
    fn test_parse_cie_64_ok() {
        let expected_rest = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        let expected_instrs: Vec<_> = (0..5).map(|_| constants::DW_CFA_nop.0).collect();

        let mut cie = CommonInformationEntry {
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
        };

        let section = Section::with_endian(Endian::Big)
            .cie(Endian::Big, &mut cie)
            .append_bytes(&expected_rest);

        let contents = section.get_contents().unwrap();

        assert_eq!(CommonInformationEntry::parse(EndianBuf::<BigEndian>::new(&contents)),
                   Ok((EndianBuf::new(&expected_rest), cie)));
    }

    #[test]
    fn test_parse_cie_length_too_big() {
        let expected_instrs: Vec<_> = (0..13).map(|_| constants::DW_CFA_nop.0).collect();

        let mut cie = CommonInformationEntry {
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
        };

        let section = Section::with_endian(Endian::Little).cie(Endian::Little, &mut cie);

        let mut contents = section.get_contents().unwrap();

        // Overwrite the length to be too big.
        contents[0] = 0;
        contents[1] = 0;
        contents[2] = 0;
        contents[3] = 255;

        assert_eq!(CommonInformationEntry::parse(EndianBuf::<LittleEndian>::new(&contents)),
                   Err(Error::BadLength));
    }

    #[test]
    fn test_parse_fde_incomplete_length_32() {
        let section = Section::with_endian(Endian::Little).L16(5);
        let contents = section.get_contents().unwrap();
        assert_eq!(FrameDescriptionEntry::parse(EndianBuf::<LittleEndian>::new(&contents),
                                                |_| unreachable!()),
                   Err(Error::UnexpectedEof));
    }

    #[test]
    fn test_parse_fde_incomplete_length_64() {
        let section = Section::with_endian(Endian::Little)
            .L32(0xffffffff)
            .L32(12345);
        let contents = section.get_contents().unwrap();
        assert_eq!(FrameDescriptionEntry::parse(EndianBuf::<LittleEndian>::new(&contents),
                                                |_| unreachable!()),
                   Err(Error::UnexpectedEof));
    }

    #[test]
    fn test_parse_fde_incomplete_cie_pointer_32() {
        let section = Section::with_endian(Endian::Big)
            // The length is not large enough to contain the CIE pointer.
            .B32(3)
            .B32(1994);
        let contents = section.get_contents().unwrap();
        assert_eq!(FrameDescriptionEntry::parse(EndianBuf::<BigEndian>::new(&contents),
                                                |_| unreachable!()),
                   Err(Error::UnexpectedEof));
    }

    #[test]
    fn test_parse_fde_bad_cie_pointer_32() {
        let section = Section::with_endian(Endian::Big)
            // Initial length
            .B32(4)
            // This is the CIE ID, not a valid offset pointer.
            .B32(0xffffffff);
        let contents = section.get_contents().unwrap();
        assert_eq!(FrameDescriptionEntry::parse(EndianBuf::<BigEndian>::new(&contents),
                                                |_| unreachable!()),
                   Err(Error::NotCiePointer));
    }

    #[test]
    fn test_parse_fde_32_ok() {
        let expected_rest = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        let cie_offset = 0xbad0bad1;
        let expected_instrs: Vec<_> = (0..7).map(|_| constants::DW_CFA_nop.0).collect();

        let cie = CommonInformationEntry {
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
        };

        let mut fde = FrameDescriptionEntry {
            length: 0,
            format: Format::Dwarf32,
            cie: cie.clone(),
            initial_segment: 0,
            initial_address: 0xfeedbeef,
            address_range: 39,
            instructions: EndianBuf::<LittleEndian>::new(&expected_instrs),
        };

        let section = Section::with_endian(Endian::Little)
            .fde(Endian::Little, cie_offset, &mut fde)
            .append_bytes(&expected_rest);

        let contents = section.get_contents().unwrap();
        let contents = EndianBuf::<LittleEndian>::new(&contents);

        let get_cie = |offset| {
            assert_eq!(offset, DebugFrameOffset(cie_offset as u64));
            Ok(cie.clone())
        };

        assert_eq!(FrameDescriptionEntry::parse(contents, get_cie),
                   Ok((EndianBuf::new(&expected_rest), fde)));
    }

    #[test]
    fn test_parse_fde_32_with_segment_ok() {
        let expected_rest = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        let cie_offset = 0xbad0bad1;
        let expected_instrs: Vec<_> = (0..92)
            .map(|_| constants::DW_CFA_nop.0)
            .collect();

        let cie = CommonInformationEntry {
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
        };

        let mut fde = FrameDescriptionEntry {
            length: 0,
            format: Format::Dwarf32,
            cie: cie.clone(),
            initial_segment: 0xbadbad11,
            initial_address: 0xfeedbeef,
            address_range: 999,
            instructions: EndianBuf::new(&expected_instrs),
        };

        let section = Section::with_endian(Endian::Little)
            .fde(Endian::Little, cie_offset, &mut fde)
            .append_bytes(&expected_rest);

        let contents = section.get_contents().unwrap();
        let contents = EndianBuf::<LittleEndian>::new(&contents);

        let get_cie = |offset| {
            assert_eq!(offset, DebugFrameOffset(cie_offset as u64));
            Ok(cie.clone())
        };

        assert_eq!(FrameDescriptionEntry::parse(contents, get_cie),
                   Ok((EndianBuf::new(&expected_rest), fde)));
    }

    #[test]
    fn test_parse_fde_64_ok() {
        let expected_rest = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        let cie_offset = 0xbad0bad1;
        let expected_instrs: Vec<_> = (0..7)
            .map(|_| constants::DW_CFA_nop.0)
            .collect();

        let cie = CommonInformationEntry {
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
        };

        let mut fde = FrameDescriptionEntry {
            length: 0,
            format: Format::Dwarf64,
            cie: cie.clone(),
            initial_segment: 0,
            initial_address: 0xfeedbeef,
            address_range: 999,
            instructions: EndianBuf::new(&expected_instrs),
        };

        let section = Section::with_endian(Endian::Little)
            .fde(Endian::Little, cie_offset, &mut fde)
            .append_bytes(&expected_rest);

        let contents = section.get_contents().unwrap();
        let contents = EndianBuf::<LittleEndian>::new(&contents);

        let get_cie = |offset| {
            assert_eq!(offset, DebugFrameOffset(cie_offset as u64));
            Ok(cie.clone())
        };

        assert_eq!(FrameDescriptionEntry::parse(contents, get_cie),
                   Ok((EndianBuf::new(&expected_rest), fde)));
    }

    #[test]
    fn test_parse_cfi_entry_on_cie_32_ok() {
        let expected_rest = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        let expected_instrs: Vec<_> = (0..4)
            .map(|_| constants::DW_CFA_nop.0)
            .collect();

        let mut cie = CommonInformationEntry {
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
        };

        let section = Section::with_endian(Endian::Big)
            .cie(Endian::Big, &mut cie)
            .append_bytes(&expected_rest);

        let contents = section.get_contents().unwrap();

        assert_eq!(parse_cfi_entry(EndianBuf::<BigEndian>::new(&contents)),
                   Ok((EndianBuf::new(&expected_rest), CieOrFde::Cie(cie))));
    }

    #[test]
    fn test_parse_cfi_entry_on_fde_32_ok() {
        let cie_offset = 0x12345678;
        let expected_rest = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        let expected_instrs: Vec<_> = (0..4)
            .map(|_| constants::DW_CFA_nop.0)
            .collect();

        let cie = CommonInformationEntry {
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
        };

        let mut fde = FrameDescriptionEntry {
            length: 0,
            format: Format::Dwarf32,
            cie: cie.clone(),
            initial_segment: 0,
            initial_address: 0xfeedbeef,
            address_range: 39,
            instructions: EndianBuf::<BigEndian>::new(&expected_instrs),
        };

        let section = Section::with_endian(Endian::Big)
            .fde(Endian::Big, cie_offset, &mut fde)
            .append_bytes(&expected_rest);

        let contents = section.get_contents().unwrap();

        match parse_cfi_entry(EndianBuf::<BigEndian>::new(&contents)) {
            Ok((rest, CieOrFde::Fde(partial))) => {
                assert_eq!(rest, EndianBuf::new(&expected_rest));

                assert_eq!(partial.length, fde.length);
                assert_eq!(partial.format, fde.format);
                assert_eq!(partial.cie_offset, DebugFrameOffset(cie_offset));

                let get_cie = |offset| {
                    assert_eq!(offset, DebugFrameOffset(cie_offset));
                    Ok(cie.clone())
                };

                assert_eq!(partial.parse(get_cie), Ok(fde));
            }
            otherwise => panic!("Unexpected result: {:#?}", otherwise),
        }
    }

    #[test]
    fn test_cfi_entries_iter() {
        let expected_instrs1: Vec<_> = (0..4)
            .map(|_| constants::DW_CFA_nop.0)
            .collect();

        let expected_instrs2: Vec<_> = (0..8)
            .map(|_| constants::DW_CFA_nop.0)
            .collect();

        let expected_instrs3: Vec<_> = (0..12)
            .map(|_| constants::DW_CFA_nop.0)
            .collect();

        let expected_instrs4: Vec<_> = (0..16)
            .map(|_| constants::DW_CFA_nop.0)
            .collect();

        let mut cie1 = CommonInformationEntry {
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
        };

        let mut cie2 = CommonInformationEntry {
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
        };

        let cie1_location = Label::new();
        let cie2_location = Label::new();

        // Write the CIEs first so that their length gets set before we clone
        // them into the FDEs and our equality assertions down the line end up
        // with all the CIEs always having he correct length.
        let section = Section::with_endian(Endian::Big)
            .mark(&cie1_location)
            .cie(Endian::Big, &mut cie1)
            .mark(&cie2_location)
            .cie(Endian::Big, &mut cie2);

        let mut fde1 = FrameDescriptionEntry {
            length: 0,
            format: Format::Dwarf32,
            cie: cie1.clone(),
            initial_segment: 0,
            initial_address: 0xfeedbeef,
            address_range: 39,
            instructions: EndianBuf::<BigEndian>::new(&expected_instrs3),
        };

        let mut fde2 = FrameDescriptionEntry {
            length: 0,
            format: Format::Dwarf32,
            cie: cie2.clone(),
            initial_segment: 0,
            initial_address: 0xfeedface,
            address_range: 9000,
            instructions: EndianBuf::<BigEndian>::new(&expected_instrs4),
        };

        let section = section.fde(Endian::Big, &cie1_location, &mut fde1)
            .fde(Endian::Big, &cie2_location, &mut fde2);

        section.start().set_const(0);

        let cie1_offset = cie1_location.value().unwrap();
        let cie2_offset = cie2_location.value().unwrap();

        let contents = section.get_contents().unwrap();
        let debug_frame = DebugFrame::<BigEndian>::new(&contents);

        let mut entries = debug_frame.entries();

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

        let mut cie = CommonInformationEntry {
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
        };

        let cie_location = Label::new();

        let section = Section::with_endian(Endian::Little)
            .append_bytes(&filler)
            .mark(&cie_location)
            .cie(Endian::Little, &mut cie)
            .append_bytes(&filler);

        section.start().set_const(0);

        let cie_offset = DebugFrameOffset(cie_location.value().unwrap());

        let contents = section.get_contents().unwrap();
        let debug_frame = DebugFrame::<LittleEndian>::new(&contents);

        assert_eq!(debug_frame.cie_from_offset(cie_offset), Ok(cie));
    }

    #[test]
    fn test_parse_cfi_instruction_advance_loc() {
        let expected_rest = [1, 2, 3, 4];
        let expected_delta = 42;
        let section = Section::with_endian(Endian::Little)
            .D8(constants::DW_CFA_advance_loc.0 | expected_delta)
            .append_bytes(&expected_rest);
        let contents = section.get_contents().unwrap();
        let input = EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok((EndianBuf::new(&expected_rest),
                       CallFrameInstruction::AdvanceLoc { delta: expected_delta as u32 })));
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
        let input = EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok((EndianBuf::new(&expected_rest),
                       CallFrameInstruction::Offset {
                       register: expected_reg as u64,
                       factored_offset: expected_offset,
                   })));
    }

    #[test]
    fn test_parse_cfi_instruction_restore() {
        let expected_rest = [1, 2, 3, 4];
        let expected_reg = 3;
        let section = Section::with_endian(Endian::Little)
            .D8(constants::DW_CFA_restore.0 | expected_reg)
            .append_bytes(&expected_rest);
        let contents = section.get_contents().unwrap();
        let input = EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok((EndianBuf::new(&expected_rest),
                       CallFrameInstruction::Restore { register: expected_reg as u64 })));
    }

    #[test]
    fn test_parse_cfi_instruction_nop() {
        let expected_rest = [1, 2, 3, 4];
        let section = Section::with_endian(Endian::Little)
            .D8(constants::DW_CFA_nop.0)
            .append_bytes(&expected_rest);
        let contents = section.get_contents().unwrap();
        let input = EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok((EndianBuf::new(&expected_rest), CallFrameInstruction::Nop)));
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
        let input = EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok((EndianBuf::new(&expected_rest),
                       CallFrameInstruction::SetLoc { address: expected_addr })));
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
        let input = EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok((EndianBuf::new(&expected_rest),
                       CallFrameInstruction::AdvanceLoc { delta: expected_delta as u32 })));
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
        let input = EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok((EndianBuf::new(&expected_rest),
                       CallFrameInstruction::AdvanceLoc { delta: expected_delta as u32 })));
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
        let input = EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok((EndianBuf::new(&expected_rest),
                       CallFrameInstruction::AdvanceLoc { delta: expected_delta })));
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
        let input = EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok((EndianBuf::new(&expected_rest),
                       CallFrameInstruction::Offset {
                       register: expected_reg,
                       factored_offset: expected_offset,
                   })));
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
        let input = EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok((EndianBuf::new(&expected_rest),
                       CallFrameInstruction::Restore { register: expected_reg })));
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
        let input = EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok((EndianBuf::new(&expected_rest),
                       CallFrameInstruction::Undefined { register: expected_reg })));
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
        let input = EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok((EndianBuf::new(&expected_rest),
                       CallFrameInstruction::SameValue { register: expected_reg })));
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
        let input = EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok((EndianBuf::new(&expected_rest),
                       CallFrameInstruction::Register {
                       dest_register: expected_dest_reg,
                       src_register: expected_src_reg,
                   })));
    }

    #[test]
    fn test_parse_cfi_instruction_remember_state() {
        let expected_rest = [1, 2, 3, 4];
        let section = Section::with_endian(Endian::Little)
            .D8(constants::DW_CFA_remember_state.0)
            .append_bytes(&expected_rest);
        let contents = section.get_contents().unwrap();
        let input = EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok((EndianBuf::new(&expected_rest), CallFrameInstruction::RememberState)));
    }

    #[test]
    fn test_parse_cfi_instruction_restore_state() {
        let expected_rest = [1, 2, 3, 4];
        let section = Section::with_endian(Endian::Little)
            .D8(constants::DW_CFA_restore_state.0)
            .append_bytes(&expected_rest);
        let contents = section.get_contents().unwrap();
        let input = EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok((EndianBuf::new(&expected_rest), CallFrameInstruction::RestoreState)));
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
        let input = EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok((EndianBuf::new(&expected_rest),
                       CallFrameInstruction::DefCfa {
                       register: expected_reg,
                       offset: expected_offset,
                   })));
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
        let input = EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok((EndianBuf::new(&expected_rest),
                       CallFrameInstruction::DefCfaRegister { register: expected_reg })));
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
        let input = EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok((EndianBuf::new(&expected_rest),
                       CallFrameInstruction::DefCfaOffset { offset: expected_offset })));
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
        let input = EndianBuf::<LittleEndian>::new(&contents);

        assert_eq!(CallFrameInstruction::parse(input),
                   Ok((EndianBuf::new(&expected_rest),
                       CallFrameInstruction::DefCfaExpression {
                       expression: EndianBuf::new(&expected_expr),
                   })));
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
        let input = EndianBuf::<LittleEndian>::new(&contents);

        assert_eq!(CallFrameInstruction::parse(input),
                   Ok((EndianBuf::new(&expected_rest),
                       CallFrameInstruction::Expression {
                       register: expected_reg,
                       expression: EndianBuf::new(&expected_expr),
                   })));
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
        let input = EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok((EndianBuf::new(&expected_rest),
                       CallFrameInstruction::OffsetExtendedSf {
                       register: expected_reg,
                       factored_offset: expected_offset,
                   })));
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
        let input = EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok((EndianBuf::new(&expected_rest),
                       CallFrameInstruction::DefCfaSf {
                       register: expected_reg,
                       factored_offset: expected_offset,
                   })));
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
        let input = EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok((EndianBuf::new(&expected_rest),
                       CallFrameInstruction::DefCfaOffsetSf { factored_offset: expected_offset })));
    }

    #[test]
    fn test_parse_cfi_instruction_val_offset() {
        let expected_rest = [1, 2, 3, 4];
        let expected_reg = 5000;
        let expected_offset = 23;
        let section = Section::with_endian(Endian::Little)
            .D8(constants::DW_CFA_val_offset.0)
            .uleb(expected_reg)
            .uleb(expected_offset)
            .append_bytes(&expected_rest);
        let contents = section.get_contents().unwrap();
        let input = EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok((EndianBuf::new(&expected_rest),
                       CallFrameInstruction::ValOffset {
                       register: expected_reg,
                       factored_offset: expected_offset,
                   })));
    }

    #[test]
    fn test_parse_cfi_instruction_val_offset_sf() {
        let expected_rest = [1, 2, 3, 4];
        let expected_reg = 5000;
        let expected_offset = -23;
        let section = Section::with_endian(Endian::Little)
            .D8(constants::DW_CFA_val_offset_sf.0)
            .uleb(expected_reg)
            .sleb(expected_offset)
            .append_bytes(&expected_rest);
        let contents = section.get_contents().unwrap();
        let input = EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Ok((EndianBuf::new(&expected_rest),
                       CallFrameInstruction::ValOffsetSf {
                       register: expected_reg,
                       factored_offset: expected_offset,
                   })));
    }

    #[test]
    fn test_parse_cfi_instruction_val_expression() {
        let expected_rest = [1, 2, 3, 4];
        let expected_reg = 5000;
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
        let input = EndianBuf::<LittleEndian>::new(&contents);

        assert_eq!(CallFrameInstruction::parse(input),
                   Ok((EndianBuf::new(&expected_rest),
                       CallFrameInstruction::ValExpression {
                       register: expected_reg,
                       expression: EndianBuf::new(&expected_expr),
                   })));
    }

    #[test]
    fn test_parse_cfi_instruction_unknown_instruction() {
        let expected_rest = [1, 2, 3, 4];
        let unknown_instr = constants::DwCfa(0b00111111);
        let section = Section::with_endian(Endian::Little)
            .D8(unknown_instr.0)
            .append_bytes(&expected_rest);
        let contents = section.get_contents().unwrap();
        let input = EndianBuf::<LittleEndian>::new(&contents);
        assert_eq!(CallFrameInstruction::parse(input),
                   Err(Error::UnknownCallFrameInstruction(unknown_instr)));
    }

    #[test]
    fn test_call_frame_instruction_iter_ok() {
        let expected_reg = 5000;
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
                       register: expected_reg,
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

    fn assert_eval<'a, I>(mut initial_ctx: UnwindContext<'a, LittleEndian>,
                          expected_ctx: UnwindContext<'a, LittleEndian>,
                          cie: CommonInformationEntry<'a, LittleEndian>,
                          fde: Option<FrameDescriptionEntry<'a, LittleEndian>>,
                          instructions: I)
        where I: AsRef<[(Result<bool>, CallFrameInstruction<'a, LittleEndian>)]>
    {
        {
            let mut table = UnwindTable::new_internal(&mut initial_ctx, &cie, fde.as_ref());
            for &(ref expected_result, ref instruction) in instructions.as_ref() {
                assert_eq!(*expected_result, table.evaluate(instruction.clone()));
            }
        }

        assert_eq!(expected_ctx, initial_ctx);
    }

    fn make_test_cie<'a>() -> CommonInformationEntry<'a, LittleEndian> {
        CommonInformationEntry {
            format: Format::Dwarf64,
            length: 0,
            return_address_register: 0,
            version: 4,
            address_size: 8,
            initial_instructions: EndianBuf::new(&[]),
            augmentation: None,
            segment_size: 0,
            data_alignment_factor: 2,
            code_alignment_factor: 3,
        }
    }

    #[test]
    fn test_eval_set_loc() {
        let cie = make_test_cie();
        let ctx = UnwindContext::new();
        let mut expected = ctx.clone();
        expected.row_mut().end_address = 42;
        let instructions = [(Ok(true), CallFrameInstruction::SetLoc { address: 42 })];
        assert_eval(ctx, expected, cie, None, instructions);
    }

    #[test]
    fn test_eval_set_loc_backwards() {
        let cie = make_test_cie();
        let mut ctx = UnwindContext::new();
        ctx.row_mut().start_address = 999;
        let expected = ctx.clone();
        let instructions = [(Err(Error::InvalidAddressRange),
                             CallFrameInstruction::SetLoc { address: 42 })];
        assert_eval(ctx, expected, cie, None, instructions);
    }

    #[test]
    fn test_eval_advance_loc() {
        let cie = make_test_cie();
        let mut ctx = UnwindContext::new();
        ctx.row_mut().start_address = 3;
        let mut expected = ctx.clone();
        expected.row_mut().end_address = 4;
        let instructions = [(Ok(true), CallFrameInstruction::AdvanceLoc { delta: 1 })];
        assert_eval(ctx, expected, cie, None, instructions);
    }

    #[test]
    fn test_eval_def_cfa() {
        let cie = make_test_cie();
        let ctx = UnwindContext::new();
        let mut expected = ctx.clone();
        expected.set_cfa(CfaRule::RegisterAndOffset {
            register: 1993,
            offset: 36,
        });
        let instructions = [(Ok(false),
                             CallFrameInstruction::DefCfa {
                                register: 1993,
                                offset: 36,
                            })];
        assert_eval(ctx, expected, cie, None, instructions);
    }

    #[test]
    fn test_eval_def_cfa_sf() {
        let cie = make_test_cie();
        let ctx = UnwindContext::new();
        let mut expected = ctx.clone();
        expected.set_cfa(CfaRule::RegisterAndOffset {
            register: 1993,
            offset: 36 * cie.data_alignment_factor as i64,
        });
        let instructions = [(Ok(false),
                             CallFrameInstruction::DefCfaSf {
                                register: 1993,
                                factored_offset: 36,
                            })];
        assert_eval(ctx, expected, cie, None, instructions);
    }

    #[test]
    fn test_eval_def_cfa_register() {
        let cie = make_test_cie();
        let mut ctx = UnwindContext::new();
        ctx.set_cfa(CfaRule::RegisterAndOffset {
            register: 3,
            offset: 8,
        });
        let mut expected = ctx.clone();
        expected.set_cfa(CfaRule::RegisterAndOffset {
            register: 1993,
            offset: 8,
        });
        let instructions = [(Ok(false), CallFrameInstruction::DefCfaRegister { register: 1993 })];
        assert_eval(ctx, expected, cie, None, instructions);
    }

    #[test]
    fn test_eval_def_cfa_register_invalid_context() {
        let cie = make_test_cie();
        let mut ctx = UnwindContext::new();
        ctx.set_cfa(CfaRule::Expression(EndianBuf::new(&[])));
        let expected = ctx.clone();
        let instructions = [(Err(Error::CfiInstructionInInvalidContext),
                             CallFrameInstruction::DefCfaRegister { register: 1993 })];
        assert_eval(ctx, expected, cie, None, instructions);
    }

    #[test]
    fn test_eval_def_cfa_offset() {
        let cie = make_test_cie();
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
        let cie = make_test_cie();
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
        let cie = make_test_cie();
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
        let cie = make_test_cie();
        let ctx = UnwindContext::new();
        let mut expected = ctx.clone();
        expected.set_register_rule(5, RegisterRule::Undefined);
        let instructions = [(Ok(false), CallFrameInstruction::Undefined { register: 5 })];
        assert_eval(ctx, expected, cie, None, instructions);
    }

    #[test]
    fn test_eval_same_value() {
        let cie = make_test_cie();
        let ctx = UnwindContext::new();
        let mut expected = ctx.clone();
        expected.set_register_rule(0, RegisterRule::SameValue);
        let instructions = [(Ok(false), CallFrameInstruction::SameValue { register: 0 })];
        assert_eval(ctx, expected, cie, None, instructions);
    }

    #[test]
    fn test_eval_offset() {
        let cie = make_test_cie();
        let ctx = UnwindContext::new();
        let mut expected = ctx.clone();
        expected.set_register_rule(2, RegisterRule::Offset(3 * cie.data_alignment_factor));
        let instructions = [(Ok(false),
                             CallFrameInstruction::Offset {
                                register: 2,
                                factored_offset: 3,
                            })];
        assert_eval(ctx, expected, cie, None, instructions);
    }

    #[test]
    fn test_eval_offset_extended_sf() {
        let cie = make_test_cie();
        let ctx = UnwindContext::new();
        let mut expected = ctx.clone();
        expected.set_register_rule(4, RegisterRule::Offset(-3 * cie.data_alignment_factor));
        let instructions = [(Ok(false),
                             CallFrameInstruction::OffsetExtendedSf {
                                register: 4,
                                factored_offset: -3,
                            })];
        assert_eval(ctx, expected, cie, None, instructions);
    }

    #[test]
    fn test_eval_val_offset() {
        let cie = make_test_cie();
        let ctx = UnwindContext::new();
        let mut expected = ctx.clone();
        expected.set_register_rule(5, RegisterRule::ValOffset(7 * cie.data_alignment_factor));
        let instructions = [(Ok(false),
                             CallFrameInstruction::ValOffset {
                                register: 5,
                                factored_offset: 7,
                            })];
        assert_eval(ctx, expected, cie, None, instructions);
    }

    #[test]
    fn test_eval_val_offset_sf() {
        let cie = make_test_cie();
        let ctx = UnwindContext::new();
        let mut expected = ctx.clone();
        expected.set_register_rule(5, RegisterRule::ValOffset(-7 * cie.data_alignment_factor));
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
        let cie = make_test_cie();
        let ctx = UnwindContext::new();
        let mut expected = ctx.clone();
        expected.set_register_rule(9, RegisterRule::Expression(EndianBuf::new(&expr)));
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
        let cie = make_test_cie();
        let ctx = UnwindContext::new();
        let mut expected = ctx.clone();
        expected.set_register_rule(9, RegisterRule::ValExpression(EndianBuf::new(&expr)));
        let instructions = [(Ok(false),
                             CallFrameInstruction::ValExpression {
                                register: 9,
                                expression: EndianBuf::new(&expr),
                            })];
        assert_eval(ctx, expected, cie, None, instructions);
    }

    #[test]
    fn test_eval_restore() {
        let cie = make_test_cie();
        let fde = FrameDescriptionEntry {
            format: Format::Dwarf64,
            length: 0,
            address_range: 0,
            initial_address: 0,
            initial_segment: 0,
            cie: cie.clone(),
            instructions: EndianBuf::new(&[]),
        };

        let mut ctx = UnwindContext::new();
        ctx.set_register_rule(0, RegisterRule::Offset(1));
        ctx.save_initial_rules();
        let expected = ctx.clone();
        ctx.set_register_rule(0, RegisterRule::Offset(2));

        let instructions = [(Ok(false), CallFrameInstruction::Restore { register: 0 })];
        assert_eval(ctx, expected, cie, Some(fde), instructions);
    }

    #[test]
    fn test_eval_restore_havent_saved_initial_context() {
        let cie = make_test_cie();
        let ctx = UnwindContext::new();
        let expected = ctx.clone();
        let instructions = [(Err(Error::CfiInstructionInInvalidContext),
                             CallFrameInstruction::Restore { register: 0 })];
        assert_eval(ctx, expected, cie, None, instructions);
    }

    #[test]
    fn test_eval_remember_state() {
        let cie = make_test_cie();
        let ctx = UnwindContext::new();
        let mut expected = ctx.clone();
        expected.push_row();
        let instructions = [(Ok(false), CallFrameInstruction::RememberState)];
        assert_eval(ctx, expected, cie, None, instructions);
    }

    #[test]
    fn test_eval_restore_state() {
        let cie = make_test_cie();

        let mut ctx = UnwindContext::new();
        ctx.set_register_rule(0, RegisterRule::SameValue);
        let expected = ctx.clone();
        ctx.push_row();
        ctx.set_register_rule(0, RegisterRule::Offset(16));

        let instructions = [// First one pops just fine.
                            (Ok(false), CallFrameInstruction::RestoreState),
                            // Second pop would try to pop out of bounds.
                            (Err(Error::PopWithEmptyStack), CallFrameInstruction::RestoreState)];

        assert_eval(ctx, expected, cie, None, instructions);
    }

    #[test]
    fn test_eval_nop() {
        let cie = make_test_cie();
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

        let cie = CommonInformationEntry {
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

        let fde = FrameDescriptionEntry {
            length: 0,
            format: Format::Dwarf32,
            cie: cie.clone(),
            initial_segment: 0,
            initial_address: 0,
            address_range: 100,
            instructions: EndianBuf::<LittleEndian>::new(&instructions),
        };

        let ctx = UninitializedUnwindContext::new();
        ctx.0.assert_fully_uninitialized();
        let mut ctx = ctx.initialize(&cie).expect("Should run initial program OK");

        assert!(ctx.0.is_initialized);
        let expected_initial_rules = [RegisterRule::Offset(8),
                                      RegisterRule::Undefined,
                                      RegisterRule::Undefined,
                                      RegisterRule::Offset(4)];
        assert_eq!(&ctx.0.initial_rules[..], &expected_initial_rules[..]);

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
                registers: vec![RegisterRule::Offset(8),
                                RegisterRule::Undefined,
                                RegisterRule::Undefined,
                                RegisterRule::Offset(4)],
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
                registers: vec![RegisterRule::Offset(-16),
                                RegisterRule::Undefined,
                                RegisterRule::Undefined,
                                RegisterRule::Offset(4)],
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
                registers: vec![RegisterRule::Offset(-16),
                                RegisterRule::Undefined,
                                RegisterRule::Undefined,
                                RegisterRule::Offset(-4)],
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
                registers: vec![RegisterRule::Offset(-16),
                                RegisterRule::Undefined,
                                RegisterRule::Undefined,
                                RegisterRule::Offset(-4),
                                RegisterRule::Undefined,
                                RegisterRule::Offset(4)],
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

        let instrs2: Vec<_> = (0..8)
            .map(|_| constants::DW_CFA_nop.0)
            .collect();

        let instrs3 = Section::with_endian(Endian::Big)
            // Initial instructions form a row, advance the address by 100.
            .D8(constants::DW_CFA_advance_loc1.0)
            .D8(100)
            // Register 0 is -16 from the CFA.
            .D8(constants::DW_CFA_offset_extended_sf.0)
            .uleb(0)
            .sleb(-16);
        let instrs3 = instrs3.get_contents().unwrap();

        let instrs4: Vec<_> = (0..16)
            .map(|_| constants::DW_CFA_nop.0)
            .collect();

        let mut cie1 = CommonInformationEntry {
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
        };

        let mut cie2 = CommonInformationEntry {
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
        };

        let cie1_location = Label::new();
        let cie2_location = Label::new();

        // Write the CIEs first so that their length gets set before we clone
        // them into the FDEs and our equality assertions down the line end up
        // with all the CIEs always having he correct length.
        let section = Section::with_endian(Endian::Big)
            .mark(&cie1_location)
            .cie(Endian::Big, &mut cie1)
            .mark(&cie2_location)
            .cie(Endian::Big, &mut cie2);

        let mut fde1 = FrameDescriptionEntry {
            length: 0,
            format: Format::Dwarf32,
            cie: cie1.clone(),
            initial_segment: 0,
            initial_address: 0xfeedbeef,
            address_range: 200,
            instructions: EndianBuf::<BigEndian>::new(&instrs3),
        };

        let mut fde2 = FrameDescriptionEntry {
            length: 0,
            format: Format::Dwarf32,
            cie: cie2.clone(),
            initial_segment: 0,
            initial_address: 0xfeedface,
            address_range: 9000,
            instructions: EndianBuf::<BigEndian>::new(&instrs4),
        };

        let section = section.fde(Endian::Big, &cie1_location, &mut fde1)
            .fde(Endian::Big, &cie2_location, &mut fde2);
        section.start().set_const(0);

        let contents = section.get_contents().unwrap();
        let debug_frame = DebugFrame::<BigEndian>::new(&contents);

        // Get the second row of the unwind table in `instrs3`.
        let ctx = UninitializedUnwindContext::new();
        let result = debug_frame.unwind_info_for_address(ctx, 0xfeedbeef + 150);
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
                       registers: vec![RegisterRule::Offset(-16)],
                   });
    }

    #[test]
    fn test_unwind_info_for_address_not_found() {
        let debug_frame = DebugFrame::<NativeEndian>::new(&[]);
        let ctx = UninitializedUnwindContext::new();
        let result = debug_frame.unwind_info_for_address(ctx, 0xbadbad99);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::NoUnwindInfoForAddress);
    }
}
