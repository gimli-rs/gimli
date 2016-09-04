use endianity::{Endianity, EndianBuf};
use parser::{Error, Format, ParseResult, parse_address, parse_initial_length,
             parse_null_terminated_string, parse_signed_leb, parse_u8, parse_unsigned_leb,
             parse_word};
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
}

fn is_cie_id(format: Format, id: u64) -> bool {
    match format {
        Format::Dwarf32 => id == 0xffffffff,
        Format::Dwarf64 => id == 0xffffffffffffffff,
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
    #[allow(dead_code)]
    fn parse
        (input: EndianBuf<'input, Endian>)
         -> ParseResult<(EndianBuf<'input, Endian>, CommonInformationEntry<'input, Endian>)> {
        let (rest, (length, format)) = try!(parse_initial_length(input));
        if length as usize > rest.len() {
            return Err(Error::BadLength);
        }

        let rest_rest = rest.range_from(length as usize..);
        let rest = rest.range_to(..length as usize);

        let (rest, cie_id) = try!(parse_word(rest, format));
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

            return Ok((rest_rest, entry));
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

        Ok((rest_rest, entry))
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
    fn parse<F>
        (input: EndianBuf<'input, Endian>,
         mut get_cie: F)
         -> ParseResult<(EndianBuf<'input, Endian>, FrameDescriptionEntry<'input, Endian>)>
        where F: FnMut(DebugFrameOffset) -> ParseResult<CommonInformationEntry<'input, Endian>>
    {
        let (rest, (length, format)) = try!(parse_initial_length(input));
        if length as usize > rest.len() {
            return Err(Error::BadLength);
        }
        let rest_rest = rest.range_from(length as usize..);
        let rest = rest.range_to(..length as usize);

        let (rest, cie_pointer) = try!(parse_word(rest, format));
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

        Ok((rest_rest, entry))
    }
}

/// An entry in the abstract CFI table that describes how to find the value of a
/// register.
///
/// "The register columns contain rules that describe whether a given register
/// has been saved and the rule to find the value for the register in the
/// previous frame."
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

#[cfg(test)]
mod tests {
    extern crate leb128;
    extern crate test_assembler;

    use super::*;
    use constants;
    use endianity::{BigEndian, Endianity, EndianBuf, LittleEndian};
    use parser::{Error, Format};
    use self::test_assembler::{Endian, Label, LabelMaker, Section, ToLabelOrNum};

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
        fn fde<'input, E>(self,
                          endian: Endian,
                          cie_offset: u64,
                          fde: &mut FrameDescriptionEntry<'input, E>)
                          -> Self
            where E: Endianity;
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

        fn fde<'input, E>(self,
                          endian: Endian,
                          cie_offset: u64,
                          fde: &mut FrameDescriptionEntry<'input, E>)
                          -> Self
            where E: Endianity
        {
            let length = Label::new();
            let start = Label::new();
            let end = Label::new();

            assert_eq!(fde.format, fde.cie.format);
            let section = match fde.format {
                Format::Dwarf32 => {
                    self.e32(endian, &length)
                        .mark(&start)
                        .e32(endian, cie_offset as u32)
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
}