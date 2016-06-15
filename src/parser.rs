//! TODO FITZGEN

use leb128;
use nom::{Err, ErrorKind, IResult, le_u8, Needed};
use std::collections::hash_map;
use std::fmt;

/// TODO FITZGEN
#[derive(Debug)]
pub enum Error {
    /// TODO FITZGEN
    LebError(leb128::read::Error),

    /// TODO FITZGEN
    AbbreviationCodeZero,

    /// TODO FITZGEN
    InvalidAbbreviationTag,

    /// TODO FITZGEN
    InvalidAbbreviationHasChildren,

    /// TODO FITZGEN
    InvalidAttributeName,

    /// TODO FITZGEN
    InvalidAttributeForm,

    /// TODO FITZGEN
    ExpectedZero,

    /// TODO FITZGEN
    DuplicateAbbreviationCode,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "gimli::parser::Error")
    }
}

impl ::std::error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::LebError(_) =>
                "Error parsing LEB128 value",
            Error::AbbreviationCodeZero =>
                "Abbreviation declared its code to be the reserved code 0",
            Error::InvalidAbbreviationTag =>
                "The abbreviation tag is invalid",
            Error::InvalidAbbreviationHasChildren =>
                "The \"does-the-abbreviation-have-children?\" byte is not DW_CHILDREN_yes or DW_CHILDREN_no",
            Error::InvalidAttributeName =>
                "The abbreviation's attribute name is invalid",
            Error::InvalidAttributeForm =>
                "The abbreviation's attribute form is invalid",
            Error::ExpectedZero =>
                "Expected zero",
            Error::DuplicateAbbreviationCode =>
                "Found an abbreviation with a code that has already been used"
        }
    }

    fn cause(&self) -> Option<&::std::error::Error> {
        match *self {
            Error::LebError(ref e) => Some(e),
            Error::AbbreviationCodeZero => None,
            Error::InvalidAbbreviationTag => None,
            Error::InvalidAbbreviationHasChildren => None,
            Error::InvalidAttributeName => None,
            Error::InvalidAttributeForm => None,
            Error::ExpectedZero => None,
            Error::DuplicateAbbreviationCode => None,
        }
    }
}

/// TODO FITZGEN
pub type ParseResult<'a, T> = IResult<&'a [u8], T, Error>;

/// TODO FITZGEN
fn parse_unsigned_leb(mut input: &[u8]) -> ParseResult<u64> {
    match leb128::read::unsigned(&mut input) {
        Ok(val) =>
            IResult::Done(input, val),
        Err(leb128::read::Error::UnexpectedEndOfData) =>
            IResult::Incomplete(Needed::Unknown),
        Err(e) =>
            IResult::Error(Err::Position(ErrorKind::Custom(Error::LebError(e)), input)),
    }
}

// /// TODO FITZGEN
// fn parse_signed_leb(mut input: &[u8]) -> ParseResult<i64> {
//     match leb128::read::signed(&mut input) {
//         Ok(val) =>
//             IResult::Done(input, val),
//         Err(leb128::read::Error::UnexpectedEndOfData) =>
//             IResult::Incomplete(Needed::Unknown),
//         Err(e) =>
//             IResult::Error(Err::Position(ErrorKind::Custom(Error::LebError(e)), input)),
//     }
// }

/// TODO FITZGEN
fn parse_abbreviation_code(mut input: &[u8]) -> ParseResult<u64> {
    match parse_unsigned_leb(&mut input) {
        IResult::Done(input, val) =>
            if val == 0 {
                IResult::Error(Err::Position(ErrorKind::Custom(Error::AbbreviationCodeZero),
                                             input))
            } else {
                IResult::Done(input, val)
            },
        res =>
            res,
    }
}

/// TODO FITZGEN
///
/// DWARF standard 4, section 7.5.4, page 154
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum AbbreviationTag {
    ArrayType = 0x01,
    ClassType = 0x02,
    EntryPoint = 0x03,
    EnumerationType = 0x04,
    FormalParameter = 0x05,
    ImportedDeclaration = 0x08,
    Label = 0x0a,
    LexicalBlock = 0x0b,
    Member = 0x0d,
    PointerType = 0x0f,
    ReferenceType = 0x10,
    CompileUnit = 0x11,
    StringType = 0x12,
    StructureType = 0x13,
    SubroutineType = 0x15,
    Typedef = 0x16,
    UnionType = 0x17,
    UnspecifiedParameters = 0x18,
    Variant = 0x19,
    CommonBlock = 0x1a,
    CommonInclusion = 0x1b,
    Inheritance = 0x1c,
    InlinedSubroutine = 0x1d,
    Module = 0x1e,
    PtrToMemberType = 0x1f,
    SetType = 0x20,
    SubrangeType = 0x21,
    WithStmt = 0x22,
    AccessDeclaration = 0x23,
    BaseType = 0x24,
    CatchBlock = 0x25,
    ConstType = 0x26,
    Constant = 0x27,
    Enumerator = 0x28,
    FileType = 0x29,
    Friend = 0x2a,
    Namelist = 0x2b,
    NamelistItem = 0x2c,
    PackedType = 0x2d,
    Subprogram = 0x2e,
    TemplateTypeParameter = 0x2f,
    TemplateValueParameter = 0x30,
    ThrownType = 0x31,
    TryBlock = 0x32,
    VariantPart = 0x33,
    Variable = 0x34,
    VolatileType = 0x35,
    DwarfProcedure = 0x36,
    RestrictType = 0x37,
    InterfaceType = 0x38,
    Namespace = 0x39,
    ImportedModule = 0x3a,
    UnspecifiedType = 0x3b,
    PartialUnit = 0x3c,
    ImportedUnit = 0x3d,
    Condition = 0x3f,
    SharedType = 0x40,
    TypeUnit = 0x41,
    RvalueReferenceType = 0x42,
    TemplateAlias = 0x43,
    LoUser = 0x4080,
    HiUser = 0xffff,
}

/// TODO FITZGEN
fn parse_abbreviation_tag(mut input: &[u8]) -> ParseResult<AbbreviationTag> {
    match parse_unsigned_leb(&mut input) {
        IResult::Done(input, val) if AbbreviationTag::ArrayType as u64 == val =>
            IResult::Done(input, AbbreviationTag::ArrayType),

        IResult::Done(input, val) if AbbreviationTag::ClassType as u64 == val =>
            IResult::Done(input, AbbreviationTag::ClassType),

        IResult::Done(input, val) if AbbreviationTag::EntryPoint as u64 == val =>
            IResult::Done(input, AbbreviationTag::EntryPoint),

        IResult::Done(input, val) if AbbreviationTag::EnumerationType as u64 == val =>
            IResult::Done(input, AbbreviationTag::EnumerationType),

        IResult::Done(input, val) if AbbreviationTag::FormalParameter as u64 == val =>
            IResult::Done(input, AbbreviationTag::FormalParameter),

        IResult::Done(input, val) if AbbreviationTag::ImportedDeclaration as u64 == val =>
            IResult::Done(input, AbbreviationTag::ImportedDeclaration),

        IResult::Done(input, val) if AbbreviationTag::Label as u64 == val =>
            IResult::Done(input, AbbreviationTag::Label),

        IResult::Done(input, val) if AbbreviationTag::LexicalBlock as u64 == val =>
            IResult::Done(input, AbbreviationTag::LexicalBlock),

        IResult::Done(input, val) if AbbreviationTag::Member as u64 == val =>
            IResult::Done(input, AbbreviationTag::Member),

        IResult::Done(input, val) if AbbreviationTag::PointerType as u64 == val =>
            IResult::Done(input, AbbreviationTag::PointerType),

        IResult::Done(input, val) if AbbreviationTag::ReferenceType as u64 == val =>
            IResult::Done(input, AbbreviationTag::ReferenceType),

        IResult::Done(input, val) if AbbreviationTag::CompileUnit as u64 == val =>
            IResult::Done(input, AbbreviationTag::CompileUnit),

        IResult::Done(input, val) if AbbreviationTag::StringType as u64 == val =>
            IResult::Done(input, AbbreviationTag::StringType),

        IResult::Done(input, val) if AbbreviationTag::StructureType as u64 == val =>
            IResult::Done(input, AbbreviationTag::StructureType),

        IResult::Done(input, val) if AbbreviationTag::SubroutineType as u64 == val =>
            IResult::Done(input, AbbreviationTag::SubroutineType),

        IResult::Done(input, val) if AbbreviationTag::Typedef as u64 == val =>
            IResult::Done(input, AbbreviationTag::Typedef),

        IResult::Done(input, val) if AbbreviationTag::UnionType as u64 == val =>
            IResult::Done(input, AbbreviationTag::UnionType),

        IResult::Done(input, val) if AbbreviationTag::UnspecifiedParameters as u64 == val =>
            IResult::Done(input, AbbreviationTag::UnspecifiedParameters),

        IResult::Done(input, val) if AbbreviationTag::Variant as u64 == val =>
            IResult::Done(input, AbbreviationTag::Variant),

        IResult::Done(input, val) if AbbreviationTag::CommonBlock as u64 == val =>
            IResult::Done(input, AbbreviationTag::CommonBlock),

        IResult::Done(input, val) if AbbreviationTag::CommonInclusion as u64 == val =>
            IResult::Done(input, AbbreviationTag::CommonInclusion),

        IResult::Done(input, val) if AbbreviationTag::Inheritance as u64 == val =>
            IResult::Done(input, AbbreviationTag::Inheritance),

        IResult::Done(input, val) if AbbreviationTag::InlinedSubroutine as u64 == val =>
            IResult::Done(input, AbbreviationTag::InlinedSubroutine),

        IResult::Done(input, val) if AbbreviationTag::Module as u64 == val =>
            IResult::Done(input, AbbreviationTag::Module),

        IResult::Done(input, val) if AbbreviationTag::PtrToMemberType as u64 == val =>
            IResult::Done(input, AbbreviationTag::PtrToMemberType),

        IResult::Done(input, val) if AbbreviationTag::SetType as u64 == val =>
            IResult::Done(input, AbbreviationTag::SetType),

        IResult::Done(input, val) if AbbreviationTag::SubrangeType as u64 == val =>
            IResult::Done(input, AbbreviationTag::SubrangeType),

        IResult::Done(input, val) if AbbreviationTag::WithStmt as u64 == val =>
            IResult::Done(input, AbbreviationTag::WithStmt),

        IResult::Done(input, val) if AbbreviationTag::AccessDeclaration as u64 == val =>
            IResult::Done(input, AbbreviationTag::AccessDeclaration),

        IResult::Done(input, val) if AbbreviationTag::BaseType as u64 == val =>
            IResult::Done(input, AbbreviationTag::BaseType),

        IResult::Done(input, val) if AbbreviationTag::CatchBlock as u64 == val =>
            IResult::Done(input, AbbreviationTag::CatchBlock),

        IResult::Done(input, val) if AbbreviationTag::ConstType as u64 == val =>
            IResult::Done(input, AbbreviationTag::ConstType),

        IResult::Done(input, val) if AbbreviationTag::Constant as u64 == val =>
            IResult::Done(input, AbbreviationTag::Constant),

        IResult::Done(input, val) if AbbreviationTag::Enumerator as u64 == val =>
            IResult::Done(input, AbbreviationTag::Enumerator),

        IResult::Done(input, val) if AbbreviationTag::FileType as u64 == val =>
            IResult::Done(input, AbbreviationTag::FileType),

        IResult::Done(input, val) if AbbreviationTag::Friend as u64 == val =>
            IResult::Done(input, AbbreviationTag::Friend),

        IResult::Done(input, val) if AbbreviationTag::Namelist as u64 == val =>
            IResult::Done(input, AbbreviationTag::Namelist),

        IResult::Done(input, val) if AbbreviationTag::NamelistItem as u64 == val =>
            IResult::Done(input, AbbreviationTag::NamelistItem),

        IResult::Done(input, val) if AbbreviationTag::PackedType as u64 == val =>
            IResult::Done(input, AbbreviationTag::PackedType),

        IResult::Done(input, val) if AbbreviationTag::Subprogram as u64 == val =>
            IResult::Done(input, AbbreviationTag::Subprogram),

        IResult::Done(input, val) if AbbreviationTag::TemplateTypeParameter as u64 == val =>
            IResult::Done(input, AbbreviationTag::TemplateTypeParameter),

        IResult::Done(input, val) if AbbreviationTag::TemplateValueParameter as u64 == val =>
            IResult::Done(input, AbbreviationTag::TemplateValueParameter),

        IResult::Done(input, val) if AbbreviationTag::ThrownType as u64 == val =>
            IResult::Done(input, AbbreviationTag::ThrownType),

        IResult::Done(input, val) if AbbreviationTag::TryBlock as u64 == val =>
            IResult::Done(input, AbbreviationTag::TryBlock),

        IResult::Done(input, val) if AbbreviationTag::VariantPart as u64 == val =>
            IResult::Done(input, AbbreviationTag::VariantPart),

        IResult::Done(input, val) if AbbreviationTag::Variable as u64 == val =>
            IResult::Done(input, AbbreviationTag::Variable),

        IResult::Done(input, val) if AbbreviationTag::VolatileType as u64 == val =>
            IResult::Done(input, AbbreviationTag::VolatileType),

        IResult::Done(input, val) if AbbreviationTag::RestrictType as u64 == val =>
            IResult::Done(input, AbbreviationTag::RestrictType),

        IResult::Done(input, val) if AbbreviationTag::InterfaceType as u64 == val =>
            IResult::Done(input, AbbreviationTag::InterfaceType),

        IResult::Done(input, val) if AbbreviationTag::Namespace as u64 == val =>
            IResult::Done(input, AbbreviationTag::Namespace),

        IResult::Done(input, val) if AbbreviationTag::ImportedModule as u64 == val =>
            IResult::Done(input, AbbreviationTag::ImportedModule),

        IResult::Done(input, val) if AbbreviationTag::UnspecifiedType as u64 == val =>
            IResult::Done(input, AbbreviationTag::UnspecifiedType),

        IResult::Done(input, val) if AbbreviationTag::PartialUnit as u64 == val =>
            IResult::Done(input, AbbreviationTag::PartialUnit),

        IResult::Done(input, val) if AbbreviationTag::ImportedUnit as u64 == val =>
            IResult::Done(input, AbbreviationTag::ImportedUnit),

        IResult::Done(input, val) if AbbreviationTag::Condition as u64 == val =>
            IResult::Done(input, AbbreviationTag::Condition),

        IResult::Done(input, val) if AbbreviationTag::SharedType as u64 == val =>
            IResult::Done(input, AbbreviationTag::SharedType),

        IResult::Done(input, val) if AbbreviationTag::TypeUnit as u64 == val =>
            IResult::Done(input, AbbreviationTag::TypeUnit),

        IResult::Done(input, val) if AbbreviationTag::RvalueReferenceType as u64 == val =>
            IResult::Done(input, AbbreviationTag::RvalueReferenceType),

        IResult::Done(input, val) if AbbreviationTag::TemplateAlias as u64 == val =>
            IResult::Done(input, AbbreviationTag::TemplateAlias),

        IResult::Done(input, val) if AbbreviationTag::LoUser as u64 == val =>
            IResult::Done(input, AbbreviationTag::LoUser),

        IResult::Done(input, val) if AbbreviationTag::HiUser as u64 == val =>
            IResult::Done(input, AbbreviationTag::HiUser),

        IResult::Done(input, _) =>
            IResult::Error(Err::Position(ErrorKind::Custom(Error::InvalidAbbreviationTag), input)),

        IResult::Incomplete(needed) =>
            IResult::Incomplete(needed),

        IResult::Error(error) =>
            IResult::Error(error),
    }
}

/// TODO FITZGEN
///
/// DWARF standard 4, section 7.5.4, page 154
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbbreviationHasChildren {
    /// TODO FITZGEN
    Yes = 0x0,

    /// TODO FITZGEN
    No = 0x1,
}

/// TODO FITZGEN
fn parse_abbreviation_has_children(input: &[u8]) -> ParseResult<AbbreviationHasChildren> {
    match le_u8(input) {
        IResult::Done(input, val) if AbbreviationHasChildren::Yes as u8 == val =>
            IResult::Done(input, AbbreviationHasChildren::Yes),

        IResult::Done(input, val) if AbbreviationHasChildren::No as u8 == val =>
            IResult::Done(input, AbbreviationHasChildren::No),

        IResult::Done(input, _) =>
            IResult::Error(
                Err::Position(ErrorKind::Custom(Error::InvalidAbbreviationHasChildren), input)),

        IResult::Incomplete(needed) =>
            IResult::Incomplete(needed),

        IResult::Error(_) =>
            IResult::Error(Err::Code(ErrorKind::Custom(Error::InvalidAbbreviationHasChildren))),
    }
}

/// TODO FITZGEN
///
/// DWARF standard 4, section 7.5.4, page 155
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum AttributeName {
    Sibling = 0x1,
    Location = 0x2,
    Name = 0x3,
    Ordering = 0x9,
    ByteSize = 0xb,
    BitOffset = 0xc,
    BitSize = 0x0d,
    StmtList = 0x10,
    LowPc = 0x11,
    HighPc = 0x12,
    Language = 0x13,
    Discr = 0x15,
    DiscrValue = 0x16,
    Visibility = 0x17,
    Import = 0x18,
    StringLength = 0x19,
    CommonReference = 0x1a,
    CompDir = 0x1b,
    ConstValue = 0x1c,
    ContainingType = 0x1d,
    DefaultValue = 0x1e,
    Inline = 0x20,
    IsOptional = 0x21,
    LowerBound = 0x22,
    Producer = 0x25,
    Prototyped = 0x27,
    ReturnAddr = 0x2a,
    StartScope = 0x2c,
    BitStride = 0x2e,
    UpperBound = 0x2f,
    AbstractOrigin = 0x31,
    Accessibility = 0x32,
    AddressClass = 0x33,
    Artificial = 0x34,
    BaseTypes = 0x35,
    CallingConvention = 0x36,
    Count = 0x37,
    DataMemberLocation = 0x38,
    DeclColumn = 0x39,
    DeclFile = 0x3a,
    DeclLine = 0x3b,
    Declaration = 0x3c,
    DiscrList = 0x3d,
    Encoding = 0x3e,
    External = 0x3f,
    FrameBase = 0x40,
    Friend = 0x41,
    IdentifierCase = 0x42,
    MacroInfo = 0x43,
    NamelistItem = 0x44,
    Priority = 0x45,
    Segment = 0x46,
    Specification = 0x47,
    StaticLink = 0x48,
    Type = 0x49,
    UseLocation = 0x4a,
    VariableParameter = 0x4b,
    Virtuality = 0x4c,
    VtableElemLocation = 0x4d,
    Allocated = 0x4e,
    Associated = 0x4f,
    DataLocation = 0x50,
    ByteStride = 0x51,
    EntryPc = 0x52,
    UseUtf8 = 0x53,
    Extension = 0x54,
    Ranges = 0x55,
    Trampoline = 0x56,
    CallColumn = 0x57,
    CallFile = 0x58,
    CallLine = 0x59,
    Description = 0x5a,
    BinaryScale = 0x5b,
    DecimalScale = 0x5c,
    Small = 0x5d,
    DecimalSign = 0x5e,
    DigitCount = 0x5f,
    PictureString = 0x60,
    Mutable = 0x61,
    ThreadsScaled = 0x62,
    Explicit = 0x63,
    ObjectPointer = 0x64,
    Endianity = 0x65,
    Elemental = 0x66,
    Pure = 0x67,
    Recursive = 0x68,
    Signature = 0x69,
    MainSubprogram = 0x6a,
    DataBitOffset = 0x6b,
    ConstExpr = 0x6c,
    EnumClass = 0x6d,
    LinkageName = 0x6e,
    LoUser = 0x2000,
    HiUser = 0x3fff,
}

/// TODO FITZGEN
fn parse_attribute_name(input: &[u8]) -> ParseResult<AttributeName> {
    match parse_unsigned_leb(input) {
        IResult::Done(input, val) if AttributeName::Sibling as u64 == val =>
            IResult::Done(input, AttributeName::Sibling),

        IResult::Done(input, val) if AttributeName::Location as u64 == val =>
            IResult::Done(input, AttributeName::Location),

        IResult::Done(input, val) if AttributeName::Name as u64 == val =>
            IResult::Done(input, AttributeName::Name),

        IResult::Done(input, val) if AttributeName::Ordering as u64 == val =>
            IResult::Done(input, AttributeName::Ordering),

        IResult::Done(input, val) if AttributeName::ByteSize as u64 == val =>
            IResult::Done(input, AttributeName::ByteSize),

        IResult::Done(input, val) if AttributeName::BitOffset as u64 == val =>
            IResult::Done(input, AttributeName::BitOffset),

        IResult::Done(input, val) if AttributeName::BitSize as u64 == val =>
            IResult::Done(input, AttributeName::BitSize),

        IResult::Done(input, val) if AttributeName::StmtList as u64 == val =>
            IResult::Done(input, AttributeName::StmtList),

        IResult::Done(input, val) if AttributeName::LowPc as u64 == val =>
            IResult::Done(input, AttributeName::LowPc),

        IResult::Done(input, val) if AttributeName::HighPc as u64 == val =>
            IResult::Done(input, AttributeName::HighPc),

        IResult::Done(input, val) if AttributeName::Language as u64 == val =>
            IResult::Done(input, AttributeName::Language),

        IResult::Done(input, val) if AttributeName::Discr as u64 == val =>
            IResult::Done(input, AttributeName::Discr),

        IResult::Done(input, val) if AttributeName::DiscrValue as u64 == val =>
            IResult::Done(input, AttributeName::DiscrValue),

        IResult::Done(input, val) if AttributeName::Visibility as u64 == val =>
            IResult::Done(input, AttributeName::Visibility),

        IResult::Done(input, val) if AttributeName::Import as u64 == val =>
            IResult::Done(input, AttributeName::Import),

        IResult::Done(input, val) if AttributeName::StringLength as u64 == val =>
            IResult::Done(input, AttributeName::StringLength),

        IResult::Done(input, val) if AttributeName::CommonReference as u64 == val =>
            IResult::Done(input, AttributeName::CommonReference),

        IResult::Done(input, val) if AttributeName::CompDir as u64 == val =>
            IResult::Done(input, AttributeName::CompDir),

        IResult::Done(input, val) if AttributeName::ConstValue as u64 == val =>
            IResult::Done(input, AttributeName::ConstValue),

        IResult::Done(input, val) if AttributeName::ContainingType as u64 == val =>
            IResult::Done(input, AttributeName::ContainingType),

        IResult::Done(input, val) if AttributeName::DefaultValue as u64 == val =>
            IResult::Done(input, AttributeName::DefaultValue),

        IResult::Done(input, val) if AttributeName::Inline as u64 == val =>
            IResult::Done(input, AttributeName::Inline),

        IResult::Done(input, val) if AttributeName::IsOptional as u64 == val =>
            IResult::Done(input, AttributeName::IsOptional),

        IResult::Done(input, val) if AttributeName::LowerBound as u64 == val =>
            IResult::Done(input, AttributeName::LowerBound),

        IResult::Done(input, val) if AttributeName::Producer as u64 == val =>
            IResult::Done(input, AttributeName::Producer),

        IResult::Done(input, val) if AttributeName::Prototyped as u64 == val =>
            IResult::Done(input, AttributeName::Prototyped),

        IResult::Done(input, val) if AttributeName::ReturnAddr as u64 == val =>
            IResult::Done(input, AttributeName::ReturnAddr),

        IResult::Done(input, val) if AttributeName::StartScope as u64 == val =>
            IResult::Done(input, AttributeName::StartScope),

        IResult::Done(input, val) if AttributeName::BitStride as u64 == val =>
            IResult::Done(input, AttributeName::BitStride),

        IResult::Done(input, val) if AttributeName::UpperBound as u64 == val =>
            IResult::Done(input, AttributeName::UpperBound),

        IResult::Done(input, val) if AttributeName::AbstractOrigin as u64 == val =>
            IResult::Done(input, AttributeName::AbstractOrigin),

        IResult::Done(input, val) if AttributeName::Accessibility as u64 == val =>
            IResult::Done(input, AttributeName::Accessibility),

        IResult::Done(input, val) if AttributeName::AddressClass as u64 == val =>
            IResult::Done(input, AttributeName::AddressClass),

        IResult::Done(input, val) if AttributeName::Artificial as u64 == val =>
            IResult::Done(input, AttributeName::Artificial),

        IResult::Done(input, val) if AttributeName::BaseTypes as u64 == val =>
            IResult::Done(input, AttributeName::BaseTypes),

        IResult::Done(input, val) if AttributeName::CallingConvention as u64 == val =>
            IResult::Done(input, AttributeName::CallingConvention),

        IResult::Done(input, val) if AttributeName::Count as u64 == val =>
            IResult::Done(input, AttributeName::Count),

        IResult::Done(input, val) if AttributeName::DataMemberLocation as u64 == val =>
            IResult::Done(input, AttributeName::DataMemberLocation),

        IResult::Done(input, val) if AttributeName::DeclColumn as u64 == val =>
            IResult::Done(input, AttributeName::DeclColumn),

        IResult::Done(input, val) if AttributeName::DeclFile as u64 == val =>
            IResult::Done(input, AttributeName::DeclFile),

        IResult::Done(input, val) if AttributeName::DeclLine as u64 == val =>
            IResult::Done(input, AttributeName::DeclLine),

        IResult::Done(input, val) if AttributeName::Declaration as u64 == val =>
            IResult::Done(input, AttributeName::Declaration),

        IResult::Done(input, val) if AttributeName::DiscrList as u64 == val =>
            IResult::Done(input, AttributeName::DiscrList),

        IResult::Done(input, val) if AttributeName::Encoding as u64 == val =>
            IResult::Done(input, AttributeName::Encoding),

        IResult::Done(input, val) if AttributeName::External as u64 == val =>
            IResult::Done(input, AttributeName::External),

        IResult::Done(input, val) if AttributeName::FrameBase as u64 == val =>
            IResult::Done(input, AttributeName::FrameBase),

        IResult::Done(input, val) if AttributeName::Friend as u64 == val =>
            IResult::Done(input, AttributeName::Friend),

        IResult::Done(input, val) if AttributeName::IdentifierCase as u64 == val =>
            IResult::Done(input, AttributeName::IdentifierCase),

        IResult::Done(input, val) if AttributeName::MacroInfo as u64 == val =>
            IResult::Done(input, AttributeName::MacroInfo),

        IResult::Done(input, val) if AttributeName::NamelistItem as u64 == val =>
            IResult::Done(input, AttributeName::NamelistItem),

        IResult::Done(input, val) if AttributeName::Priority as u64 == val =>
            IResult::Done(input, AttributeName::Priority),

        IResult::Done(input, val) if AttributeName::Segment as u64 == val =>
            IResult::Done(input, AttributeName::Segment),

        IResult::Done(input, val) if AttributeName::Specification as u64 == val =>
            IResult::Done(input, AttributeName::Specification),

        IResult::Done(input, val) if AttributeName::StaticLink as u64 == val =>
            IResult::Done(input, AttributeName::StaticLink),

        IResult::Done(input, val) if AttributeName::Type as u64 == val =>
            IResult::Done(input, AttributeName::Type),

        IResult::Done(input, val) if AttributeName::UseLocation as u64 == val =>
            IResult::Done(input, AttributeName::UseLocation),

        IResult::Done(input, val) if AttributeName::VariableParameter as u64 == val =>
            IResult::Done(input, AttributeName::VariableParameter),

        IResult::Done(input, val) if AttributeName::Virtuality as u64 == val =>
            IResult::Done(input, AttributeName::Virtuality),

        IResult::Done(input, val) if AttributeName::VtableElemLocation as u64 == val =>
            IResult::Done(input, AttributeName::VtableElemLocation),

        IResult::Done(input, val) if AttributeName::Allocated as u64 == val =>
            IResult::Done(input, AttributeName::Allocated),

        IResult::Done(input, val) if AttributeName::Associated as u64 == val =>
            IResult::Done(input, AttributeName::Associated),

        IResult::Done(input, val) if AttributeName::DataLocation as u64 == val =>
            IResult::Done(input, AttributeName::DataLocation),

        IResult::Done(input, val) if AttributeName::ByteStride as u64 == val =>
            IResult::Done(input, AttributeName::ByteStride),

        IResult::Done(input, val) if AttributeName::EntryPc as u64 == val =>
            IResult::Done(input, AttributeName::EntryPc),

        IResult::Done(input, val) if AttributeName::UseUtf8 as u64 == val =>
            IResult::Done(input, AttributeName::UseUtf8),

        IResult::Done(input, val) if AttributeName::Extension as u64 == val =>
            IResult::Done(input, AttributeName::Extension),

        IResult::Done(input, val) if AttributeName::Ranges as u64 == val =>
            IResult::Done(input, AttributeName::Ranges),

        IResult::Done(input, val) if AttributeName::Trampoline as u64 == val =>
            IResult::Done(input, AttributeName::Trampoline),

        IResult::Done(input, val) if AttributeName::CallColumn as u64 == val =>
            IResult::Done(input, AttributeName::CallColumn),

        IResult::Done(input, val) if AttributeName::CallFile as u64 == val =>
            IResult::Done(input, AttributeName::CallFile),

        IResult::Done(input, val) if AttributeName::CallLine as u64 == val =>
            IResult::Done(input, AttributeName::CallLine),

        IResult::Done(input, val) if AttributeName::Description as u64 == val =>
            IResult::Done(input, AttributeName::Description),

        IResult::Done(input, val) if AttributeName::BinaryScale as u64 == val =>
            IResult::Done(input, AttributeName::BinaryScale),

        IResult::Done(input, val) if AttributeName::DecimalScale as u64 == val =>
            IResult::Done(input, AttributeName::DecimalScale),

        IResult::Done(input, val) if AttributeName::Small as u64 == val =>
            IResult::Done(input, AttributeName::Small),

        IResult::Done(input, val) if AttributeName::DecimalSign as u64 == val =>
            IResult::Done(input, AttributeName::DecimalSign),

        IResult::Done(input, val) if AttributeName::DigitCount as u64 == val =>
            IResult::Done(input, AttributeName::DigitCount),

        IResult::Done(input, val) if AttributeName::PictureString as u64 == val =>
            IResult::Done(input, AttributeName::PictureString),

        IResult::Done(input, val) if AttributeName::Mutable as u64 == val =>
            IResult::Done(input, AttributeName::Mutable),

        IResult::Done(input, val) if AttributeName::ThreadsScaled as u64 == val =>
            IResult::Done(input, AttributeName::ThreadsScaled),

        IResult::Done(input, val) if AttributeName::Explicit as u64 == val =>
            IResult::Done(input, AttributeName::Explicit),

        IResult::Done(input, val) if AttributeName::ObjectPointer as u64 == val =>
            IResult::Done(input, AttributeName::ObjectPointer),

        IResult::Done(input, val) if AttributeName::Endianity as u64 == val =>
            IResult::Done(input, AttributeName::Endianity),

        IResult::Done(input, val) if AttributeName::Elemental as u64 == val =>
            IResult::Done(input, AttributeName::Elemental),

        IResult::Done(input, val) if AttributeName::Pure as u64 == val =>
            IResult::Done(input, AttributeName::Pure),

        IResult::Done(input, val) if AttributeName::Recursive as u64 == val =>
            IResult::Done(input, AttributeName::Recursive),

        IResult::Done(input, val) if AttributeName::Signature as u64 == val =>
            IResult::Done(input, AttributeName::Signature),

        IResult::Done(input, val) if AttributeName::MainSubprogram as u64 == val =>
            IResult::Done(input, AttributeName::MainSubprogram),

        IResult::Done(input, val) if AttributeName::DataBitOffset as u64 == val =>
            IResult::Done(input, AttributeName::DataBitOffset),

        IResult::Done(input, val) if AttributeName::ConstExpr as u64 == val =>
            IResult::Done(input, AttributeName::ConstExpr),

        IResult::Done(input, val) if AttributeName::EnumClass as u64 == val =>
            IResult::Done(input, AttributeName::EnumClass),

        IResult::Done(input, val) if AttributeName::LinkageName as u64 == val =>
            IResult::Done(input, AttributeName::LinkageName),

        IResult::Done(input, val) if AttributeName::LoUser as u64 == val =>
            IResult::Done(input, AttributeName::LoUser),

        IResult::Done(input, val) if AttributeName::HiUser as u64 == val =>
            IResult::Done(input, AttributeName::HiUser),

        IResult::Done(input, _) =>
            IResult::Error(
                Err::Position(ErrorKind::Custom(Error::InvalidAttributeName), input)),

        IResult::Incomplete(needed) =>
            IResult::Incomplete(needed),

        IResult::Error(error) =>
            IResult::Error(error),
    }
}

/// TODO FITZGEN
///
/// DWARF standard 4, section 7.5.4, page 160
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum AttributeForm {
    Addr = 0x01,
    Block2 = 0x03,
    Block4 = 0x04,
    Data2 = 0x05,
    Data4 = 0x06,
    Data8 = 0x07,
    String = 0x08,
    Block = 0x09,
    Block1 = 0x0a,
    Data1 = 0x0b,
    Flag = 0x0c,
    Sdata = 0x0d,
    Strp = 0x0e,
    Udata = 0x0f,
    RefAddr = 0x10,
    Ref1 = 0x11,
    Ref2 = 0x12,
    Ref4 = 0x13,
    Ref8 = 0x14,
    RefUdata = 0x15,
    Indirect = 0x16,
    SecOffset = 0x17,
    Exprloc = 0x18,
    FlagPresent = 0x19,
    RefSig8 = 0x20,
}

/// TODO FITZGEN
fn parse_attribute_form(input: &[u8]) -> ParseResult<AttributeForm> {
    match parse_unsigned_leb(input) {
        IResult::Done(input, val) if AttributeForm::Addr as u64 == val =>
            IResult::Done(input, AttributeForm::Addr),

        IResult::Done(input, val) if AttributeForm::Block2 as u64 == val =>
            IResult::Done(input, AttributeForm::Block2),

        IResult::Done(input, val) if AttributeForm::Block4 as u64 == val =>
            IResult::Done(input, AttributeForm::Block4),

        IResult::Done(input, val) if AttributeForm::Data2 as u64 == val =>
            IResult::Done(input, AttributeForm::Data2),

        IResult::Done(input, val) if AttributeForm::Data4 as u64 == val =>
            IResult::Done(input, AttributeForm::Data4),

        IResult::Done(input, val) if AttributeForm::Data8 as u64 == val =>
            IResult::Done(input, AttributeForm::Data8),

        IResult::Done(input, val) if AttributeForm::String as u64 == val =>
            IResult::Done(input, AttributeForm::String),

        IResult::Done(input, val) if AttributeForm::Block as u64 == val =>
            IResult::Done(input, AttributeForm::Block),

        IResult::Done(input, val) if AttributeForm::Block1 as u64 == val =>
            IResult::Done(input, AttributeForm::Block1),

        IResult::Done(input, val) if AttributeForm::Data1 as u64 == val =>
            IResult::Done(input, AttributeForm::Data1),

        IResult::Done(input, val) if AttributeForm::Flag as u64 == val =>
            IResult::Done(input, AttributeForm::Flag),

        IResult::Done(input, val) if AttributeForm::Sdata as u64 == val =>
            IResult::Done(input, AttributeForm::Sdata),

        IResult::Done(input, val) if AttributeForm::Strp as u64 == val =>
            IResult::Done(input, AttributeForm::Strp),

        IResult::Done(input, val) if AttributeForm::Udata as u64 == val =>
            IResult::Done(input, AttributeForm::Udata),

        IResult::Done(input, val) if AttributeForm::RefAddr as u64 == val =>
            IResult::Done(input, AttributeForm::RefAddr),

        IResult::Done(input, val) if AttributeForm::Ref1 as u64 == val =>
            IResult::Done(input, AttributeForm::Ref1),

        IResult::Done(input, val) if AttributeForm::Ref2 as u64 == val =>
            IResult::Done(input, AttributeForm::Ref2),

        IResult::Done(input, val) if AttributeForm::Ref4 as u64 == val =>
            IResult::Done(input, AttributeForm::Ref4),

        IResult::Done(input, val) if AttributeForm::Ref8 as u64 == val =>
            IResult::Done(input, AttributeForm::Ref8),

        IResult::Done(input, val) if AttributeForm::RefUdata as u64 == val =>
            IResult::Done(input, AttributeForm::RefUdata),

        IResult::Done(input, val) if AttributeForm::Indirect as u64 == val =>
            IResult::Done(input, AttributeForm::Indirect),

        IResult::Done(input, val) if AttributeForm::SecOffset as u64 == val =>
            IResult::Done(input, AttributeForm::SecOffset),

        IResult::Done(input, val) if AttributeForm::Exprloc as u64 == val =>
            IResult::Done(input, AttributeForm::Exprloc),

        IResult::Done(input, val) if AttributeForm::FlagPresent as u64 == val =>
            IResult::Done(input, AttributeForm::FlagPresent),

        IResult::Done(input, val) if AttributeForm::RefSig8 as u64 == val =>
            IResult::Done(input, AttributeForm::RefSig8),

        IResult::Done(input, _) =>
            IResult::Error(
                Err::Position(ErrorKind::Custom(Error::InvalidAttributeForm), input)),

        IResult::Incomplete(needed) =>
            IResult::Incomplete(needed),

        IResult::Error(error) =>
            IResult::Error(error),
    }
}

/// TODO FITZGEN
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttributeSpecification {
    name: AttributeName,
    form: AttributeForm,
}

impl AttributeSpecification {
    /// TODO FITZGEN
    pub fn name(&self) -> AttributeName {
        self.name
    }

    /// TODO FITZGEN
    pub fn form(&self) -> AttributeForm {
        self.form
    }
}

/// TODO FITZGEN
fn parse_attribute_specification(input: &[u8]) -> ParseResult<AttributeSpecification> {
    chain!(input,
           name: parse_attribute_name ~
           form: parse_attribute_form,
           || AttributeSpecification {
               name: name,
               form: form,
           })
}

/// TODO FITZGEN
fn parse_null_attribute_specification(input: &[u8]) -> ParseResult<()> {
    let (input1, name) = try_parse!(input, parse_unsigned_leb);
    if name != 0 {
        return IResult::Error(Err::Position(ErrorKind::Custom(Error::ExpectedZero), input));
    }

    let (input2, form) = try_parse!(input1, parse_unsigned_leb);
    if form != 0 {
        return IResult::Error(Err::Position(ErrorKind::Custom(Error::ExpectedZero), input1));
    }

    IResult::Done(input2, ())
}

/// TODO FITZGEN
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Abbreviation {
    code: u64,
    tag: AbbreviationTag,
    has_children: AbbreviationHasChildren,
    attributes: Vec<AttributeSpecification>,
}

impl Abbreviation {
    /// TODO FITZGEN
    pub fn code(&self) -> u64 {
        self.code
    }

    /// TODO FITZGEN
    pub fn tag(&self) -> AbbreviationTag {
        self.tag
    }

    /// TODO FITZGEN
    pub fn has_children(&self) -> bool {
        match self.has_children {
            AbbreviationHasChildren::Yes => true,
            AbbreviationHasChildren::No => false,
        }
    }

    /// TODO FITZGEN
    pub fn attributes(&self) -> &[AttributeSpecification] {
        &self.attributes[..]
    }
}

fn parse_attribute_specifications(mut input: &[u8]) -> ParseResult<Vec<AttributeSpecification>> {
    // There has to be a better way to keep parsing attributes until we see two
    // 0 LEB128s, but take_until!/take_while! aren't quite expressive enough for
    // this case.

    let mut results = Vec::new();

    loop {
        let (input1, attribute) = try_parse!(
            input,
            alt!(parse_null_attribute_specification => { |_| None } |
                 parse_attribute_specification      => { |a| Some(a) }));

        input = input1;

        match attribute {
            None => break,
            Some(attr) => results.push(attr),
        };
    }

    IResult::Done(input, results)
}

/// TODO FITZGEN
fn parse_abbreviation(input: &[u8]) -> ParseResult<Abbreviation> {
    chain!(input,
           code: parse_abbreviation_code ~
           tag: parse_abbreviation_tag ~
           has_children: parse_abbreviation_has_children ~
           attributes: parse_attribute_specifications,
           || Abbreviation {
               code: code,
               tag: tag,
               has_children: has_children,
               attributes: attributes,
           })
}

/// TODO FITZGEN
#[derive(Debug, Clone)]
pub struct Abbreviations {
    abbrevs: hash_map::HashMap<u64, Abbreviation>,
}

impl Abbreviations {
    fn new() -> Abbreviations {
        Abbreviations {
            abbrevs: hash_map::HashMap::new(),
        }
    }

    fn insert(&mut self, abbrev: Abbreviation) -> Result<(), ()> {
        match self.abbrevs.entry(abbrev.code) {
            hash_map::Entry::Occupied(_) =>
                Err(()),
            hash_map::Entry::Vacant(entry) => {
                entry.insert(abbrev);
                Ok(())
            },
        }
    }
}

fn parse_null_abbreviation(input: &[u8]) -> ParseResult<()> {
    let (input1, name) = try_parse!(input, parse_unsigned_leb);
    if name == 0 {
        IResult::Done(input1, ())
    } else {
        IResult::Error(Err::Position(ErrorKind::Custom(Error::ExpectedZero), input))
    }

}

/// TODO FITZGEN
pub fn parse_abbreviations(mut input: &[u8]) -> ParseResult<Abbreviations> {
    // Again with the super funky keep-parsing-X-while-we-can't-parse-a-Y
    // thing... This should definitely be abstracted out.

    let mut results = Abbreviations::new();

    loop {
        let (input1, abbrev) = try_parse!(input,
                                          alt!(parse_null_abbreviation => { |_| None } |
                                               parse_abbreviation      => { |a| Some(a) }));

        match abbrev {
            None => break,
            Some(abbrev) => {
                match results.insert(abbrev) {
                    Ok(_) =>
                        input = input1,
                    Err(_) =>
                        return IResult::Error(
                            Err::Position(
                                ErrorKind::Custom(Error::DuplicateAbbreviationCode),
                                input)),
                }
            }
        }
    }

    IResult::Done(input, results)
}
