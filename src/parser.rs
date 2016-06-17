//! Functions for parsing DWARF debugging information.

use leb128;
use nom::{self, Err, ErrorKind, IResult, le_u8, le_u16, le_u32, le_u64, Needed};
use std::fmt;
use types::{Abbreviation, AbbreviationHasChildren, Abbreviations, AbbreviationTag, AttributeForm,
            AttributeName, AttributeSpecification, CompilationUnitHeader, TypeUnitHeader};

/// A parse error.
#[derive(Debug)]
pub enum Error {
    /// A malformed LEB128 value.
    LebError(leb128::read::Error),

    /// An error from a primitive parser.
    Primitive(u32),

    /// Zero is an illegal value for an abbreviation code.
    AbbreviationCodeZero,

    /// The abbreviation's tag is not a known variant of `AbbreviationTag` (aka
    /// `DW_TAG_*`).
    InvalidAbbreviationTag,

    /// The abbreviation's "does the abbreviated type have children?" byte was
    /// not one of `DW_CHILDREN_yes` or `DW_CHILDREN_no`.
    InvalidAbbreviationHasChildren,

    /// The abbreviation's attribute name is not a valid variant of
    /// `AttributeName` (aka `DW_AT_*`).
    InvalidAttributeName,

    /// The abbreviation's attribute form is not a valid variant of
    /// `AttributeForm` (aka `DW_FORM_*`).
    InvalidAttributeForm,

    /// Expected a zero byte, but did not find one.
    ExpectedZero,

    /// An abbreviation attempted to declare a code that is already in use by an
    /// earlier abbreviation definition.
    DuplicateAbbreviationCode,

    /// Found a compilation unit length within the range of reserved values, but
    /// whose specific value we do not know what to do with.
    UnknownReservedCompilationUnitLength,

    /// The reported DWARF version is a version we do not know how to parse.
    UnknownDwarfVersion,
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
            Error::Primitive(_) =>
                "Error parsing primitive value",
            Error::AbbreviationCodeZero =>
                "Abbreviation declared its code to be the reserved code 0",
            Error::InvalidAbbreviationTag =>
                "The abbreviation tag is invalid",
            Error::InvalidAbbreviationHasChildren =>
                "The \"does-the-abbreviated-type-have-children?\" byte is not DW_CHILDREN_yes or DW_CHILDREN_no",
            Error::InvalidAttributeName =>
                "The abbreviation's attribute name is invalid",
            Error::InvalidAttributeForm =>
                "The abbreviation's attribute form is invalid",
            Error::ExpectedZero =>
                "Expected zero",
            Error::DuplicateAbbreviationCode =>
                "Found an abbreviation with a code that has already been used",
            Error::UnknownReservedCompilationUnitLength =>
                "Unknown reserved compilation unit length value found",
            Error::UnknownDwarfVersion =>
                "The DWARF version is a version that we do not know how to parse",
        }
    }

    fn cause(&self) -> Option<&::std::error::Error> {
        match *self {
            Error::LebError(ref e) => Some(e),
            Error::Primitive(_) => None,
            Error::AbbreviationCodeZero => None,
            Error::InvalidAbbreviationTag => None,
            Error::InvalidAbbreviationHasChildren => None,
            Error::InvalidAttributeName => None,
            Error::InvalidAttributeForm => None,
            Error::ExpectedZero => None,
            Error::DuplicateAbbreviationCode => None,
            Error::UnknownReservedCompilationUnitLength => None,
            Error::UnknownDwarfVersion => None,
        }
    }
}

impl From<u32> for Error {
    fn from(e: u32) -> Self {
        Error::Primitive(e)
    }
}

/// The result of an attempted parse.
pub type ParseResult<Input, T> = IResult<Input, T, Error>;

macro_rules! try_parse_result (
    ($result:expr) => (
        match $result {
            IResult::Done(rest, out) => (rest, out),
            IResult::Error(e) => return IResult::Error(e),
            IResult::Incomplete(i) => return IResult::Incomplete(i)
        }
    );
);

/// Parse an unsigned LEB128 encoded integer.
fn parse_unsigned_leb(mut input: &[u8]) -> ParseResult<&[u8], u64> {
    match leb128::read::unsigned(&mut input) {
        Ok(val) =>
            IResult::Done(input, val),
        Err(leb128::read::Error::UnexpectedEndOfData) =>
            IResult::Incomplete(Needed::Unknown),
        Err(e) =>
            IResult::Error(Err::Position(ErrorKind::Custom(Error::LebError(e)), input)),
    }
}

/// Parse an abbreviation's code.
fn parse_abbreviation_code(mut input: &[u8]) -> ParseResult<&[u8], u64> {
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

/// Parse an abbreviation's tag.
fn parse_abbreviation_tag(mut input: &[u8]) -> ParseResult<&[u8], AbbreviationTag> {
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

/// Parse an abbreviation's "does the type have children?" byte.
fn parse_abbreviation_has_children(input: &[u8]) -> ParseResult<&[u8], AbbreviationHasChildren> {
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

/// Parse an attribute's name.
fn parse_attribute_name(input: &[u8]) -> ParseResult<&[u8], AttributeName> {
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

/// Parse an attribute's form.
fn parse_attribute_form(input: &[u8]) -> ParseResult<&[u8], AttributeForm> {
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

/// Parse a non-null attribute specification.
fn parse_attribute_specification(input: &[u8]) -> ParseResult<&[u8], AttributeSpecification> {
    chain!(input,
           name: parse_attribute_name ~
           form: parse_attribute_form,
           || AttributeSpecification::new(name, form))
}

/// Parse the null attribute specification.
fn parse_null_attribute_specification(input: &[u8]) -> ParseResult<&[u8], ()> {
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

/// Parse a series of attribute specifications, terminated by a null attribute
/// specification.
fn parse_attribute_specifications(mut input: &[u8]) -> ParseResult<&[u8], Vec<AttributeSpecification>> {
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

/// Parse a non-null abbreviation.
fn parse_abbreviation(input: &[u8]) -> ParseResult<&[u8], Abbreviation> {
    chain!(input,
           code: parse_abbreviation_code ~
           tag: parse_abbreviation_tag ~
           has_children: parse_abbreviation_has_children ~
           attributes: parse_attribute_specifications,
           || Abbreviation::new(code, tag, has_children, attributes))
}

/// Parse a null abbreviation.
fn parse_null_abbreviation(input: &[u8]) -> ParseResult<&[u8], ()> {
    let (input1, name) = try_parse!(input, parse_unsigned_leb);
    if name == 0 {
        IResult::Done(input1, ())
    } else {
        IResult::Error(Err::Position(ErrorKind::Custom(Error::ExpectedZero), input))
    }

}

/// Parse a series of abbreviations, terminated by a null abbreviation.
pub fn parse_abbreviations(mut input: &[u8]) -> ParseResult<&[u8], Abbreviations> {
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

/// Any type U that implements TranslateInput<T> can be lowered to T and then
/// later raised back to U. This is useful for lowering types that are a
/// composition of a `&[u8]` and some extra data down to `&[u8]` to use nom's
/// builtin parsers and then raise the result and input back up to the original
/// composition input type.
trait TranslateInput<T> {
    fn lower(self) -> T;
    fn raise(original: Self, lowered_result: T) -> Self;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Unknown,
    Dwarf64,
    Dwarf32,
}

/// The input to parsing various compilation unit header information.
#[derive(Debug, Clone, Copy)]
pub struct CuInput<'a>(&'a [u8], Format);

impl<'a> nom::InputLength for CuInput<'a> {
    fn input_len(&self) -> usize {
        self.0.len()
    }
}

impl<'a> CuInput<'a> {
    /// Construct a new `CuInput`.
    pub fn new(input: &'a [u8]) -> CuInput<'a> {
        CuInput(input, Format::Unknown)
    }

    fn into_dwarf_32(self) -> CuInput<'a> {
        debug_assert!(self.1 == Format::Unknown);
        CuInput(self.0, Format::Dwarf32)
    }

    fn into_dwarf_64(self) -> CuInput<'a> {
        debug_assert!(self.1 == Format::Unknown);
        CuInput(self.0, Format::Dwarf64)
    }
}

impl<'a> TranslateInput<&'a [u8]> for CuInput<'a> {
    fn lower(self) -> &'a[u8] {
        self.0
    }

    fn raise(original: Self, lowered: &'a [u8]) -> Self {
        CuInput(lowered, original.1)
    }
}

/// Use a parser for some lower input type on a higher input type that is a
/// composition of the lower input type and whatever extra data. Specifically,
/// we use this so that we can use parsers on inputs of `&[u8]` with inputs of
/// `CuInput` of `DieInput`, etc.
fn translate_domain<Output,
                    LowerError,
                    HigherError,
                    HigherInput,
                    LowerInput,
                    LowerParser>(input: HigherInput,
                                 parser: LowerParser) -> IResult<HigherInput, Output, HigherError>
    where HigherInput: TranslateInput<LowerInput> + Clone,
          LowerParser: Fn(LowerInput) -> IResult<LowerInput, Output, LowerError>,
          HigherError: From<LowerError>
{
    let lowered_input = input.clone().lower();
    let lowered_result = parser(lowered_input);
    raise_result(input, lowered_result)
}

fn raise_result<LowerInput,
                HigherInput,
                T,
                LowerError,
                HigherError>(original: HigherInput,
                             lowered: IResult<LowerInput, T, LowerError>)
                             -> IResult<HigherInput, T, HigherError>
    where HigherInput: TranslateInput<LowerInput> + Clone,
          HigherError: From<LowerError>
{
    use nom::{Err, ErrorKind};

    fn translate_err<LowerInput,
                     HigherInput,
                     LowerError,
                     HigherError>(original: HigherInput,
                                  err: Err<LowerInput, LowerError>) -> Err<HigherInput, HigherError>
        where HigherInput: TranslateInput<LowerInput> + Clone,
              HigherError: From<LowerError>
    {

        fn translate_code<LowerError, HigherError>(code: ErrorKind<LowerError>)
                                                   -> ErrorKind<HigherError>
            where HigherError: From<LowerError>
        {
            // MATCH ALL THE THINGS!!!!
            match code {
                ErrorKind::Custom(e) => ErrorKind::Custom(e.into()),
                ErrorKind::Tag => ErrorKind::Tag,
                ErrorKind::MapRes => ErrorKind::MapRes,
                ErrorKind::MapOpt => ErrorKind::MapOpt,
                ErrorKind::Alt => ErrorKind::Alt,
                ErrorKind::IsNot => ErrorKind::IsNot,
                ErrorKind::IsA => ErrorKind::IsA,
                ErrorKind::SeparatedList => ErrorKind::SeparatedList,
                ErrorKind::SeparatedNonEmptyList => ErrorKind::SeparatedNonEmptyList,
                ErrorKind::Many1 => ErrorKind::Many1,
                ErrorKind::Count => ErrorKind::Count,
                ErrorKind::TakeUntilAndConsume => ErrorKind::TakeUntilAndConsume,
                ErrorKind::TakeUntil => ErrorKind::TakeUntil,
                ErrorKind::TakeUntilEitherAndConsume => ErrorKind::TakeUntilEitherAndConsume,
                ErrorKind::TakeUntilEither => ErrorKind::TakeUntilEither,
                ErrorKind::LengthValue => ErrorKind::LengthValue,
                ErrorKind::TagClosure => ErrorKind::TagClosure,
                ErrorKind::Alpha => ErrorKind::Alpha,
                ErrorKind::Digit => ErrorKind::Digit,
                ErrorKind::HexDigit => ErrorKind::HexDigit,
                ErrorKind::AlphaNumeric => ErrorKind::AlphaNumeric,
                ErrorKind::Space => ErrorKind::Space,
                ErrorKind::MultiSpace => ErrorKind::MultiSpace,
                ErrorKind::LengthValueFn => ErrorKind::LengthValueFn,
                ErrorKind::Eof => ErrorKind::Eof,
                ErrorKind::ExprOpt => ErrorKind::ExprOpt,
                ErrorKind::ExprRes => ErrorKind::ExprRes,
                ErrorKind::CondReduce => ErrorKind::CondReduce,
                ErrorKind::Switch => ErrorKind::Switch,
                ErrorKind::TagBits => ErrorKind::TagBits,
                ErrorKind::OneOf => ErrorKind::OneOf,
                ErrorKind::NoneOf => ErrorKind::NoneOf,
                ErrorKind::Char => ErrorKind::Char,
                ErrorKind::CrLf => ErrorKind::CrLf,
                ErrorKind::RegexpMatch => ErrorKind::RegexpMatch,
                ErrorKind::RegexpMatches => ErrorKind::RegexpMatches,
                ErrorKind::RegexpFind => ErrorKind::RegexpFind,
                ErrorKind::RegexpCapture => ErrorKind::RegexpCapture,
                ErrorKind::RegexpCaptures => ErrorKind::RegexpCaptures,
                ErrorKind::TakeWhile1 => ErrorKind::TakeWhile1,
                ErrorKind::Complete => ErrorKind::Complete,
                ErrorKind::Fix => ErrorKind::Fix,
                ErrorKind::Escaped => ErrorKind::Escaped,
                ErrorKind::EscapedTransform => ErrorKind::EscapedTransform,
                ErrorKind::TagStr => ErrorKind::TagStr,
                ErrorKind::IsNotStr => ErrorKind::IsNotStr,
                ErrorKind::IsAStr => ErrorKind::IsAStr,
                ErrorKind::TakeWhile1Str => ErrorKind::TakeWhile1Str,
                ErrorKind::NonEmpty => ErrorKind::NonEmpty,
                ErrorKind::ManyMN => ErrorKind::ManyMN,
                ErrorKind::TakeUntilAndConsumeStr => ErrorKind::TakeUntilAndConsumeStr,
                ErrorKind::TakeUntilStr => ErrorKind::TakeUntilStr,
                ErrorKind::Many0 => ErrorKind::Many0,
                ErrorKind::OctDigit => ErrorKind::OctDigit,
            }
        }

        match err {
            Err::Code(code) =>
                Err::Code(translate_code(code)),
            Err::Node(code, boxed_err) =>
                Err::Node(translate_code(code),
                          Box::new(translate_err(original, *boxed_err))),
            Err::Position(code, position) =>
                Err::Position(translate_code(code),
                              TranslateInput::raise(original, position)),
            Err::NodePosition(code, position, boxed_err) =>
                Err::NodePosition(translate_code(code),
                                  TranslateInput::raise(original.clone(), position),
                                  Box::new(translate_err(original, *boxed_err))),
        }
    }

    match lowered {
        IResult::Incomplete(needed) =>
            IResult::Incomplete(needed),
        IResult::Done(rest, val) =>
            IResult::Done(TranslateInput::raise(original, rest), val),
        IResult::Error(err) =>
            IResult::Error(translate_err(original, err)),
    }
}

const MAX_DWARF_32_UNIT_LENGTH: u64 = 0xfffffff0;

const DWARF_64_INITIAL_UNIT_LENGTH: u64 = 0xffffffff;

named!(parse_u32_as_u64<&[u8], u64>,
       chain!(val: le_u32, || val as u64));

/// Parse the compilation unit header's length.
fn parse_unit_length(input: CuInput) -> ParseResult<CuInput, u64> {
    match translate_domain(input, parse_u32_as_u64) {
        IResult::Done(rest, val) if val < MAX_DWARF_32_UNIT_LENGTH =>
            IResult::Done(rest.into_dwarf_32(), val),

        IResult::Done(rest, val) if val == DWARF_64_INITIAL_UNIT_LENGTH =>
            match translate_domain(rest, le_u64) {
                IResult::Done(rest, val) =>
                    IResult::Done(rest.into_dwarf_64(), val),
                otherwise =>
                    otherwise
            },

        IResult::Done(_, _) =>
            IResult::Error(Err::Position(
                ErrorKind::Custom(Error::UnknownReservedCompilationUnitLength), input)),

        otherwise =>
            otherwise
    }
}

#[test]
fn test_parse_unit_length_32_ok() {
    let buf = [0x12, 0x34, 0x56, 0x78];

    match parse_unit_length(CuInput(&buf, Format::Unknown)) {
        IResult::Done(rest, length) => {
            assert_eq!(rest.0.len(), 0);
            assert_eq!(rest.1, Format::Dwarf32);
            assert_eq!(0x78563412, length);
        },
        _ =>
            assert!(false),
    }
}

#[test]
fn test_parse_unit_length_64_ok() {
    let buf = [0xff, 0xff, 0xff, 0xff, // DWARF_64_INITIAL_UNIT_LENGTH
               0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xff]; // Actual length

    match parse_unit_length(CuInput(&buf, Format::Unknown)) {
        IResult::Done(rest, length) => {
            assert_eq!(rest.0.len(), 0);
            assert_eq!(rest.1, Format::Dwarf64);
            assert_eq!(0xffdebc9a78563412, length);
        },
        _ =>
            assert!(false),
    }
}

#[test]
fn test_parse_unit_length_unknown_reserved_value() {
    let buf = [0xfe, 0xff, 0xff, 0xff];

    match parse_unit_length(CuInput(&buf, Format::Unknown)) {
        IResult::Error(Err::Position(
            ErrorKind::Custom(Error::UnknownReservedCompilationUnitLength),
            _)) =>
            assert!(true),
        _ =>
            assert!(false),
    };
}

#[test]
fn test_parse_unit_length_incomplete() {
    let buf = [0xff, 0xff, 0xff]; // Need at least 4 bytes.

    match parse_unit_length(CuInput(&buf, Format::Unknown)) {
        IResult::Incomplete(_) => assert!(true),
        _ => assert!(false),
    };
}

#[test]
fn test_parse_unit_length_64_incomplete() {
    let buf = [0xff, 0xff, 0xff, 0xff, // DWARF_64_INITIAL_UNIT_LENGTH
               0x12, 0x34, 0x56, 0x78, ]; // Actual length is not long enough

    match parse_unit_length(CuInput(&buf, Format::Unknown)) {
        IResult::Incomplete(_) => assert!(true),
        _ => assert!(false),
    };
}

/// Parse the DWARF version from the compilation unit header.
fn parse_version(input: CuInput) -> ParseResult<CuInput, u16> {
    match translate_domain(input, le_u16) {
        // DWARF 1 was very different, and is obsolete, so isn't supported by
        // this reader.
        IResult::Done(rest, val) if 2 <= val && val <= 4 =>
            IResult::Done(rest, val),

        IResult::Done(_, _) =>
            IResult::Error(Err::Position(
                ErrorKind::Custom(Error::UnknownDwarfVersion), input)),

        otherwise =>
            otherwise
    }
}

#[test]
fn test_compilation_unit_version_ok() {
    let buf = [0x04, 0x00, 0xff, 0xff]; // Version 4 and two extra bytes

    match parse_version(CuInput(&buf, Format::Unknown)) {
        IResult::Done(rest, val) => {
            assert_eq!(val, 4);
            assert_eq!(rest.0, &[0xff, 0xff]);
        },
        _ =>
            assert!(false),
    };
}

#[test]
fn test_compilation_unit_version_unknown_version() {
    let buf = [0xab, 0xcd];

    match parse_version(CuInput(&buf, Format::Unknown)) {
        IResult::Error(Err::Position(ErrorKind::Custom(Error::UnknownDwarfVersion), _)) =>
            assert!(true),
        _ =>
            assert!(false),
    };

    let buf = [0x1, 0x0];

    match parse_version(CuInput(&buf, Format::Unknown)) {
        IResult::Error(Err::Position(ErrorKind::Custom(Error::UnknownDwarfVersion), _)) =>
            assert!(true),
        _ =>
            assert!(false),
    };
}

#[test]
fn test_compilation_unit_version_incomplete() {
    let buf = [0x04];

    match parse_version(CuInput(&buf, Format::Unknown)) {
        IResult::Incomplete(_) =>
            assert!(true),
        _ =>
            assert!(false),
    };
}

/// Parse the debug_abbrev_offset in the compilation unit header.
fn parse_debug_abbrev_offset(input: CuInput) -> ParseResult<CuInput, u64> {
    match input.1 {
        Format::Unknown =>
            panic!("Need to know if this is 32- or 64-bit DWARF to parse the debug_abbrev_offset"),
        Format::Dwarf32 =>
            translate_domain(input, parse_u32_as_u64),
        Format::Dwarf64 =>
            translate_domain(input, le_u64),
    }
}

#[test]
fn test_parse_debug_abbrev_offset_32() {
    let buf = [0x01, 0x02, 0x03, 0x04];

    match parse_debug_abbrev_offset(CuInput(&buf, Format::Dwarf32)) {
        IResult::Done(_, val) => assert_eq!(val, 0x04030201),
        _ => assert!(false),
    };
}

#[test]
fn test_parse_debug_abbrev_offset_32_incomplete() {
    let buf = [0x01, 0x02];

    match parse_debug_abbrev_offset(CuInput(&buf, Format::Dwarf32)) {
        IResult::Incomplete(_) => assert!(true),
        _ => assert!(false),
    };
}

#[test]
fn test_parse_debug_abbrev_offset_64() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    match parse_debug_abbrev_offset(CuInput(&buf, Format::Dwarf64)) {
        IResult::Done(_, val) => assert_eq!(val, 0x0807060504030201),
        _ => assert!(false),
    };
}

#[test]
fn test_parse_debug_abbrev_offset_64_incomplete() {
    let buf = [0x01, 0x02];

    match parse_debug_abbrev_offset(CuInput(&buf, Format::Dwarf64)) {
        IResult::Incomplete(_) => assert!(true),
        _ => assert!(false),
    };
}

#[test]
#[should_panic]
fn test_parse_debug_abbrev_offset_unknown() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    parse_debug_abbrev_offset(CuInput(&buf, Format::Unknown));
}

/// Parse the size of addresses (in bytes) on the target architecture.
fn parse_address_size(input: CuInput) -> ParseResult<CuInput, u8> {
    translate_domain(input, le_u8)
}

#[test]
fn test_parse_address_size_ok() {
    let buf = [0x04];

    match parse_address_size(CuInput(&buf, Format::Unknown)) {
        IResult::Done(_, val) => assert_eq!(val, 4),
        _ => assert!(false),
    };
}

/// Parse a compilation unit header.
pub fn parse_compilation_unit_header(input: CuInput)
                                     -> ParseResult<CuInput, CompilationUnitHeader>
{
    chain!(input,
           unit_length: parse_unit_length ~
           version: parse_version ~
           offset: parse_debug_abbrev_offset ~
           address_size: parse_address_size,
           || CompilationUnitHeader::new(unit_length,
                                         version,
                                         offset,
                                         address_size))
}

#[test]
fn test_parse_compilation_unit_header_32_ok() {
    let buf = [
        0x01, 0x02, 0x03, 0x04, // 32-bit unit length
        0x04, 0x00,             // version 4
        0x05, 0x06, 0x07, 0x08, // debug_abbrev_offset
        0x04                    // address size
    ];

    match parse_compilation_unit_header(CuInput::new(&buf)) {
        IResult::Done(_, header) =>
            assert_eq!(header, CompilationUnitHeader::new(0x04030201, 4, 0x08070605, 4)),
        _ =>
            assert!(false),
    }
}

#[test]
fn test_parse_compilation_unit_header_64_ok() {
    let buf = [
        0xff, 0xff, 0xff, 0xff,                         // enable 64-bit
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // unit length
        0x04, 0x00,                                     // version 4
        0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, // debug_abbrev_offset
        0x08                                            // address size
    ];

    match parse_compilation_unit_header(CuInput::new(&buf)) {
        IResult::Done(_, header) =>
            assert_eq!(header, CompilationUnitHeader::new(0x0807060504030201,
                                                          4,
                                                          0x0102030405060708,
                                                          8)),
        _ =>
            assert!(false),
    }
}

/// Parse a type unit header's unique type signature. Callers should handle
/// unique-ness checking.
fn parse_type_signature(input: CuInput) -> ParseResult<CuInput, u64> {
    translate_domain(input, le_u64)
}

#[test]
fn test_parse_type_signature_ok() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    match parse_type_signature(CuInput::new(&buf)) {
        IResult::Done(_, val) => assert_eq!(val, 0x0807060504030201),
        _ => assert!(false),
    }
}

#[test]
fn test_parse_type_signature_incomplete() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];

    match parse_type_signature(CuInput::new(&buf)) {
        IResult::Incomplete(_) => assert!(true),
        _ => assert!(false),
    }
}

/// Parse a type unit header's type offset.
fn parse_type_offset(input: CuInput) -> ParseResult<CuInput, u64> {
    match input.1 {
        Format::Unknown =>
            panic!("Need to know if this is 32- or 64-bit DWARF to parse the type_offset"),
        Format::Dwarf32 =>
            translate_domain(input, parse_u32_as_u64),
        Format::Dwarf64 =>
            translate_domain(input, le_u64),
    }
}

#[test]
fn test_parse_type_offset_32_ok() {
    let buf = [0x12, 0x34, 0x56, 0x78, 0x00];

    match parse_type_offset(CuInput(&buf, Format::Dwarf32)) {
        IResult::Done(rest, offset) => {
            assert_eq!(rest.0.len(), 1);
            assert_eq!(rest.1, Format::Dwarf32);
            assert_eq!(0x78563412, offset);
        },
        _ =>
            assert!(false),
    }
}

#[test]
fn test_parse_type_offset_64_ok() {
    let buf = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xff, 0x00];

    match parse_type_offset(CuInput(&buf, Format::Dwarf64)) {
        IResult::Done(rest, offset) => {
            assert_eq!(rest.0.len(), 1);
            assert_eq!(rest.1, Format::Dwarf64);
            assert_eq!(0xffdebc9a78563412, offset);
        },
        _ =>
            assert!(false),
    }
}

#[test]
#[should_panic]
fn test_parse_type_offset_unknown() {
    let buf = [0xfe, 0xff, 0xff, 0xff];

    parse_type_offset(CuInput(&buf, Format::Unknown));
}

#[test]
fn test_parse_type_offset_incomplete() {
    let buf = [0xff, 0xff, 0xff]; // Need at least 4 bytes.

    match parse_type_offset(CuInput(&buf, Format::Dwarf32)) {
        IResult::Incomplete(_) => assert!(true),
        _ => assert!(false),
    };
}

/// Parse a type unit header.
pub fn parse_type_unit_header(input: CuInput) -> ParseResult<CuInput, TypeUnitHeader> {
    chain!(input,
           header: parse_compilation_unit_header ~
           signature: parse_type_signature ~
           offset: parse_type_offset,
           || TypeUnitHeader::new(header, signature, offset))
}

#[test]
fn test_parse_type_unit_header_32_ok() {
    let buf = [
        0xff, 0xff, 0xff, 0xff,                         // enable 64-bit unit length mode
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // The actual unit length
        0x04, 0x00,                                     // version 4
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // debug_abbrev_offset
        0x08,                                           // address size
        0xef, 0xbe, 0xad, 0xde, 0xef, 0xbe, 0xad, 0xde, // type signature
        0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78  // type offset
    ];

    let result = parse_type_unit_header(CuInput::new(&buf));
    println!("result = {:#?}", result);

    match result {
        IResult::Done(_, header) =>
            assert_eq!(header, TypeUnitHeader::new(CompilationUnitHeader::new(0x0807060504030201,
                                                                              4,
                                                                              0x0807060504030201,
                                                                              8),
                                                   0xdeadbeefdeadbeef,
                                                   0x7856341278563412)),
        _ =>
            assert!(false),
    }
}
