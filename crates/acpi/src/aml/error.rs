//! Errors from loading and running AML.

use core::fmt;

use super::host::HostError;

/// Why a table failed to load or a control method failed to run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AmlError {
    /// The definition block's header is malformed, its checksum is wrong or it is not a DSDT/SSDT.
    InvalidTable,
    /// The code ended in the middle of a term.
    UnexpectedEnd,
    /// An opcode that is reserved, misplaced or not valid here.
    InvalidOpcode(u8),
    /// An extended (`0x5B`-prefixed) opcode that is reserved or not valid here.
    InvalidExtOpcode(u8),
    /// A `PkgLength` that is malformed or runs past its enclosing term.
    InvalidPkgLength,
    /// A name that is malformed (a bad character, too many segments, an unterminated prefix).
    InvalidName,
    /// A path string passed by the caller that is not a valid namespace path.
    InvalidPath,
    /// A name that resolves to nothing.
    NotFound,
    /// An object is declared twice in one scope.
    AlreadyExists,
    /// An operand has a type the operation cannot use.
    TypeMismatch,
    /// A numeric operand or a string that cannot be converted to what the operation needs.
    InvalidOperand,
    /// An index or bit range lies outside its buffer, package, string or operation region.
    OutOfBounds,
    /// `Divide` or `Mod` by zero.
    DivideByZero,
    /// A method was called with the wrong number of arguments.
    WrongArgCount,
    /// A value was needed from a method that returned none, or from a local that was never set.
    NoValue,
    /// `Break`, `Continue` or `Return` outside the construct they belong to.
    BadControlFlow,
    /// Terms nest, or methods call each other, more deeply than [`Config::max_depth`](super::Config::max_depth).
    TooDeep,
    /// The step or sleep budget ([`Config::max_steps`](super::Config::max_steps),
    /// [`Config::max_sleep_us`](super::Config::max_sleep_us)) ran out, probably in a loop that never ends.
    Timeout,
    /// An object, field or namespace would be larger than the interpreter allows.
    TooLarge,
    /// A construct that this interpreter does not implement (named in the message).
    Unsupported(&'static str),
    /// The host refused an access to an operation region.
    Host(HostError),
    /// The AML executed `Fatal`.
    Fatal {
        /// The fatal error type.
        kind: u8,
        /// The fatal error code.
        code: u32,
        /// The fatal error argument.
        arg: u64,
    },
}

impl From<HostError> for AmlError {
    fn from(e: HostError) -> Self {
        AmlError::Host(e)
    }
}

impl fmt::Display for AmlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AmlError::InvalidTable => f.write_str("invalid definition block"),
            AmlError::UnexpectedEnd => f.write_str("AML ended in the middle of a term"),
            AmlError::InvalidOpcode(op) => write!(f, "invalid opcode {op:#04x}"),
            AmlError::InvalidExtOpcode(op) => write!(f, "invalid extended opcode 0x5b {op:#04x}"),
            AmlError::InvalidPkgLength => f.write_str("invalid PkgLength"),
            AmlError::InvalidName => f.write_str("invalid name"),
            AmlError::InvalidPath => f.write_str("invalid namespace path"),
            AmlError::NotFound => f.write_str("name not found"),
            AmlError::AlreadyExists => f.write_str("object already exists"),
            AmlError::TypeMismatch => f.write_str("operand has the wrong type"),
            AmlError::InvalidOperand => f.write_str("operand cannot be converted"),
            AmlError::OutOfBounds => f.write_str("access out of bounds"),
            AmlError::DivideByZero => f.write_str("divide by zero"),
            AmlError::WrongArgCount => f.write_str("wrong number of arguments"),
            AmlError::NoValue => f.write_str("no value"),
            AmlError::BadControlFlow => f.write_str("Break, Continue or Return outside its construct"),
            AmlError::TooDeep => f.write_str("nesting too deep"),
            AmlError::Timeout => f.write_str("step or sleep budget exhausted"),
            AmlError::TooLarge => f.write_str("object too large"),
            AmlError::Unsupported(what) => write!(f, "unsupported: {what}"),
            AmlError::Host(e) => write!(f, "host access failed: {e:?}"),
            AmlError::Fatal { kind, code, arg } => {
                write!(f, "AML fatal error type {kind:#x} code {code:#x} arg {arg:#x}")
            }
        }
    }
}

impl core::error::Error for AmlError {}
