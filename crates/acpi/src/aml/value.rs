//! Run-time values of the AML data types.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use super::namespace::NodeId;

/// A value an AML expression can have.
#[derive(Clone, Debug, Default, PartialEq)]
pub enum Value {
    /// Nothing: a local that was never stored to, or a method that returned no value.
    #[default]
    Uninit,
    /// An integer. It is 64 bits wide, or 32 when the defining table's revision is below 2.
    Integer(u64),
    /// An ASCII string.
    String(String),
    /// A byte buffer.
    Buffer(Vec<u8>),
    /// A package of values.
    Package(Vec<Value>),
    /// A reference to an object, from `RefOf`, `Index`, or a name that refers to a device, mutex or the like.
    Reference(Ref),
}

/// A reference to a place that holds a value or an object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ref {
    /// A namespace object.
    Node(NodeId),
    /// A method local; `frame` is the depth of the method invocation that owns it.
    Local {
        /// The invocation's depth in the call stack.
        frame: usize,
        /// The local's number, 0 to 7.
        n: u8,
    },
    /// A method argument.
    Arg {
        /// The invocation's depth in the call stack.
        frame: usize,
        /// The argument's number, 0 to 6.
        n: u8,
    },
    /// One element of a package, or one byte of a buffer or string, held in `base`.
    Index {
        /// Where the package, buffer or string is.
        base: Box<Ref>,
        /// The element's position.
        index: usize,
    },
}

impl Value {
    /// The integer, if this is one.
    pub fn as_integer(&self) -> Option<u64> {
        match self {
            Value::Integer(i) => Some(*i),
            _ => None,
        }
    }

    /// The string, if this is one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    /// The buffer's bytes, if this is a buffer.
    pub fn as_buffer(&self) -> Option<&[u8]> {
        match self {
            Value::Buffer(b) => Some(b),
            _ => None,
        }
    }

    /// The package's elements, if this is a package.
    pub fn as_package(&self) -> Option<&[Value]> {
        match self {
            Value::Package(p) => Some(p),
            _ => None,
        }
    }
}

impl From<u64> for Value {
    fn from(v: u64) -> Self {
        Value::Integer(v)
    }
}

impl From<&str> for Value {
    fn from(v: &str) -> Self {
        Value::String(String::from(v))
    }
}

impl From<Vec<u8>> for Value {
    fn from(v: Vec<u8>) -> Self {
        Value::Buffer(v)
    }
}

/// The value `ObjectType` reports for a [`Value`].
pub(crate) fn type_code(v: &Value) -> u64 {
    match v {
        Value::Uninit => 0,
        Value::Integer(_) => 1,
        Value::String(_) => 2,
        Value::Buffer(_) => 3,
        Value::Package(_) => 4,
        Value::Reference(_) => 0,
    }
}
