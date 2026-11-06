// SPDX-License-Identifier: GPL-2.0-only
//! Run-time values of the AML data types.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use super::error::AmlError;
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
    /// A method local; `frame` identifies the method invocation that owns it. Once that invocation returns,
    /// the reference is stale and using it fails with [`AmlError::StaleReference`].
    Local {
        /// The invocation's serial number, unique for the life of the interpreter.
        frame: usize,
        /// The local's number, 0 to 7.
        n: u8,
    },
    /// A method argument, with the same lifetime as [`Ref::Local`].
    Arg {
        /// The invocation's serial number, unique for the life of the interpreter.
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
    /// How many levels of package and reference this value nests. Scalars are 0. The interpreter keeps this
    /// below [`Config::max_depth`](super::Config::max_depth), so the recursive `Clone`, `Drop`, `Debug` and
    /// `PartialEq` cannot overflow the stack.
    pub(crate) fn depth(&self) -> usize {
        match self {
            Value::Package(p) => 1 + p.iter().map(Value::depth).max().unwrap_or(0),
            Value::Reference(r) => 1 + r.depth(),
            _ => 0,
        }
    }

    /// Roughly how many bytes of heap cloning this value allocates.
    pub(crate) fn copy_size(&self) -> usize {
        match self {
            Value::String(s) => s.len(),
            Value::Buffer(b) => b.len(),
            Value::Package(p) => {
                p.iter().map(|v| core::mem::size_of::<Value>() + v.copy_size()).fold(0, usize::saturating_add)
            }
            Value::Reference(r) => r.depth().saturating_mul(core::mem::size_of::<Ref>()),
            _ => 0,
        }
    }

    /// A copy made with fallible allocations: [`AmlError::OutOfMemory`] if the heap cannot hold it. The
    /// recursion is as deep as the value nests, which the interpreter keeps below `max_depth`.
    pub(crate) fn try_clone(&self) -> Result<Value, AmlError> {
        Ok(match self {
            Value::String(s) => {
                let mut t = String::new();
                t.try_reserve_exact(s.len()).map_err(|_| AmlError::OutOfMemory)?;
                t.push_str(s);
                Value::String(t)
            }
            Value::Buffer(b) => Value::Buffer(try_copy(b)?),
            Value::Package(p) => {
                let mut v = Vec::new();
                v.try_reserve_exact(p.len()).map_err(|_| AmlError::OutOfMemory)?;
                for x in p {
                    v.push(x.try_clone()?);
                }
                Value::Package(v)
            }
            other => other.clone(),
        })
    }

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

/// `n` zero bytes, or [`AmlError::OutOfMemory`].
pub(crate) fn try_zeroed(n: usize) -> Result<Vec<u8>, AmlError> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| AmlError::OutOfMemory)?;
    v.resize(n, 0);
    Ok(v)
}

/// A copy of `b`, or [`AmlError::OutOfMemory`].
pub(crate) fn try_copy(b: &[u8]) -> Result<Vec<u8>, AmlError> {
    let mut v = Vec::new();
    v.try_reserve_exact(b.len()).map_err(|_| AmlError::OutOfMemory)?;
    v.extend_from_slice(b);
    Ok(v)
}

impl Ref {
    /// How many [`Ref::Index`] levels this reference nests.
    pub(crate) fn depth(&self) -> usize {
        let mut n = 0;
        let mut r = self;
        while let Ref::Index { base, .. } = r {
            n += 1;
            r = base;
        }
        n
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
