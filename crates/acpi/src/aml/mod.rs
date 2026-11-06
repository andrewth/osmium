//! An AML interpreter: the ACPI namespace and the control methods in it.
//!
//! ```ignore
//! let mut aml = Interpreter::new(MyHost::new(), Config::default());
//! aml.load_tables(&acpi)?;
//! aml.initialize();
//! let crs = aml.evaluate("\\_SB_.PCI0._CRS", &[])?;
//! ```
//!
//! # How it runs
//!
//! The interpreter reads AML and acts on it in one pass; there is no syntax tree. Loading a definition
//! block runs its top-level terms, which declare devices, methods, regions and fields in the
//! [`Namespace`]. A method body is kept as a span of the table and run each time it is called, and the
//! initializer of a `Name` holding a buffer or package is evaluated the first time the name is read, so
//! a table can refer to objects declared after it.
//!
//! Operation regions reach the machine through the [`Host`] trait. Everything else (arithmetic, strings,
//! buffers, packages, references, fields, control flow, mutexes and events, `Notify`, `Sleep`) is
//! implemented here.
//!
//! # Limits
//!
//! AML comes from firmware, which is not trusted any more than a disk image is. Nothing in it can make
//! the interpreter panic or recurse past [`Config::max_depth`]. One call runs at most [`Config::max_steps`]
//! steps, where a step is a term, 64 bytes of data copied, converted or compared, 64 bits of a field
//! moved, or one access to an operation region; and it allocates at most [`Config::max_alloc_bytes`] in
//! all, with no single buffer or string over a megabyte and no package over 65536 elements. Every
//! allocation whose size the AML chooses (buffers, strings, packages and copies of them) is fallible, so a
//! heap smaller than the budget gives [`AmlError::OutOfMemory`] rather than the allocation-failure handler;
//! the small fixed-size ones (a namespace entry's maps, a reference) are not. Between calls the namespace holds at most [`Config::max_retained_bytes`]
//! of data. A table with an error stops loading at that point, and a method with an error fails that one
//! call.
//!
//! Not implemented: `Load`, `LoadTable`, `Unload` and `DataTableRegion` (return
//! [`AmlError::Unsupported`]); the Global Lock handshake (`Acquire(\_GL_)` always succeeds, so a field
//! declared with the lock rule is accessed without it); mutex ownership and timeouts (the interpreter is
//! single-threaded, so an `Acquire` never waits); and the buffer access types used for SMBus and IPMI
//! fields. Packages and buffers passed as method arguments are copied, so a method cannot modify its
//! caller's package through `Index`.

mod access;
mod cursor;
mod error;
mod exec;
mod field;
mod host;
mod interp;
mod name;
mod namespace;
mod ops;
mod value;

pub use error::AmlError;
pub use host::{Host, HostError, PciAddress, space};
pub use interp::{Config, DeviceInfo, InitReport, Interpreter, LoadReport, TableInfo};
pub use name::NameSeg;
pub use namespace::{Namespace, NodeId, ObjectKind, ROOT};
pub use value::{Ref, Value};
