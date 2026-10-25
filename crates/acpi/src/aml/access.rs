//! Reading and writing objects and references, and the implicit conversions between data types.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::cursor::Cursor;
use super::error::AmlError;
use super::host::Host;
use super::interp::Interpreter;
use super::name::NameString;
use super::namespace::{Data, NodeId, Object, ROOT};
use super::ops;
use super::value::{Ref, Value};

/// How a value is written to a place.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// `Store`: converts to the type of a named object, and writes through a reference held in an argument.
    Store,
    /// `CopyObject`: replaces the object whatever its type.
    Copy,
}

/// Where a result goes.
pub(crate) enum Target {
    /// Nowhere (`Zero`).
    Null,
    /// The `Debug` object.
    Debug,
    /// A local, argument, named object or element.
    Place(Ref),
}

/// An operand that may name a place or merely produce a value.
pub(crate) enum Operand {
    Place(Ref),
    Value(Value),
}

impl<H: Host> Interpreter<H> {
    // ----- the running frame -----

    pub(crate) fn int64(&self) -> bool {
        self.frames.last().is_none_or(|f| f.int64)
    }

    pub(crate) fn scope(&self) -> NodeId {
        self.frames.last().map_or(ROOT, |f| f.scope)
    }

    pub(crate) fn code(&self) -> Arc<[u8]> {
        self.frames.last().map_or_else(|| Arc::from([]), |f| f.code.clone())
    }

    /// Truncates to the integer width in force.
    pub(crate) fn trunc(&self, v: u64) -> u64 {
        if self.int64() { v } else { v & 0xffff_ffff }
    }

    /// The all-ones integer.
    pub(crate) fn ones(&self) -> u64 {
        self.trunc(u64::MAX)
    }

    fn top(&self) -> usize {
        self.frames.len().saturating_sub(1)
    }

    // ----- operands and targets -----

    /// Reads an operand that may be a place: a local, an argument, a name, or an expression giving a
    /// reference (`Index`, `RefOf`, `DerefOf`). A method call is made, and gives a value.
    pub(crate) fn operand(&mut self, c: &mut Cursor<'_>) -> Result<Operand, AmlError> {
        let b = c.peek().ok_or(AmlError::UnexpectedEnd)?;
        match b {
            0x60..=0x67 => {
                c.pos += 1;
                Ok(Operand::Place(Ref::Local { frame: self.top(), n: b - 0x60 }))
            }
            0x68..=0x6e => {
                c.pos += 1;
                Ok(Operand::Place(Ref::Arg { frame: self.top(), n: b - 0x68 }))
            }
            b if NameString::starts_with(b) => {
                let name = NameString::parse(c)?;
                let id = match self.ns.lookup(self.scope(), &name) {
                    Some(id) => self.ns.resolve_alias(id),
                    None => {
                        let text = super::exec::name_text(&name);
                        self.warn(alloc::format!("{text} not found"));
                        return Err(AmlError::NotFound);
                    }
                };
                match self.ns.object(id) {
                    Some(Object::Method(m)) => {
                        let n = usize::from(m.args);
                        let mut args = Vec::with_capacity(n);
                        for _ in 0..n {
                            args.push(self.arg(c)?);
                        }
                        Ok(Operand::Value(self.call(id, args)?))
                    }
                    _ => Ok(Operand::Place(Ref::Node(id))),
                }
            }
            _ => {
                c.pos += 1;
                if b == 0x83 {
                    // DerefOf names the place its reference points to, so it can be stored through.
                    return match self.arg(c)? {
                        Value::Reference(r) => Ok(Operand::Place(r)),
                        v => Ok(Operand::Value(v)),
                    };
                }
                c.pos -= 1;
                match self.arg(c)? {
                    Value::Reference(r) => Ok(Operand::Place(r)),
                    v => Ok(Operand::Value(v)),
                }
            }
        }
    }

    pub(crate) fn target(&mut self, c: &mut Cursor<'_>) -> Result<Target, AmlError> {
        match c.peek() {
            Some(0x00) => {
                c.pos += 1;
                Ok(Target::Null)
            }
            Some(0x5b) if c.data.get(c.pos + 1) == Some(&0x31) => {
                c.pos += 2;
                Ok(Target::Debug)
            }
            _ => match self.operand(c)? {
                Operand::Place(r) => Ok(Target::Place(r)),
                Operand::Value(_) => Err(AmlError::TypeMismatch),
            },
        }
    }

    pub(crate) fn store_target(&mut self, t: &Target, v: Value) -> Result<(), AmlError> {
        match t {
            Target::Null => Ok(()),
            Target::Debug => {
                let msg = alloc::format!("{v:?}");
                self.host.debug(&msg);
                Ok(())
            }
            Target::Place(r) => self.write_ref(r, v, Mode::Store),
        }
    }

    // ----- conversions -----

    /// Converts to an integer as an operand of arithmetic is: a string is read as hex digits, a buffer as
    /// little-endian bytes, and a reference is followed.
    pub(crate) fn integer_from(&mut self, v: Value) -> Result<u64, AmlError> {
        let int64 = self.int64();
        let n = match v {
            Value::Integer(i) => i,
            Value::String(s) => ops::parse_hex(&s),
            Value::Buffer(b) => ops::buffer_to_integer(&b, int64),
            Value::Reference(r) => match self.read_ref(&r)? {
                Value::Reference(_) => return Err(AmlError::TypeMismatch),
                inner => return self.integer_from(inner),
            },
            Value::Uninit => return Err(AmlError::NoValue),
            Value::Package(_) => return Err(AmlError::TypeMismatch),
        };
        Ok(self.trunc(n))
    }

    pub(crate) fn buffer_from(&mut self, v: Value) -> Result<Vec<u8>, AmlError> {
        let int64 = self.int64();
        match v {
            Value::Integer(i) => Ok(ops::integer_to_buffer(i, int64)),
            Value::String(s) => Ok(s.into_bytes()),
            Value::Buffer(b) => Ok(b),
            Value::Reference(r) => match self.read_ref(&r)? {
                Value::Reference(_) => Err(AmlError::TypeMismatch),
                inner => self.buffer_from(inner),
            },
            Value::Uninit => Err(AmlError::NoValue),
            Value::Package(_) => Err(AmlError::TypeMismatch),
        }
    }

    /// Converts to a string as `Concatenate` does: an integer as full-width hex digits, a buffer as its
    /// bytes in hex separated by commas.
    pub(crate) fn string_from(&mut self, v: Value) -> Result<String, AmlError> {
        let int64 = self.int64();
        match v {
            Value::String(s) => Ok(s),
            Value::Integer(i) => Ok(ops::hex_string(i, if int64 { 16 } else { 8 })),
            Value::Buffer(b) => {
                let parts: Vec<String> = b.iter().map(|&x| ops::hex_string(u64::from(x), 2)).collect();
                Ok(parts.join(","))
            }
            Value::Reference(r) => match self.read_ref(&r)? {
                Value::Reference(_) => Err(AmlError::TypeMismatch),
                inner => self.string_from(inner),
            },
            Value::Uninit => Err(AmlError::NoValue),
            Value::Package(_) => Err(AmlError::TypeMismatch),
        }
    }

    /// Follows a reference to the data it points at; any other value is returned unchanged. A reference
    /// to an object that is not data (a device) stays a reference.
    pub(crate) fn deref_data(&mut self, v: Value) -> Result<Value, AmlError> {
        match v {
            Value::Reference(r) => self.read_ref(&r),
            v => Ok(v),
        }
    }

    // ----- places -----

    /// Reads a place, following references until data (or an object that is not data) is reached.
    pub(crate) fn read_data(&mut self, r: &Ref) -> Result<Value, AmlError> {
        let mut v = self.read_ref(r)?;
        for _ in 0..8 {
            match v {
                Value::Reference(inner) if !matches!(inner, Ref::Node(id) if !self.is_data_node(id)) => {
                    v = self.read_ref(&inner)?;
                }
                other => return Ok(other),
            }
        }
        Err(AmlError::TypeMismatch)
    }

    fn is_data_node(&self, id: NodeId) -> bool {
        matches!(
            self.ns.object(self.ns.resolve_alias(id)),
            Some(Object::Data(_) | Object::Field(_) | Object::BufferField(_))
        )
    }

    /// Evaluates a named object's initializer if that has not happened yet.
    pub(crate) fn ensure_ready(&mut self, id: NodeId) -> Result<(), AmlError> {
        let lazy = match self.ns.object_mut(id) {
            Some(Object::Data(d)) => match d {
                Data::Ready(_) => return Ok(()),
                Data::Lazy(l) => {
                    let l = l.clone();
                    // A name that refers to itself sees nothing rather than recursing.
                    *d = Data::Ready(Value::Uninit);
                    l
                }
            },
            _ => return Ok(()),
        };
        let scope = self.ns.parent(id).unwrap_or(ROOT);
        let r = self.push_frame(scope, lazy.code.clone(), lazy.int64, false, Vec::new()).and_then(|()| {
            let mut c = Cursor::new(&lazy.code, lazy.start, lazy.end);
            let r = self.arg(&mut c);
            self.pop_frame();
            r
        });
        let (restore, result) = match r {
            Ok(v) => (Data::Ready(v), Ok(())),
            Err(e) => (Data::Lazy(lazy), Err(e)),
        };
        if let Some(Object::Data(d)) = self.ns.object_mut(id) {
            *d = restore;
        }
        result
    }

    /// The value of a named object. A method is run with no arguments; an object that holds no data (a
    /// device, a mutex) gives a reference to itself.
    pub(crate) fn read_node(&mut self, id: NodeId) -> Result<Value, AmlError> {
        let id = self.ns.resolve_alias(id);
        match self.ns.object(id).ok_or(AmlError::NotFound)? {
            Object::Data(_) => {
                self.ensure_ready(id)?;
                match self.ns.object(id) {
                    Some(Object::Data(Data::Ready(v))) => Ok(v.clone()),
                    _ => Err(AmlError::TypeMismatch),
                }
            }
            Object::Field(f) => {
                let f = f.clone();
                self.field_read(&f)
            }
            Object::BufferField(b) => {
                let b = b.clone();
                self.buffer_field_read(&b)
            }
            Object::Method(_) | Object::Native(_) => self.call(id, Vec::new()),
            _ => Ok(Value::Reference(Ref::Node(id))),
        }
    }

    /// The storage behind a place that holds plain data.
    pub(crate) fn place_value(&mut self, r: &Ref) -> Result<&mut Value, AmlError> {
        match r {
            Ref::Node(id) => {
                let id = self.ns.resolve_alias(*id);
                self.ensure_ready(id)?;
                match self.ns.object_mut(id) {
                    Some(Object::Data(Data::Ready(v))) => Ok(v),
                    _ => Err(AmlError::TypeMismatch),
                }
            }
            Ref::Local { frame, n } => {
                self.frames.get_mut(*frame).and_then(|f| f.locals.get_mut(usize::from(*n))).ok_or(AmlError::OutOfBounds)
            }
            Ref::Arg { frame, n } => {
                self.frames.get_mut(*frame).and_then(|f| f.args.get_mut(usize::from(*n))).ok_or(AmlError::OutOfBounds)
            }
            Ref::Index { base, index } => {
                let base = self.resolve_place(base.as_ref().clone())?;
                match self.place_value(&base)? {
                    Value::Package(p) => p.get_mut(*index).ok_or(AmlError::OutOfBounds),
                    _ => Err(AmlError::TypeMismatch),
                }
            }
        }
    }

    /// Follows references held in a place to the place that holds the data.
    pub(crate) fn resolve_place(&mut self, mut r: Ref) -> Result<Ref, AmlError> {
        for _ in 0..8 {
            match self.place_value(&r) {
                Ok(Value::Reference(inner)) => r = inner.clone(),
                _ => return Ok(r),
            }
        }
        Err(AmlError::TypeMismatch)
    }

    pub(crate) fn read_ref(&mut self, r: &Ref) -> Result<Value, AmlError> {
        match r {
            Ref::Node(id) => self.read_node(*id),
            Ref::Local { .. } | Ref::Arg { .. } => Ok(self.place_value(r)?.clone()),
            Ref::Index { base, index } => {
                let base = self.resolve_place(base.as_ref().clone())?;
                let whole = match self.place_value(&base) {
                    Ok(Value::Package(p)) => return p.get(*index).cloned().ok_or(AmlError::OutOfBounds),
                    Ok(Value::Buffer(b)) => {
                        return b.get(*index).map(|&x| Value::Integer(u64::from(x))).ok_or(AmlError::OutOfBounds);
                    }
                    Ok(Value::String(s)) => {
                        return s
                            .as_bytes()
                            .get(*index)
                            .map(|&x| Value::Integer(u64::from(x)))
                            .ok_or(AmlError::OutOfBounds);
                    }
                    Ok(_) => return Err(AmlError::TypeMismatch),
                    Err(_) => self.read_ref(&base)?,
                };
                match whole {
                    Value::Buffer(b) => {
                        b.get(*index).map(|&x| Value::Integer(u64::from(x))).ok_or(AmlError::OutOfBounds)
                    }
                    _ => Err(AmlError::TypeMismatch),
                }
            }
        }
    }

    pub(crate) fn write_ref(&mut self, r: &Ref, v: Value, mode: Mode) -> Result<(), AmlError> {
        match r {
            Ref::Local { .. } => {
                *self.place_value(r)? = v;
                Ok(())
            }
            Ref::Arg { .. } => {
                if mode == Mode::Store
                    && let Value::Reference(inner) = self.place_value(r)?
                {
                    let inner = inner.clone();
                    self.descend()?;
                    let res = self.write_ref(&inner, v, mode);
                    self.depth = self.depth.saturating_sub(1);
                    return res;
                }
                *self.place_value(r)? = v;
                Ok(())
            }
            Ref::Node(id) => self.write_node(*id, v, mode),
            Ref::Index { base, index } => self.write_index(base, *index, v),
        }
    }

    pub(crate) fn write_node(&mut self, id: NodeId, v: Value, mode: Mode) -> Result<(), AmlError> {
        let id = self.ns.resolve_alias(id);
        match self.ns.object(id).ok_or(AmlError::NotFound)? {
            Object::Data(_) => {
                self.ensure_ready(id)?;
                let new = if mode == Mode::Store { self.coerce_to_existing(id, v)? } else { v };
                *self.place_value(&Ref::Node(id))? = new;
                Ok(())
            }
            Object::Field(f) => {
                let f = f.clone();
                self.field_write(&f, v)
            }
            Object::BufferField(b) => {
                let b = b.clone();
                self.buffer_field_write(&b, v)
            }
            _ => Err(AmlError::TypeMismatch),
        }
    }

    /// What `Store` makes of `v` for a named object that already holds data: an integer, string or buffer
    /// keeps its type, with `v` converted to it.
    fn coerce_to_existing(&mut self, id: NodeId, v: Value) -> Result<Value, AmlError> {
        let convertible = matches!(v, Value::Integer(_) | Value::String(_) | Value::Buffer(_) | Value::Reference(_));
        let kind = match self.place_value(&Ref::Node(id))? {
            Value::Integer(_) => 1,
            Value::String(_) => 2,
            Value::Buffer(b) => 3 + b.len(),
            _ => 0,
        };
        if !convertible || kind == 0 {
            return Ok(v);
        }
        Ok(match kind {
            1 => Value::Integer(self.integer_from(v)?),
            2 => Value::String(self.string_from(v)?),
            n => {
                let mut b = self.buffer_from(v)?;
                let old = n - 3;
                if old != 0 {
                    b.resize(old, 0);
                }
                Value::Buffer(b)
            }
        })
    }

    fn write_index(&mut self, base: &Ref, index: usize, v: Value) -> Result<(), AmlError> {
        let base = self.resolve_place(base.clone())?;
        if matches!(self.place_value(&base)?, Value::Package(_)) {
            if let Value::Package(p) = self.place_value(&base)? {
                *p.get_mut(index).ok_or(AmlError::OutOfBounds)? = v;
            }
            return Ok(());
        }
        let byte = self.integer_from(v)? as u8;
        match self.place_value(&base)? {
            Value::Buffer(b) => *b.get_mut(index).ok_or(AmlError::OutOfBounds)? = byte,
            Value::String(s) => {
                if byte >= 0x80 {
                    return Err(AmlError::InvalidOperand);
                }
                // An ASCII byte replaced by another keeps the string valid UTF-8.
                let mut bytes = core::mem::take(s).into_bytes();
                let hit = bytes.get_mut(index).map(|x| *x = byte).is_some();
                *s = String::from_utf8(bytes).unwrap_or_default();
                if !hit {
                    return Err(AmlError::OutOfBounds);
                }
            }
            _ => return Err(AmlError::TypeMismatch),
        }
        Ok(())
    }
}
