//! Executing AML terms.
//!
//! There is no syntax tree. A term is evaluated as it is read, which is why every operand is parsed and
//! evaluated in the order it appears, and why a false `If` or the end of a `While` skips its body by its
//! `PkgLength` rather than by walking it.

use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;

use super::access::{Mode, Operand, Target};
use super::cursor::Cursor;
use super::error::AmlError;
use super::host::Host;
use super::interp::Interpreter;
use super::name::{NameSeg, NameString};
use super::namespace::{BufferField, Data, FieldKind, FieldUnit, Lazy, Method, NodeId, Object, Region, Update};
use super::ops;
use super::value::{Ref, Value, type_code};

/// Largest buffer or string AML may create.
pub(crate) const MAX_OBJECT: u64 = 1 << 20;
/// Most elements a package may have.
const MAX_PACKAGE: u64 = 1 << 16;
/// Largest field, in bits.
pub(crate) const MAX_FIELD_BITS: u64 = 1 << 20;

/// What a term did to the flow of control.
pub(crate) enum Flow {
    /// Fell through, with the value of the term (meaningful for expressions).
    Next(Value),
    Break,
    Continue,
    Return(Value),
}

fn flag(b: bool, ones: u64) -> Value {
    Value::Integer(if b { ones } else { 0 })
}

impl<H: Host> Interpreter<H> {
    /// Runs terms until the cursor ends or one breaks the flow.
    pub(crate) fn exec_list(&mut self, c: &mut Cursor<'_>) -> Result<Flow, AmlError> {
        while !c.at_end() {
            match self.term(c)? {
                Flow::Next(_) => {}
                other => return Ok(other),
            }
        }
        Ok(Flow::Next(Value::Uninit))
    }

    /// Evaluates a term that must produce a value.
    pub(crate) fn arg(&mut self, c: &mut Cursor<'_>) -> Result<Value, AmlError> {
        match self.term(c)? {
            Flow::Next(v) => Ok(v),
            _ => Err(AmlError::BadControlFlow),
        }
    }

    pub(crate) fn int_arg(&mut self, c: &mut Cursor<'_>) -> Result<u64, AmlError> {
        let v = self.arg(c)?;
        self.integer_from(v)
    }

    fn call_args(&mut self, c: &mut Cursor<'_>, n: usize) -> Result<Vec<Value>, AmlError> {
        let mut args = Vec::with_capacity(n);
        for _ in 0..n {
            args.push(self.arg(c)?);
        }
        Ok(args)
    }

    /// Reads one term and runs it.
    pub(crate) fn term(&mut self, c: &mut Cursor<'_>) -> Result<Flow, AmlError> {
        self.steps += 1;
        if self.steps > self.config.max_steps {
            return Err(AmlError::Timeout);
        }
        self.descend()?;
        let r = self.term_inner(c);
        self.depth = self.depth.saturating_sub(1);
        r
    }

    fn term_inner(&mut self, c: &mut Cursor<'_>) -> Result<Flow, AmlError> {
        let op = c.byte()?;
        let v = match op {
            0x00 => Value::Integer(0),
            0x01 => Value::Integer(1),
            0xff => Value::Integer(self.ones()),
            0x0a => Value::Integer(u64::from(c.byte()?)),
            0x0b => Value::Integer(u64::from(c.word()?)),
            0x0c => Value::Integer(u64::from(c.dword()?)),
            0x0d => Value::String(string_constant(c)?),
            0x0e => Value::Integer(self.trunc(c.qword()?)),
            0x06 | 0x08 | 0x10 | 0x14 | 0x15 => {
                self.declare(op, c)?;
                Value::Uninit
            }
            0x11 => self.buffer_term(c)?,
            0x12 | 0x13 => self.package_term(op, c)?,
            0x5b => return self.ext_term(c),
            0x60..=0x67 => {
                self.frames.last().and_then(|f| f.locals.get(usize::from(op - 0x60))).cloned().unwrap_or_default()
            }
            0x68..=0x6e => {
                self.frames.last().and_then(|f| f.args.get(usize::from(op - 0x68))).cloned().unwrap_or_default()
            }
            0x70 => {
                let v = self.arg(c)?;
                let t = self.target(c)?;
                self.store_target(&t, v.clone())?;
                v
            }
            0x71 => match self.operand(c)? {
                Operand::Place(r) => Value::Reference(r),
                Operand::Value(v) => Value::Reference(self.anonymous(v)?),
            },
            0x72 | 0x74 | 0x77 | 0x79 | 0x7a | 0x7b..=0x7f | 0x85 => self.arithmetic(op, c)?,
            0x73 => self.concat(c)?,
            0x75 | 0x76 => self.increment(op == 0x75, c)?,
            0x78 => self.divide(c)?,
            0x80..=0x82 => self.unary(op, c)?,
            0x83 => self.deref_of(c)?,
            0x84 => self.concat_res(c)?,
            0x86 => {
                let path = match self.operand(c)? {
                    Operand::Place(Ref::Node(id)) => self.ns.path(id),
                    _ => return Err(AmlError::TypeMismatch),
                };
                let value = self.int_arg(c)?;
                self.host.notify(&path, value as u8);
                Value::Uninit
            }
            0x87 => self.size_of(c)?,
            0x88 => self.index(c)?,
            0x89 => self.match_term(c)?,
            0x8a | 0x8b | 0x8c | 0x8d | 0x8f => {
                self.create_buffer_field(op, c)?;
                Value::Uninit
            }
            0x8e => self.object_type(c)?,
            0x90 | 0x91 => {
                let a = self.int_arg(c)?;
                let b = self.int_arg(c)?;
                let r = if op == 0x90 { a != 0 && b != 0 } else { a != 0 || b != 0 };
                flag(r, self.ones())
            }
            0x92 => {
                let a = self.int_arg(c)?;
                flag(a == 0, self.ones())
            }
            0x93..=0x95 => {
                let a = self.arg(c)?;
                let b = self.arg(c)?;
                let ord = self.compare(a, b)?;
                let want = match op {
                    0x93 => Ordering::Equal,
                    0x94 => Ordering::Greater,
                    _ => Ordering::Less,
                };
                flag(ord == want, self.ones())
            }
            0x96 | 0x97 | 0x98 | 0x99 | 0x9c => self.convert(op, c)?,
            0x9d => {
                let v = self.arg(c)?;
                let t = self.target(c)?;
                match t {
                    Target::Place(r) => self.write_ref(&r, v.clone(), Mode::Copy)?,
                    other => self.store_target(&other, v.clone())?,
                }
                v
            }
            0x9e => self.mid(c)?,
            0x9f => return Ok(Flow::Continue),
            0xa0 => return self.if_else(c),
            0xa2 => return self.while_loop(c),
            0xa3 | 0xcc => Value::Uninit,
            0xa4 => {
                let v = self.arg(c)?;
                return Ok(Flow::Return(v));
            }
            0xa5 => return Ok(Flow::Break),
            b if NameString::starts_with(b) => {
                c.pos -= 1;
                self.name_term(c)?
            }
            _ => return Err(AmlError::InvalidOpcode(op)),
        };
        Ok(Flow::Next(v))
    }

    // ----- names -----

    fn name_term(&mut self, c: &mut Cursor<'_>) -> Result<Value, AmlError> {
        let name = NameString::parse(c)?;
        let id = self.lookup_or_warn(&name)?;
        match self.ns.object(id) {
            Some(Object::Method(m)) => {
                let n = usize::from(m.args);
                let args = self.call_args(c, n)?;
                self.call(id, args)
            }
            Some(Object::Native(_)) => {
                let args = self.call_args(c, 1)?;
                self.call(id, args)
            }
            _ => self.read_node(id),
        }
    }

    fn lookup_or_warn(&mut self, name: &NameString<'_>) -> Result<NodeId, AmlError> {
        match self.ns.lookup(self.scope(), name) {
            Some(id) => Ok(self.ns.resolve_alias(id)),
            None => {
                let scope = self.ns.path(self.scope());
                self.warn(alloc::format!("{} not found from {scope}", name_text(name)));
                Err(AmlError::NotFound)
            }
        }
    }

    /// Creates a named object in the current scope. A name that is already taken is skipped with a warning
    /// and gives `None`.
    pub(crate) fn create(&mut self, name: &NameString<'_>, object: Object) -> Result<Option<NodeId>, AmlError> {
        let (parent, seg) = self.ns.locate_new(self.scope(), name)?;
        match self.ns.insert(parent, seg, object) {
            Ok(id) => {
                if let Some(f) = self.frames.last_mut().filter(|f| f.track) {
                    f.created.push(id);
                }
                Ok(Some(id))
            }
            Err(AmlError::AlreadyExists) => {
                let path = self.ns.path(parent);
                self.warn(alloc::format!("{seg} already exists in {path}"));
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// A node with no name holding `v`, so that a reference to it can be made.
    pub(crate) fn anonymous(&mut self, v: Value) -> Result<Ref, AmlError> {
        let id = self.ns.insert_anonymous(Object::Data(Data::Ready(v)))?;
        if let Some(f) = self.frames.last_mut() {
            f.created.push(id);
        }
        Ok(Ref::Node(id))
    }

    // ----- declarations -----

    fn declare(&mut self, op: u8, c: &mut Cursor<'_>) -> Result<(), AmlError> {
        match op {
            0x06 => {
                let src = NameString::parse(c)?;
                let alias = NameString::parse(c)?;
                let target = self.lookup_or_warn(&src)?;
                self.create(&alias, Object::Alias(target))?;
            }
            0x08 => {
                let name = NameString::parse(c)?;
                let data = match c.peek() {
                    Some(0x11..=0x13) => {
                        let start = c.pos;
                        c.pos += 1;
                        let end = c.pkg_length()?;
                        c.pos = end;
                        Data::Lazy(Lazy { code: self.code(), start, end, int64: self.int64() })
                    }
                    _ => Data::Ready(self.arg(c)?),
                };
                self.create(&name, Object::Data(data))?;
            }
            0x10 => self.scope_term(0x10, c)?,
            0x14 => {
                let end = c.pkg_length()?;
                let mut b = c.until(end);
                c.pos = end;
                let name = NameString::parse(&mut b)?;
                let flags = b.byte()?;
                let m = Method { code: self.code(), start: b.pos, end, args: flags & 7, int64: self.int64() };
                self.create(&name, Object::Method(m))?;
            }
            _ => {
                // External(name, type, args): a declaration for the compiler only.
                NameString::parse(c)?;
                c.take(2)?;
            }
        }
        Ok(())
    }

    /// `Scope`, `Device`, `Processor`, `PowerResource` and `ThermalZone`: a name, a few fixed fields, then
    /// terms that run with the object as the current scope.
    fn scope_term(&mut self, kind: u8, c: &mut Cursor<'_>) -> Result<(), AmlError> {
        let end = c.pkg_length()?;
        let mut b = c.until(end);
        c.pos = end;
        let name = NameString::parse(&mut b)?;
        let object = match kind {
            0x10 => None,
            0x82 => Some(Object::Device),
            0x83 => {
                b.take(6)?;
                Some(Object::Processor)
            }
            0x84 => {
                b.take(3)?;
                Some(Object::PowerResource)
            }
            _ => Some(Object::ThermalZone),
        };
        let node = match object {
            None => self.lookup_or_warn(&name)?,
            Some(o) => match self.create(&name, o)? {
                Some(n) => n,
                None => return Ok(()),
            },
        };
        self.in_scope(node, &mut b)
    }

    fn in_scope(&mut self, node: NodeId, body: &mut Cursor<'_>) -> Result<(), AmlError> {
        let saved = self.frames.last().map(|f| f.scope).ok_or(AmlError::BadControlFlow)?;
        if let Some(f) = self.frames.last_mut() {
            f.scope = node;
        }
        let r = self.exec_list(body);
        if let Some(f) = self.frames.last_mut() {
            f.scope = saved;
        }
        match r? {
            Flow::Next(_) => Ok(()),
            _ => Err(AmlError::BadControlFlow),
        }
    }

    fn lookup_object(&mut self, name: &NameString<'_>) -> Result<NodeId, AmlError> {
        self.lookup_or_warn(name)
    }

    fn region_term(&mut self, c: &mut Cursor<'_>) -> Result<(), AmlError> {
        let name = NameString::parse(c)?;
        let space = c.byte()?;
        let offset = self.int_arg(c)?;
        let length = self.int_arg(c)?;
        self.create(&name, Object::Region(Region { space, offset, length }))?;
        Ok(())
    }

    /// `Field`, `IndexField` and `BankField`.
    fn field_term(&mut self, op: u8, c: &mut Cursor<'_>) -> Result<(), AmlError> {
        let end = c.pkg_length()?;
        let mut b = c.until(end);
        c.pos = end;
        let first = NameString::parse(&mut b)?;
        let first = self.lookup_object(&first)?;
        let kind = match op {
            0x81 => FieldKind::Region(first),
            0x86 => {
                let data = NameString::parse(&mut b)?;
                let data = self.lookup_object(&data)?;
                FieldKind::Index { index: first, data }
            }
            _ => {
                let bank = NameString::parse(&mut b)?;
                let bank = self.lookup_object(&bank)?;
                let value = self.int_arg(&mut b)?;
                FieldKind::Bank { region: first, bank, value }
            }
        };
        let flags = b.byte()?;
        let update = match (flags >> 5) & 3 {
            1 => Update::Ones,
            2 => Update::Zeros,
            _ => Update::Preserve,
        };
        let mut access = flags & 0xf;
        let int64 = self.int64();
        let mut bit = 0u64;
        while !b.at_end() {
            match b.byte()? {
                0x00 => bit = bit.checked_add(b.raw_pkg_length()?).ok_or(AmlError::TooLarge)?,
                0x01 => {
                    access = b.byte()? & 0xf;
                    b.byte()?;
                }
                0x02 => {
                    // ConnectField: a name, or an inline buffer of resource descriptors.
                    if b.peek() == Some(0x11) {
                        b.pos += 1;
                        let e = b.pkg_length()?;
                        b.pos = e;
                    } else {
                        NameString::parse(&mut b)?;
                    }
                }
                0x03 => {
                    access = b.byte()? & 0xf;
                    b.take(2)?;
                }
                lead if NameSeg::is_lead(lead) => {
                    b.pos -= 1;
                    let seg = NameSeg::new(*b.take(4)?.first_chunk().ok_or(AmlError::InvalidName)?)
                        .ok_or(AmlError::InvalidName)?;
                    let len = b.raw_pkg_length()?;
                    if len > MAX_FIELD_BITS {
                        return Err(AmlError::TooLarge);
                    }
                    let unit = FieldUnit { kind, bit_offset: bit, bit_len: len, access, update, int64 };
                    let (parent, _) = (self.scope(), ());
                    match self.ns.insert(parent, seg, Object::Field(unit)) {
                        Ok(id) => {
                            if let Some(f) = self.frames.last_mut().filter(|f| f.track) {
                                f.created.push(id);
                            }
                        }
                        Err(AmlError::AlreadyExists) => self.warn(alloc::format!("field {seg} already exists")),
                        Err(e) => return Err(e),
                    }
                    bit = bit.checked_add(len).ok_or(AmlError::TooLarge)?;
                }
                other => return Err(AmlError::InvalidOpcode(other)),
            }
        }
        Ok(())
    }

    fn create_buffer_field(&mut self, op: u8, c: &mut Cursor<'_>) -> Result<(), AmlError> {
        let source = self.buffer_source(c)?;
        let index = self.int_arg(c)?;
        let (bit_offset, bit_len) = match op {
            0x8d => (index, 1),
            0x8c => (index.checked_mul(8).ok_or(AmlError::OutOfBounds)?, 8),
            0x8b => (index.checked_mul(8).ok_or(AmlError::OutOfBounds)?, 16),
            0x8a => (index.checked_mul(8).ok_or(AmlError::OutOfBounds)?, 32),
            0x8f => (index.checked_mul(8).ok_or(AmlError::OutOfBounds)?, 64),
            _ => {
                let len = self.int_arg(c)?;
                if len == 0 || len > MAX_FIELD_BITS {
                    return Err(AmlError::InvalidOperand);
                }
                (index, len)
            }
        };
        let name = NameString::parse(c)?;
        let int64 = self.int64();
        self.create(&name, Object::BufferField(BufferField { source, bit_offset, bit_len, int64 }))?;
        Ok(())
    }

    /// The place a buffer field's buffer lives in.
    fn buffer_source(&mut self, c: &mut Cursor<'_>) -> Result<Ref, AmlError> {
        match self.operand(c)? {
            Operand::Place(r) => self.resolve_place(r),
            Operand::Value(v) => self.anonymous(v),
        }
    }

    // ----- extended opcodes -----

    fn ext_term(&mut self, c: &mut Cursor<'_>) -> Result<Flow, AmlError> {
        let op = c.byte()?;
        let v = match op {
            0x01 => {
                let name = NameString::parse(c)?;
                c.byte()?;
                self.create(&name, Object::Mutex)?;
                Value::Uninit
            }
            0x02 => {
                let name = NameString::parse(c)?;
                self.create(&name, Object::Event)?;
                Value::Uninit
            }
            0x12 => self.cond_ref_of(c)?,
            0x13 => {
                self.create_buffer_field(0x13, c)?;
                Value::Uninit
            }
            0x1f => return Err(AmlError::Unsupported("LoadTable")),
            0x20 => return Err(AmlError::Unsupported("Load")),
            0x2a => return Err(AmlError::Unsupported("Unload")),
            0x21 => {
                let us = self.int_arg(c)?;
                self.spend(us)?;
                self.host.stall(us.min(u64::from(u32::MAX)) as u32);
                Value::Uninit
            }
            0x22 => {
                let ms = self.int_arg(c)?;
                self.spend(ms.saturating_mul(1000))?;
                self.host.sleep(ms.min(u64::from(u32::MAX)) as u32);
                Value::Uninit
            }
            0x23 => {
                // No other thread can hold a mutex: acquiring always succeeds.
                self.operand(c)?;
                c.word()?;
                Value::Integer(0)
            }
            0x27 => {
                self.operand(c)?;
                Value::Uninit
            }
            0x24 | 0x26 => {
                let Operand::Place(Ref::Node(id)) = self.operand(c)? else { return Err(AmlError::TypeMismatch) };
                if op == 0x24 {
                    *self.events.entry(id).or_insert(0) += 1;
                } else {
                    self.events.insert(id, 0);
                }
                Value::Uninit
            }
            0x25 => {
                let Operand::Place(Ref::Node(id)) = self.operand(c)? else { return Err(AmlError::TypeMismatch) };
                self.int_arg(c)?;
                match self.events.get_mut(&id) {
                    Some(n) if *n > 0 => {
                        *n -= 1;
                        Value::Integer(0)
                    }
                    _ => Value::Integer(self.ones()),
                }
            }
            0x28 | 0x29 => {
                let v = self.int_arg(c)?;
                let t = self.target(c)?;
                let r = if op == 0x28 { ops::from_bcd(v) } else { ops::to_bcd(v) }.ok_or(AmlError::InvalidOperand)?;
                let r = Value::Integer(self.trunc(r));
                self.store_target(&t, r.clone())?;
                r
            }
            0x30 => Value::Integer(self.config.revision),
            0x31 => Value::Uninit,
            0x32 => {
                let kind = c.byte()?;
                let code = c.dword()?;
                let arg = self.int_arg(c)?;
                self.host.fatal(kind, code, arg);
                return Err(AmlError::Fatal { kind, code, arg });
            }
            0x33 => Value::Integer(self.host.timer()),
            0x80 => {
                self.region_term(c)?;
                Value::Uninit
            }
            0x81 | 0x86 | 0x87 => {
                self.field_term(op, c)?;
                Value::Uninit
            }
            0x82..=0x85 => {
                self.scope_term(op, c)?;
                Value::Uninit
            }
            0x88 => return Err(AmlError::Unsupported("DataTableRegion")),
            _ => return Err(AmlError::InvalidExtOpcode(op)),
        };
        Ok(Flow::Next(v))
    }

    /// Counts `us` microseconds of sleeping against the budget.
    fn spend(&mut self, us: u64) -> Result<(), AmlError> {
        self.sleep_us = self.sleep_us.saturating_add(us);
        if self.sleep_us > self.config.max_sleep_us { Err(AmlError::Timeout) } else { Ok(()) }
    }

    fn cond_ref_of(&mut self, c: &mut Cursor<'_>) -> Result<Value, AmlError> {
        let src = match c.peek() {
            Some(b) if NameString::starts_with(b) => {
                let name = NameString::parse(c)?;
                self.ns.lookup(self.scope(), &name).map(|id| Ref::Node(self.ns.resolve_alias(id)))
            }
            _ => match self.operand(c)? {
                Operand::Place(r) => Some(r),
                Operand::Value(_) => None,
            },
        };
        let t = self.target(c)?;
        match src {
            Some(r) => {
                self.store_target(&t, Value::Reference(r))?;
                Ok(Value::Integer(self.ones()))
            }
            None => Ok(Value::Integer(0)),
        }
    }

    // ----- data objects -----

    fn buffer_term(&mut self, c: &mut Cursor<'_>) -> Result<Value, AmlError> {
        let end = c.pkg_length()?;
        let mut b = c.until(end);
        c.pos = end;
        let size = self.int_arg(&mut b)?;
        if size > MAX_OBJECT {
            return Err(AmlError::TooLarge);
        }
        let mut buf = alloc::vec![0u8; size as usize];
        let init = b.data.get(b.pos..b.end).unwrap_or_default();
        let n = init.len().min(buf.len());
        if let (Some(dst), Some(src)) = (buf.get_mut(..n), init.get(..n)) {
            dst.copy_from_slice(src);
        }
        Ok(Value::Buffer(buf))
    }

    fn package_term(&mut self, op: u8, c: &mut Cursor<'_>) -> Result<Value, AmlError> {
        let end = c.pkg_length()?;
        let mut b = c.until(end);
        c.pos = end;
        let n = if op == 0x12 { u64::from(b.byte()?) } else { self.int_arg(&mut b)? };
        if n > MAX_PACKAGE {
            return Err(AmlError::TooLarge);
        }
        let n = n as usize;
        let mut items = Vec::with_capacity(n.min(64));
        while !b.at_end() && items.len() < n {
            items.push(self.package_element(&mut b)?);
        }
        items.resize(n, Value::Uninit);
        Ok(Value::Package(items))
    }

    /// A package element. A name stands for the object it names: data is copied, anything else (a device, a
    /// power resource) becomes a reference. A name that does not exist yet is kept as a string.
    fn package_element(&mut self, b: &mut Cursor<'_>) -> Result<Value, AmlError> {
        if !b.peek().is_some_and(NameString::starts_with) {
            return self.arg(b);
        }
        let name = NameString::parse(b)?;
        match self.ns.lookup(self.scope(), &name) {
            Some(id) => {
                let id = self.ns.resolve_alias(id);
                match self.ns.object(id) {
                    Some(Object::Data(_)) => self.read_node(id),
                    _ => Ok(Value::Reference(Ref::Node(id))),
                }
            }
            None => Ok(Value::String(name_text(&name))),
        }
    }

    // ----- expressions -----

    fn arithmetic(&mut self, op: u8, c: &mut Cursor<'_>) -> Result<Value, AmlError> {
        let a = self.int_arg(c)?;
        let b = self.int_arg(c)?;
        let t = self.target(c)?;
        let bits = if self.int64() { 64 } else { 32 };
        let r = match op {
            0x72 => a.wrapping_add(b),
            0x74 => a.wrapping_sub(b),
            0x77 => a.wrapping_mul(b),
            0x79 => {
                if b >= bits {
                    0
                } else {
                    a << b
                }
            }
            0x7a => {
                if b >= bits {
                    0
                } else {
                    a >> b
                }
            }
            0x7b => a & b,
            0x7c => !(a & b),
            0x7d => a | b,
            0x7e => !(a | b),
            0x7f => a ^ b,
            _ => a.checked_rem(b).ok_or(AmlError::DivideByZero)?,
        };
        let r = Value::Integer(self.trunc(r));
        self.store_target(&t, r.clone())?;
        Ok(r)
    }

    fn divide(&mut self, c: &mut Cursor<'_>) -> Result<Value, AmlError> {
        let a = self.int_arg(c)?;
        let b = self.int_arg(c)?;
        let rem = self.target(c)?;
        let quo = self.target(c)?;
        let q = a.checked_div(b).ok_or(AmlError::DivideByZero)?;
        let r = a.checked_rem(b).ok_or(AmlError::DivideByZero)?;
        self.store_target(&rem, Value::Integer(r))?;
        self.store_target(&quo, Value::Integer(q))?;
        Ok(Value::Integer(q))
    }

    /// `Not`, `FindSetLeftBit` and `FindSetRightBit`.
    fn unary(&mut self, op: u8, c: &mut Cursor<'_>) -> Result<Value, AmlError> {
        let a = self.int_arg(c)?;
        let t = self.target(c)?;
        let r = match op {
            0x80 => !a,
            0x81 => ops::find_set_left(a),
            _ => ops::find_set_right(a),
        };
        let r = Value::Integer(self.trunc(r));
        self.store_target(&t, r.clone())?;
        Ok(r)
    }

    fn increment(&mut self, up: bool, c: &mut Cursor<'_>) -> Result<Value, AmlError> {
        let Operand::Place(r) = self.operand(c)? else { return Err(AmlError::TypeMismatch) };
        let cur = self.read_ref(&r)?;
        let n = self.integer_from(cur)?;
        let n = Value::Integer(self.trunc(if up { n.wrapping_add(1) } else { n.wrapping_sub(1) }));
        self.write_ref(&r, n.clone(), Mode::Store)?;
        Ok(n)
    }

    /// Orders two values by the type of the first, converting the second to match.
    fn compare(&mut self, a: Value, b: Value) -> Result<Ordering, AmlError> {
        let a = self.deref_data(a)?;
        let b = self.deref_data(b)?;
        match a {
            Value::Integer(x) => Ok(x.cmp(&self.integer_from(b)?)),
            Value::String(s) => {
                let t = self.string_from(b)?;
                Ok(s.as_bytes().cmp(t.as_bytes()))
            }
            Value::Buffer(x) => Ok(x.cmp(&self.buffer_from(b)?)),
            _ => Err(AmlError::TypeMismatch),
        }
    }

    fn concat(&mut self, c: &mut Cursor<'_>) -> Result<Value, AmlError> {
        let a = self.arg(c)?;
        let b = self.arg(c)?;
        let t = self.target(c)?;
        let a = self.deref_data(a)?;
        let int64 = self.int64();
        let r = match a {
            Value::Integer(x) => {
                let mut buf = ops::integer_to_buffer(x, int64);
                let y = self.integer_from(b)?;
                buf.extend(ops::integer_to_buffer(y, int64));
                Value::Buffer(buf)
            }
            Value::String(mut s) => {
                s.push_str(&self.string_from(b)?);
                if s.len() as u64 > MAX_OBJECT {
                    return Err(AmlError::TooLarge);
                }
                Value::String(s)
            }
            Value::Buffer(mut x) => {
                x.extend(self.buffer_from(b)?);
                if x.len() as u64 > MAX_OBJECT {
                    return Err(AmlError::TooLarge);
                }
                Value::Buffer(x)
            }
            _ => return Err(AmlError::TypeMismatch),
        };
        self.store_target(&t, r.clone())?;
        Ok(r)
    }

    /// `ConcatenateResTemplate`: two resource templates joined, dropping the first's end tag.
    fn concat_res(&mut self, c: &mut Cursor<'_>) -> Result<Value, AmlError> {
        let a = self.arg(c)?;
        let b = self.arg(c)?;
        let t = self.target(c)?;
        let mut a = self.buffer_from(a)?;
        let b = self.buffer_from(b)?;
        // The end tag is the last two bytes: 0x79 and a checksum.
        if a.len() >= 2 && a.get(a.len() - 2) == Some(&0x79) {
            a.truncate(a.len() - 2);
        }
        a.extend(b);
        if a.len() as u64 > MAX_OBJECT {
            return Err(AmlError::TooLarge);
        }
        let r = Value::Buffer(a);
        self.store_target(&t, r.clone())?;
        Ok(r)
    }

    fn mid(&mut self, c: &mut Cursor<'_>) -> Result<Value, AmlError> {
        let src = self.arg(c)?;
        let index = self.int_arg(c)?;
        let len = self.int_arg(c)?;
        let t = self.target(c)?;
        let src = self.deref_data(src)?;
        let window = |total: usize| {
            let start = (index as usize).min(total);
            let end = start.saturating_add(len as usize).min(total);
            (start, end)
        };
        let r = match src {
            Value::String(s) => {
                let (a, b) = window(s.len());
                Value::String(s.bytes().skip(a).take(b - a).map(char::from).collect())
            }
            other => {
                let buf = self.buffer_from(other)?;
                let (a, b) = window(buf.len());
                Value::Buffer(buf.get(a..b).unwrap_or_default().to_vec())
            }
        };
        self.store_target(&t, r.clone())?;
        Ok(r)
    }

    /// `ToBuffer`, `ToDecimalString`, `ToHexString`, `ToInteger` and `ToString`.
    fn convert(&mut self, op: u8, c: &mut Cursor<'_>) -> Result<Value, AmlError> {
        let v = self.arg(c)?;
        let limit = if op == 0x9c { Some(self.int_arg(c)?) } else { None };
        let t = self.target(c)?;
        let v = self.deref_data(v)?;
        let int64 = self.int64();
        let r = match op {
            0x96 => Value::Buffer(self.buffer_from(v)?),
            0x99 => match v {
                Value::String(s) => Value::Integer(ops::parse_integer(&s, int64).ok_or(AmlError::InvalidOperand)?),
                other => Value::Integer(self.integer_from(other)?),
            },
            0x9c => match v {
                Value::Buffer(b) => {
                    let n = match limit {
                        Some(l) if l != 0 && l < u64::from(u32::MAX) => l as usize,
                        _ => usize::MAX,
                    };
                    Value::String(
                        b.iter()
                            .take(n)
                            .take_while(|&&x| x != 0)
                            .map(|&x| if x < 0x80 { char::from(x) } else { '?' })
                            .collect(),
                    )
                }
                other => Value::String(self.string_from(other)?),
            },
            _ => {
                let hex = op == 0x98;
                match v {
                    Value::Integer(i) => Value::String(if hex { ops::hex_string(i, 0) } else { alloc::format!("{i}") }),
                    Value::Buffer(b) => {
                        let parts: Vec<String> = b
                            .iter()
                            .map(|&x| if hex { ops::hex_string(u64::from(x), 2) } else { alloc::format!("{x}") })
                            .collect();
                        Value::String(parts.join(","))
                    }
                    Value::String(s) => Value::String(s),
                    _ => return Err(AmlError::TypeMismatch),
                }
            }
        };
        self.store_target(&t, r.clone())?;
        Ok(r)
    }

    fn deref_of(&mut self, c: &mut Cursor<'_>) -> Result<Value, AmlError> {
        match self.arg(c)? {
            Value::Reference(r) => self.read_ref(&r),
            Value::String(path) => {
                let (root, segs) = super::namespace::parse_path(&path)?;
                let mut cur = if root { super::namespace::ROOT } else { self.scope() };
                for seg in segs {
                    cur = self.ns.child(cur, seg).ok_or(AmlError::NotFound)?;
                }
                self.read_node(cur)
            }
            other => Ok(other),
        }
    }

    fn size_of(&mut self, c: &mut Cursor<'_>) -> Result<Value, AmlError> {
        let v = match self.operand(c)? {
            Operand::Place(r) => self.read_data(&r)?,
            Operand::Value(v) => v,
        };
        let n = match v {
            Value::String(s) => s.len(),
            Value::Buffer(b) => b.len(),
            Value::Package(p) => p.len(),
            _ => return Err(AmlError::TypeMismatch),
        };
        Ok(Value::Integer(n as u64))
    }

    fn index(&mut self, c: &mut Cursor<'_>) -> Result<Value, AmlError> {
        let base = match self.operand(c)? {
            Operand::Place(r) => self.resolve_place(r)?,
            Operand::Value(v) => self.anonymous(v)?,
        };
        let index = self.int_arg(c)?;
        let t = self.target(c)?;
        let len = match self.place_value(&base) {
            Ok(Value::Package(p)) => p.len(),
            Ok(Value::Buffer(b)) => b.len(),
            Ok(Value::String(s)) => s.len(),
            _ => return Err(AmlError::TypeMismatch),
        };
        if index >= len as u64 {
            return Err(AmlError::OutOfBounds);
        }
        let r = Value::Reference(Ref::Index { base: alloc::boxed::Box::new(base), index: index as usize });
        self.store_target(&t, r.clone())?;
        Ok(r)
    }

    fn match_term(&mut self, c: &mut Cursor<'_>) -> Result<Value, AmlError> {
        let pkg = self.arg(c)?;
        let op1 = c.byte()?;
        let obj1 = self.arg(c)?;
        let op2 = c.byte()?;
        let obj2 = self.arg(c)?;
        let start = self.int_arg(c)?;
        let Value::Package(items) = self.deref_data(pkg)? else { return Err(AmlError::TypeMismatch) };
        for (i, item) in items.into_iter().enumerate().skip(start.min(usize::MAX as u64) as usize) {
            if !matches!(item, Value::Integer(_) | Value::String(_) | Value::Buffer(_)) {
                continue;
            }
            if self.match_op(op1, &item, &obj1)? && self.match_op(op2, &item, &obj2)? {
                return Ok(Value::Integer(i as u64));
            }
        }
        Ok(Value::Integer(self.ones()))
    }

    fn match_op(&mut self, op: u8, item: &Value, obj: &Value) -> Result<bool, AmlError> {
        if op == 0 {
            return Ok(true);
        }
        let ord = match self.compare(item.clone(), obj.clone()) {
            Ok(o) => o,
            Err(AmlError::TypeMismatch | AmlError::InvalidOperand) => return Ok(false),
            Err(e) => return Err(e),
        };
        Ok(match op {
            1 => ord == Ordering::Equal,
            2 => ord != Ordering::Greater,
            3 => ord == Ordering::Less,
            4 => ord != Ordering::Less,
            5 => ord == Ordering::Greater,
            _ => return Err(AmlError::InvalidOperand),
        })
    }

    fn object_type(&mut self, c: &mut Cursor<'_>) -> Result<Value, AmlError> {
        if c.peek() == Some(0x5b) && c.data.get(c.pos + 1) == Some(&0x31) {
            c.pos += 2;
            return Ok(Value::Integer(16));
        }
        let code = match c.peek() {
            Some(b) if NameString::starts_with(b) => {
                let name = NameString::parse(c)?;
                match self.ns.lookup(self.scope(), &name) {
                    Some(id) => self.type_of_node(id)?,
                    None => 0,
                }
            }
            _ => match self.operand(c)? {
                Operand::Place(r) => self.type_of_ref(&r)?,
                Operand::Value(v) => type_code(&v),
            },
        };
        Ok(Value::Integer(code))
    }

    fn type_of_ref(&mut self, r: &Ref) -> Result<u64, AmlError> {
        match r {
            Ref::Node(id) => self.type_of_node(*id),
            Ref::Index { base, .. } => {
                let b = self.resolve_place(base.as_ref().clone())?;
                if matches!(self.place_value(&b), Ok(Value::Package(_))) {
                    let v = self.read_ref(r)?;
                    match v {
                        Value::Reference(inner) => self.type_of_ref(&inner),
                        v => Ok(type_code(&v)),
                    }
                } else {
                    Ok(14)
                }
            }
            _ => match self.read_ref(r)? {
                Value::Reference(inner) => self.type_of_ref(&inner),
                v => Ok(type_code(&v)),
            },
        }
    }

    fn type_of_node(&mut self, id: NodeId) -> Result<u64, AmlError> {
        let id = self.ns.resolve_alias(id);
        Ok(match self.ns.object(id).ok_or(AmlError::NotFound)? {
            Object::Data(_) => {
                self.ensure_ready(id)?;
                match self.ns.object(id) {
                    Some(Object::Data(Data::Ready(v))) => type_code(v),
                    _ => 0,
                }
            }
            Object::Field(_) => 5,
            Object::Device | Object::Scope => 6,
            Object::Event => 7,
            Object::Method(_) | Object::Native(_) => 8,
            Object::Mutex => 9,
            Object::Region(_) => 10,
            Object::PowerResource => 11,
            Object::Processor => 12,
            Object::ThermalZone => 13,
            Object::BufferField(_) => 14,
            Object::Alias(_) | Object::Removed => 0,
        })
    }

    // ----- control flow -----

    fn if_else(&mut self, c: &mut Cursor<'_>) -> Result<Flow, AmlError> {
        let end = c.pkg_length()?;
        let mut body = c.until(end);
        c.pos = end;
        let pred = self.int_arg(&mut body)?;
        let mut else_body = None;
        if c.peek() == Some(0xa1) {
            c.pos += 1;
            let e_end = c.pkg_length()?;
            else_body = Some(c.until(e_end));
            c.pos = e_end;
        }
        if pred != 0 {
            self.exec_list(&mut body)
        } else if let Some(mut e) = else_body {
            self.exec_list(&mut e)
        } else {
            Ok(Flow::Next(Value::Uninit))
        }
    }

    fn while_loop(&mut self, c: &mut Cursor<'_>) -> Result<Flow, AmlError> {
        let end = c.pkg_length()?;
        let start = c.pos;
        c.pos = end;
        loop {
            let mut body = Cursor::new(c.data, start, end);
            if self.int_arg(&mut body)? == 0 {
                break;
            }
            match self.exec_list(&mut body)? {
                Flow::Next(_) | Flow::Continue => {}
                Flow::Break => break,
                r @ Flow::Return(_) => return Ok(r),
            }
        }
        Ok(Flow::Next(Value::Uninit))
    }
}

/// A string constant: bytes up to a NUL. Anything outside ASCII becomes `?`.
fn string_constant(c: &mut Cursor<'_>) -> Result<String, AmlError> {
    let mut s = String::new();
    loop {
        match c.byte()? {
            0 => return Ok(s),
            b => s.push(if b < 0x80 { char::from(b) } else { '?' }),
        }
        if s.len() as u64 > MAX_OBJECT {
            return Err(AmlError::TooLarge);
        }
    }
}

/// A name as AML text, for messages and for names that did not resolve.
pub(crate) fn name_text(name: &NameString<'_>) -> String {
    let mut s = String::new();
    if name.root {
        s.push('\\');
    }
    for _ in 0..name.parents {
        s.push('^');
    }
    for (i, seg) in name.segments().enumerate() {
        if i > 0 {
            s.push('.');
        }
        s.push_str(seg.as_str());
    }
    s
}
