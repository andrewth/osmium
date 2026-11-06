// SPDX-License-Identifier: GPL-2.0-only
//! The ACPI namespace: a tree of named objects.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write;

use super::error::AmlError;
use super::name::{NameSeg, NameString};
use super::value::{Ref, Value};

/// Most objects the namespace may hold, a bound on what a hostile table can make the interpreter allocate.
const MAX_NODES: usize = 1 << 20;

/// Roughly what one namespace entry costs to hold, not counting its data. Creating an object charges this
/// against [`Config::max_alloc_bytes`](super::Config::max_alloc_bytes).
pub(crate) const NODE_COST: usize = core::mem::size_of::<Node>() + 32;

/// A handle to an object in the [`Namespace`]. It stays valid until the object is removed, which only
/// happens to objects a method created for itself. A handle to a removed object never refers to anything
/// again: the slot's next occupant gets a new generation, so the stale handle finds nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId {
    pub(crate) index: u32,
    pub(crate) generation: u32,
}

/// The root of the namespace, `\`.
pub const ROOT: NodeId = NodeId { index: 0, generation: 0 };

/// What kind of object a namespace entry is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectKind {
    /// The root or a predefined scope such as `\_SB_`.
    Scope,
    /// A named integer, string, buffer or package.
    Data,
    /// A control method (or a method the interpreter implements itself, such as `_OSI`).
    Method,
    /// A `Device`.
    Device,
    /// A `Processor`.
    Processor,
    /// A `ThermalZone`.
    ThermalZone,
    /// A `PowerResource`.
    PowerResource,
    /// A `Mutex`.
    Mutex,
    /// An `Event`.
    Event,
    /// An `OperationRegion`.
    OpRegion,
    /// A field of an operation region, index field or bank field.
    Field,
    /// A field of a buffer (`CreateField` and relatives).
    BufferField,
    /// An `Alias`.
    Alias,
}

/// AML code that is evaluated when its result is first needed.
#[derive(Clone, Debug)]
pub(crate) struct Lazy {
    pub code: Arc<[u8]>,
    pub start: usize,
    pub end: usize,
    pub int64: bool,
}

/// A named object's data, evaluated on first use so a table can refer to names defined after it.
#[derive(Clone, Debug)]
pub(crate) enum Data {
    Ready(Value),
    Lazy(Lazy),
}

#[derive(Clone, Debug)]
pub(crate) struct Method {
    pub code: Arc<[u8]>,
    pub start: usize,
    pub end: usize,
    pub args: u8,
    pub int64: bool,
}

/// Methods the interpreter implements itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Native {
    /// `\_OSI`
    Osi,
}

#[derive(Clone, Debug)]
pub(crate) struct Region {
    pub space: u8,
    pub offset: u64,
    pub length: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Update {
    Preserve,
    Ones,
    Zeros,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum FieldKind {
    Region(NodeId),
    Index { index: NodeId, data: NodeId },
    Bank { region: NodeId, bank: NodeId, value: u64 },
}

#[derive(Clone, Debug)]
pub(crate) struct FieldUnit {
    pub kind: FieldKind,
    pub bit_offset: u64,
    pub bit_len: u64,
    /// The access type from the field flags: 0 any, 1 byte, 2 word, 3 dword, 4 qword, 5 buffer.
    pub access: u8,
    pub update: Update,
    /// Whether the defining table has 64-bit integers.
    pub int64: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct BufferField {
    pub source: Ref,
    pub bit_offset: u64,
    pub bit_len: u64,
    pub int64: bool,
}

#[derive(Clone, Debug)]
pub(crate) enum Object {
    Scope,
    Data(Data),
    Method(Method),
    Native(Native),
    Device,
    Processor,
    ThermalZone,
    PowerResource,
    Mutex,
    Event,
    Region(Region),
    Field(FieldUnit),
    BufferField(BufferField),
    Alias(NodeId),
    Removed,
}

struct Node {
    /// Bumped each time the slot is reused, so a [`NodeId`] of an earlier occupant no longer matches.
    generation: u32,
    /// The bytes of data this object held when last measured (see [`Namespace::retained_bytes`]).
    retained: usize,
    name: NameSeg,
    parent: Option<NodeId>,
    /// Children by name, for lookup.
    children: BTreeMap<NameSeg, NodeId>,
    /// Children in the order they were declared, which is the order ACPI walks them in.
    order: Vec<NodeId>,
    object: Object,
}

/// The tree of named objects the loaded tables define.
pub struct Namespace {
    nodes: Vec<Node>,
    free: Vec<u32>,
    /// The sum of every node's `retained`.
    retained: usize,
}

impl Namespace {
    pub(crate) fn new() -> Self {
        let root = Node {
            generation: 0,
            retained: 0,
            name: NameSeg(*b"\\___"),
            parent: None,
            children: BTreeMap::new(),
            order: Vec::new(),
            object: Object::Scope,
        };
        Self { nodes: alloc::vec![root], free: Vec::new(), retained: 0 }
    }

    fn node(&self, id: NodeId) -> Option<&Node> {
        self.nodes
            .get(id.index as usize)
            .filter(|n| n.generation == id.generation && !matches!(n.object, Object::Removed))
    }

    fn node_mut(&mut self, id: NodeId) -> Option<&mut Node> {
        self.nodes
            .get_mut(id.index as usize)
            .filter(|n| n.generation == id.generation && !matches!(n.object, Object::Removed))
    }

    pub(crate) fn object(&self, id: NodeId) -> Option<&Object> {
        self.node(id).map(|n| &n.object)
    }

    pub(crate) fn object_mut(&mut self, id: NodeId) -> Option<&mut Object> {
        self.node_mut(id).map(|n| &mut n.object)
    }

    /// How many bytes of data (strings, buffers and packages) the objects in the namespace held when they
    /// were last measured, which is at the end of each outermost call. The interpreter keeps this at or
    /// below [`Config::max_retained_bytes`](super::Config::max_retained_bytes).
    pub fn retained_bytes(&self) -> usize {
        self.retained
    }

    pub(crate) fn retained_of(&self, id: NodeId) -> usize {
        self.node(id).map_or(0, |n| n.retained)
    }

    /// Records that `id` now holds `bytes` bytes of data.
    pub(crate) fn set_retained(&mut self, id: NodeId, bytes: usize) {
        let Some(n) = self.node_mut(id) else { return };
        let old = core::mem::replace(&mut n.retained, bytes);
        self.retained = self.retained.saturating_sub(old).saturating_add(bytes);
    }

    /// Whether `id` still names an object.
    pub fn exists(&self, id: NodeId) -> bool {
        self.node(id).is_some()
    }

    /// The kind of object at `id`.
    pub fn kind(&self, id: NodeId) -> Option<ObjectKind> {
        Some(match self.object(id)? {
            Object::Scope => ObjectKind::Scope,
            Object::Data(_) => ObjectKind::Data,
            Object::Method(_) | Object::Native(_) => ObjectKind::Method,
            Object::Device => ObjectKind::Device,
            Object::Processor => ObjectKind::Processor,
            Object::ThermalZone => ObjectKind::ThermalZone,
            Object::PowerResource => ObjectKind::PowerResource,
            Object::Mutex => ObjectKind::Mutex,
            Object::Event => ObjectKind::Event,
            Object::Region(_) => ObjectKind::OpRegion,
            Object::Field(_) => ObjectKind::Field,
            Object::BufferField(_) => ObjectKind::BufferField,
            Object::Alias(_) => ObjectKind::Alias,
            Object::Removed => return None,
        })
    }

    /// The object's name segment.
    pub fn name(&self, id: NodeId) -> Option<NameSeg> {
        self.node(id).map(|n| n.name)
    }

    /// The enclosing scope; `None` for the root.
    pub fn parent(&self, id: NodeId) -> Option<NodeId> {
        self.node(id)?.parent
    }

    /// The child of `id` named `seg`.
    pub fn child(&self, id: NodeId, seg: NameSeg) -> Option<NodeId> {
        self.node(id)?.children.get(&seg).copied()
    }

    /// The objects declared directly in `id`, in the order they were declared.
    pub fn children(&self, id: NodeId) -> impl Iterator<Item = (NameSeg, NodeId)> + '_ {
        self.node(id).into_iter().flat_map(|n| n.order.iter().filter_map(|&c| Some((self.node(c)?.name, c))))
    }

    /// Every object under `id` (not including it), parents before children.
    pub fn descendants(&self, id: NodeId) -> Vec<NodeId> {
        let mut out = Vec::new();
        let mut stack: Vec<NodeId> = self.children(id).map(|(_, c)| c).collect();
        stack.reverse();
        while let Some(n) = stack.pop() {
            out.push(n);
            let before = stack.len();
            stack.extend(self.children(n).map(|(_, c)| c));
            if let Some(added) = stack.get_mut(before..) {
                added.reverse();
            }
        }
        out
    }

    /// The absolute path of `id`, such as `\_SB_.PCI0`.
    pub fn path(&self, id: NodeId) -> String {
        let mut segs = Vec::new();
        let mut cur = id;
        while let Some(n) = self.node(cur) {
            let Some(parent) = n.parent else { break };
            segs.push(n.name);
            cur = parent;
        }
        let mut s = String::from("\\");
        for (i, seg) in segs.iter().rev().enumerate() {
            if i > 0 {
                s.push('.');
            }
            let _ = write!(s, "{seg}");
        }
        s
    }

    /// Finds an object by path: `\_SB.PCI0` is absolute, `PCI0` is relative to the root. Segments shorter
    /// than four characters are padded with `_`, so `_SB` and `_SB_` are the same.
    pub fn find(&self, path: &str) -> Option<NodeId> {
        self.find_from(ROOT, path)
    }

    /// Like [`find`](Self::find), but a relative path starts at `scope`.
    pub fn find_from(&self, scope: NodeId, path: &str) -> Option<NodeId> {
        let (root, segs) = parse_path(path).ok()?;
        let mut cur = if root { ROOT } else { scope };
        for seg in segs {
            cur = self.resolve_alias(self.child(cur, seg)?);
        }
        Some(cur)
    }

    /// Follows `Alias` objects to the object they name.
    pub fn resolve_alias(&self, mut id: NodeId) -> NodeId {
        for _ in 0..16 {
            match self.object(id) {
                Some(Object::Alias(target)) => id = *target,
                _ => break,
            }
        }
        id
    }

    /// Resolves a name from inside `scope`. A bare segment is searched for in `scope` and then in each
    /// enclosing scope; any other name is looked up exactly.
    pub(crate) fn lookup(&self, scope: NodeId, name: &NameString<'_>) -> Option<NodeId> {
        let mut segs = name.segments();
        if name.is_simple() {
            let seg = segs.next()?;
            let mut s = Some(scope);
            while let Some(n) = s {
                if let Some(c) = self.child(n, seg) {
                    return Some(c);
                }
                s = self.parent(n);
            }
            return None;
        }
        let mut cur = if name.root { ROOT } else { scope };
        for _ in 0..name.parents {
            cur = self.parent(cur)?;
        }
        for seg in segs {
            cur = self.child(self.resolve_alias(cur), seg)?;
        }
        Some(cur)
    }

    /// Finds the scope a new object named by `name` goes in, and its segment. Every segment but the last
    /// must exist.
    pub(crate) fn locate_new(&self, scope: NodeId, name: &NameString<'_>) -> Result<(NodeId, NameSeg), AmlError> {
        let mut cur = if name.root { ROOT } else { scope };
        for _ in 0..name.parents {
            cur = self.parent(cur).ok_or(AmlError::NotFound)?;
        }
        let mut last = None;
        for seg in name.segments() {
            if let Some(prev) = last.replace(seg) {
                cur = self.resolve_alias(self.child(cur, prev).ok_or(AmlError::NotFound)?);
            }
        }
        Ok((cur, last.ok_or(AmlError::InvalidName)?))
    }

    pub(crate) fn insert(&mut self, parent: NodeId, name: NameSeg, object: Object) -> Result<NodeId, AmlError> {
        if self.node(parent).ok_or(AmlError::NotFound)?.children.contains_key(&name) {
            return Err(AmlError::AlreadyExists);
        }
        let id = self.alloc(name, Some(parent), object)?;
        if let Some(p) = self.node_mut(parent) {
            p.children.insert(name, id);
            p.order.push(id);
        }
        Ok(id)
    }

    /// An object with no name, for values that need a place to live.
    pub(crate) fn insert_anonymous(&mut self, object: Object) -> Result<NodeId, AmlError> {
        self.alloc(NameSeg(*b"____"), None, object)
    }

    fn alloc(&mut self, name: NameSeg, parent: Option<NodeId>, object: Object) -> Result<NodeId, AmlError> {
        let fresh = |generation| Node {
            generation,
            retained: 0,
            name,
            parent,
            children: BTreeMap::new(),
            order: Vec::new(),
            object,
        };
        if let Some(slot) = self.free.pop()
            && let Some(n) = self.nodes.get_mut(slot as usize)
        {
            // A slot is only freed while its generation can still be bumped (see `remove`).
            let generation = n.generation.wrapping_add(1);
            *n = fresh(generation);
            return Ok(NodeId { index: slot, generation });
        }
        if self.nodes.len() >= MAX_NODES {
            return Err(AmlError::TooLarge);
        }
        self.nodes.try_reserve(1).map_err(|_| AmlError::OutOfMemory)?;
        self.nodes.push(fresh(0));
        Ok(NodeId { index: (self.nodes.len() - 1) as u32, generation: 0 })
    }

    /// Removes `id` and everything under it, and gives what was removed.
    pub(crate) fn remove(&mut self, id: NodeId) -> Vec<NodeId> {
        if id == ROOT || self.node(id).is_none() {
            return Vec::new();
        }
        let mut doomed = self.descendants(id);
        doomed.push(id);
        if let Some(Node { parent: Some(p), name, .. }) = self.node(id) {
            let (p, name) = (*p, *name);
            if let Some(pn) = self.node_mut(p)
                && pn.children.get(&name) == Some(&id)
            {
                pn.children.remove(&name);
                pn.order.retain(|&c| c != id);
            }
        }
        for &d in &doomed {
            if let Some(n) = self.node_mut(d) {
                n.object = Object::Removed;
                n.children = BTreeMap::new();
                n.order = Vec::new();
                n.parent = None;
                let retained = core::mem::take(&mut n.retained);
                // A slot whose generation would wrap is retired rather than reused, so that no handle to an
                // earlier occupant can ever match again.
                let reusable = n.generation != u32::MAX;
                self.retained = self.retained.saturating_sub(retained);
                if reusable {
                    self.free.push(d.index);
                }
            }
        }
        doomed
    }
}

/// Splits `\_SB.PCI0` into whether it is absolute and its segments.
pub(crate) fn parse_path(path: &str) -> Result<(bool, Vec<NameSeg>), AmlError> {
    let (root, rest) = match path.strip_prefix('\\') {
        Some(r) => (true, r),
        None => (false, path),
    };
    let mut segs = Vec::new();
    if rest.is_empty() {
        return Ok((root, segs));
    }
    for part in rest.split('.') {
        let b = part.as_bytes();
        if b.is_empty() || b.len() > 4 {
            return Err(AmlError::InvalidPath);
        }
        let mut seg = [b'_'; 4];
        for (d, s) in seg.iter_mut().zip(b) {
            *d = *s;
        }
        segs.push(NameSeg::new(seg).ok_or(AmlError::InvalidPath)?);
    }
    Ok((root, segs))
}
