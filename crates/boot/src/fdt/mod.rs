//! Flattened Device Tree.
//!
//! ```ignore
//! let fdt = unsafe { Fdt::from_ptr(dtb_addr as *const u8) }?;
//! let uart = fdt.find_compatible(&["ns16550a"]).unwrap();
//! let (base, size) = uart.reg().next().unwrap();
//! let bootargs = fdt.chosen().and_then(|c| c.property("bootargs")).and_then(|p| p.as_str());
//! ```

#[cfg(feature = "alloc")]
mod writer;
#[cfg(feature = "alloc")]
pub use writer::FdtWriter;

use core::fmt;

use osmium_mm::{MemoryMap, PhysAddr, RegionKind};

use crate::{be32, be64, cstr};

const MAGIC: u32 = 0xd00d_feed;
const BEGIN_NODE: u32 = 1;
const END_NODE: u32 = 2;
const PROP: u32 = 3;
const NOP: u32 = 4;
const END: u32 = 9;
const MAX_DEPTH: usize = 32;

/// Why a blob is not a usable device tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FdtError {
    /// Wrong magic number.
    BadMagic,
    /// The header or a block lies outside the blob.
    Truncated,
    /// Format versions older than 16 are not supported.
    BadVersion,
}

/// A parsed device tree blob.
#[derive(Clone, Copy)]
pub struct Fdt<'a> {
    data: &'a [u8],
    /// Struct block `[start, end)`.
    structs: Span,
    /// Strings block `[start, end)`.
    strings: Span,
    rsvmap: usize,
    boot_cpu: u32,
}

impl<'a> Fdt<'a> {
    /// Validates the header of `data`.
    pub fn new(data: &'a [u8]) -> Result<Self, FdtError> {
        let h = |i: usize| be32(data, i * 4).ok_or(FdtError::Truncated);
        if h(0)? != MAGIC {
            return Err(FdtError::BadMagic);
        }
        let total = h(1)? as usize;
        if total > data.len() {
            return Err(FdtError::Truncated);
        }
        if h(6)? > 17 || h(5)? < 16 {
            return Err(FdtError::BadVersion);
        }
        let data = &data[..total];
        let (s_off, st_off, rsv) = (h(2)? as usize, h(3)? as usize, h(4)? as usize);
        let (st_size, s_size) = (h(8)? as usize, h(9)? as usize);
        let structs = Span { start: s_off, end: s_off.checked_add(s_size).ok_or(FdtError::Truncated)? };
        let strings = Span { start: st_off, end: st_off.checked_add(st_size).ok_or(FdtError::Truncated)? };
        if structs.end > total || strings.end > total || rsv > total {
            return Err(FdtError::Truncated);
        }
        Ok(Self { data, structs, strings, rsvmap: rsv, boot_cpu: h(7)? })
    }

    /// Parses the blob at `ptr`, reading its length from the header.
    ///
    /// # Safety
    /// `ptr` must point to a readable device tree that stays valid and
    /// unmodified for `'a`.
    pub unsafe fn from_ptr(ptr: *const u8) -> Result<Self, FdtError> {
        // SAFETY: the caller guarantees the header is readable.
        let header = unsafe { core::slice::from_raw_parts(ptr, 8) };
        if be32(header, 0) != Some(MAGIC) {
            return Err(FdtError::BadMagic);
        }
        let total = be32(header, 4).ok_or(FdtError::Truncated)? as usize;
        // SAFETY: the caller guarantees the whole blob is readable.
        Self::new(unsafe { core::slice::from_raw_parts(ptr, total) })
    }

    /// Size of the blob in bytes.
    pub fn total_size(&self) -> usize {
        self.data.len()
    }

    /// Physical id of the boot CPU.
    pub fn boot_cpu(&self) -> u32 {
        self.boot_cpu
    }

    /// The root node.
    pub fn root(&self) -> Node<'a> {
        Node { fdt: *self, begin: self.structs.start + self.skip_nops(0), parent_cells: Cells::ROOT }
    }

    /// Finds a node by absolute path. A path component without a unit
    /// address (`memory`) matches a node with one (`memory@80000000`).
    pub fn find_node(&self, path: &str) -> Option<Node<'a>> {
        let mut node = self.root();
        for part in path.split('/').filter(|p| !p.is_empty()) {
            node = node.children().find(|c| {
                let name = c.name();
                name == part || (!part.contains('@') && name.split('@').next() == Some(part))
            })?;
        }
        Some(node)
    }

    /// Every node, depth-first.
    pub fn all_nodes(&self) -> AllNodes<'a> {
        AllNodes { fdt: *self, off: self.root().begin, stack: [Cells::ROOT; MAX_DEPTH], depth: 0 }
    }

    /// The first node compatible with any of `compatible`.
    pub fn find_compatible(&self, compatible: &[&str]) -> Option<Node<'a>> {
        self.all_nodes().find(|n| n.compatible().any(|c| compatible.contains(&c)))
    }

    /// The `/chosen` node.
    pub fn chosen(&self) -> Option<Node<'a>> {
        self.find_node("/chosen")
    }

    /// The `bootargs` property of `/chosen`.
    pub fn bootargs(&self) -> Option<&'a str> {
        self.chosen()?.property("bootargs")?.as_str()
    }

    /// `(address, size)` of every RAM range in `device_type = "memory"` nodes.
    pub fn memory(&self) -> impl Iterator<Item = (u64, u64)> + 'a + use<'a> {
        self.all_nodes()
            .filter(|n| n.property("device_type").and_then(|p| p.as_str()) == Some("memory"))
            .flat_map(|n| n.reg().map(|(a, s)| (a, s.unwrap_or(0))))
    }

    /// Entries of the memory reservation block.
    pub fn reservations(&self) -> impl Iterator<Item = (u64, u64)> + 'a + use<'a> {
        let data = self.data;
        let base = self.rsvmap;
        (0..)
            .map(move |i| Some((be64(data, base + i * 16)?, be64(data, base + i * 16 + 8)?)))
            .map_while(|e| e.filter(|&(a, s)| a != 0 || s != 0))
    }

    /// Adds RAM, reserved ranges (the reservation block and
    /// `/reserved-memory` children) and, if given, the blob itself to `map`.
    pub fn fill_memory_map<const N: usize>(
        &self,
        map: &mut MemoryMap<N>,
        blob_at: Option<PhysAddr>,
    ) -> Result<(), osmium_mm::map::MapFull> {
        let range = |a: u64, s: u64| (PhysAddr::new(a), PhysAddr::new(a.saturating_add(s)));
        for (a, s) in self.memory() {
            let (lo, hi) = range(a, s);
            map.add(lo, hi, RegionKind::Usable)?;
        }
        for (a, s) in self.reservations() {
            let (lo, hi) = range(a, s);
            map.reserve(lo, hi, RegionKind::Reserved)?;
        }
        if let Some(rm) = self.find_node("/reserved-memory") {
            for (a, s) in rm.children().flat_map(|c| c.reg()) {
                let (lo, hi) = range(a, s.unwrap_or(0));
                map.reserve(lo, hi, RegionKind::Reserved)?;
            }
        }
        if let Some(at) = blob_at {
            map.reserve(at, at + self.total_size() as u64, RegionKind::Bootloader)?;
        }
        Ok(())
    }

    fn token(&self, off: usize) -> Option<u32> {
        if off >= self.structs.end {
            return None;
        }
        be32(self.data, off)
    }

    fn skip_nops(&self, rel: usize) -> usize {
        let mut off = self.structs.start + rel;
        while self.token(off) == Some(NOP) {
            off += 4;
        }
        off - self.structs.start
    }

    fn string(&self, nameoff: usize) -> Option<&'a str> {
        cstr(self.data.get(self.strings.start + nameoff..self.strings.end)?)
    }

    /// Parses the property at `off`; returns it and the offset after it.
    fn prop_at(&self, off: usize) -> Option<(Property<'a>, usize)> {
        let len = be32(self.data, off + 4)? as usize;
        let name = self.string(be32(self.data, off + 8)? as usize)?;
        let value = self.data.get(off + 12..off + 12 + len)?;
        Some((Property { name, value }, align4(off + 12 + len)))
    }

    /// Returns the offset just past the END_NODE matching the BEGIN_NODE at `begin`.
    fn skip_node(&self, begin: usize) -> Option<usize> {
        let mut depth = 0usize;
        let mut off = begin;
        loop {
            match self.token(off)? {
                BEGIN_NODE => {
                    depth += 1;
                    off = align4(off + 4 + cstr(self.data.get(off + 4..)?)?.len() + 1);
                }
                END_NODE => {
                    depth -= 1;
                    off += 4;
                    if depth == 0 {
                        return Some(off);
                    }
                }
                PROP => off = self.prop_at(off)?.1,
                NOP => off += 4,
                _ => return None,
            }
        }
    }
}

impl fmt::Debug for Fdt<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Fdt").field("size", &self.total_size()).field("boot_cpu", &self.boot_cpu).finish()
    }
}

#[derive(Clone, Copy, Debug)]
struct Span {
    start: usize,
    end: usize,
}

impl Span {
    #[cfg(test)]
    fn len(&self) -> usize {
        self.end - self.start
    }
}

const fn align4(x: usize) -> usize {
    (x + 3) & !3
}

/// `#address-cells` and `#size-cells` in effect for a node's `reg`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cells {
    /// Cells per address.
    pub address: u32,
    /// Cells per size.
    pub size: u32,
}

impl Cells {
    /// Defaults the specification prescribes when a node gives none.
    pub const ROOT: Self = Self { address: 2, size: 1 };
}

/// A node of the tree.
#[derive(Clone, Copy)]
pub struct Node<'a> {
    fdt: Fdt<'a>,
    /// Offset of the BEGIN_NODE token.
    begin: usize,
    parent_cells: Cells,
}

impl<'a> Node<'a> {
    /// The node's name, including any unit address (`uart@10000000`). The
    /// root's name is empty.
    pub fn name(&self) -> &'a str {
        self.fdt.data.get(self.begin + 4..).and_then(cstr).unwrap_or("")
    }

    fn props_start(&self) -> usize {
        align4(self.begin + 4 + self.name().len() + 1)
    }

    /// The node's properties.
    pub fn properties(&self) -> impl Iterator<Item = Property<'a>> + 'a + use<'a> {
        let fdt = self.fdt;
        let mut off = self.props_start();
        core::iter::from_fn(move || {
            loop {
                match fdt.token(off)? {
                    NOP => off += 4,
                    PROP => {
                        let (p, next) = fdt.prop_at(off)?;
                        off = next;
                        return Some(p);
                    }
                    _ => return None,
                }
            }
        })
    }

    /// The property called `name`.
    pub fn property(&self, name: &str) -> Option<Property<'a>> {
        self.properties().find(|p| p.name == name)
    }

    /// Cells this node defines for its children's `reg`.
    pub fn child_cells(&self) -> Cells {
        let get = |n: &str, d| self.property(n).and_then(|p| p.as_u32()).unwrap_or(d);
        Cells { address: get("#address-cells", 2), size: get("#size-cells", 1) }
    }

    /// The node's direct children.
    pub fn children(&self) -> impl Iterator<Item = Node<'a>> + 'a + use<'a> {
        let fdt = self.fdt;
        let cells = self.child_cells();
        // Skip past the properties to the first child.
        let mut off = self.props_start();
        loop {
            match fdt.token(off) {
                Some(NOP) => off += 4,
                Some(PROP) => match fdt.prop_at(off) {
                    Some((_, next)) => off = next,
                    None => break,
                },
                _ => break,
            }
        }
        core::iter::from_fn(move || {
            loop {
                match fdt.token(off)? {
                    NOP => off += 4,
                    BEGIN_NODE => {
                        let child = Node { fdt, begin: off, parent_cells: cells };
                        off = fdt.skip_node(off)?;
                        return Some(child);
                    }
                    _ => return None,
                }
            }
        })
    }

    /// The `compatible` strings.
    pub fn compatible(&self) -> impl Iterator<Item = &'a str> + 'a + use<'a> {
        self.property("compatible").into_iter().flat_map(|p| p.as_str_list())
    }

    /// Returns true if `compatible` lists `s`.
    pub fn is_compatible(&self, s: &str) -> bool {
        self.compatible().any(|c| c == s)
    }

    /// `(address, size)` pairs of the `reg` property, decoded with the
    /// parent's cell counts. `size` is `None` when `#size-cells` is 0.
    pub fn reg(&self) -> impl Iterator<Item = (u64, Option<u64>)> + 'a + use<'a> {
        let Cells { address, size } = self.parent_cells;
        let value = self.property("reg").map_or(&[][..], |p| p.value);
        let stride = (address + size) as usize * 4;
        let usable = address <= 2 && size <= 2 && stride > 0;
        let chunks = if usable { value.chunks_exact(stride) } else { [].chunks_exact(1) };
        chunks.map(move |c| {
            let a = read_cells(&c[..address as usize * 4]);
            let s = (size > 0).then(|| read_cells(&c[address as usize * 4..]));
            (a, s)
        })
    }

    /// Interrupt specifiers of the `interrupts` property, one `u32` each
    /// (the common one-cell case, as on the RISC-V PLIC).
    pub fn interrupts(&self) -> impl Iterator<Item = u32> + 'a + use<'a> {
        self.property("interrupts").into_iter().flat_map(|p| p.as_u32_cells())
    }
}

impl fmt::Debug for Node<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Node({:?})", self.name())
    }
}

fn read_cells(bytes: &[u8]) -> u64 {
    bytes.as_chunks::<4>().0.iter().fold(0, |acc, c| acc << 32 | u32::from_be_bytes(*c) as u64)
}

/// Depth-first iterator over all nodes.
pub struct AllNodes<'a> {
    fdt: Fdt<'a>,
    off: usize,
    /// Child cells of each open ancestor.
    stack: [Cells; MAX_DEPTH],
    depth: usize,
}

impl<'a> Iterator for AllNodes<'a> {
    type Item = Node<'a>;

    fn next(&mut self) -> Option<Node<'a>> {
        loop {
            match self.fdt.token(self.off)? {
                BEGIN_NODE => {
                    let parent_cells = if self.depth == 0 { Cells::ROOT } else { self.stack[self.depth - 1] };
                    let node = Node { fdt: self.fdt, begin: self.off, parent_cells };
                    if self.depth == MAX_DEPTH {
                        return None;
                    }
                    self.stack[self.depth] = node.child_cells();
                    self.depth += 1;
                    self.off = node.props_start();
                    return Some(node);
                }
                END_NODE => {
                    self.depth = self.depth.checked_sub(1)?;
                    self.off += 4;
                }
                PROP => self.off = self.fdt.prop_at(self.off)?.1,
                NOP => self.off += 4,
                END => return None,
                _ => return None,
            }
        }
    }
}

/// A property: a name and raw big-endian bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Property<'a> {
    /// The property name.
    pub name: &'a str,
    /// The raw value.
    pub value: &'a [u8],
}

impl<'a> Property<'a> {
    /// The value as one big-endian `u32`.
    pub fn as_u32(&self) -> Option<u32> {
        (self.value.len() == 4).then(|| be32(self.value, 0)).flatten()
    }

    /// The value as a big-endian `u64` (one or two cells).
    pub fn as_u64(&self) -> Option<u64> {
        match self.value.len() {
            4 => be32(self.value, 0).map(u64::from),
            8 => be64(self.value, 0),
            _ => None,
        }
    }

    /// The value as a NUL-terminated string.
    pub fn as_str(&self) -> Option<&'a str> {
        cstr(self.value)
    }

    /// The value as a list of NUL-terminated strings.
    pub fn as_str_list(&self) -> impl Iterator<Item = &'a str> + 'a + use<'a> {
        self.value.split(|&b| b == 0).filter(|s| !s.is_empty()).filter_map(|s| core::str::from_utf8(s).ok())
    }

    /// The value as big-endian `u32` cells.
    pub fn as_u32_cells(&self) -> impl Iterator<Item = u32> + 'a + use<'a> {
        self.value.as_chunks::<4>().0.iter().map(|c| u32::from_be_bytes(*c))
    }
}

#[cfg(all(test, feature = "alloc"))]
mod tests;
