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
pub struct Fdt<'src> {
    data: &'src [u8],
    /// Struct block `[start, end)`.
    structs: Span,
    /// Strings block `[start, end)`.
    strings: Span,
    rsvmap: usize,
    boot_cpu: u32,
}

impl<'src> Fdt<'src> {
    /// Validates the header of `data`.
    pub fn new(data: &'src [u8]) -> Result<Self, FdtError> {
        let h = |i: usize| be32(data, i * 4).ok_or(FdtError::Truncated);
        if h(0)? != MAGIC {
            return Err(FdtError::BadMagic);
        }
        let total = h(1)? as usize;
        if total > data.len() {
            return Err(FdtError::Truncated);
        }
        let version = h(5)?;
        if h(6)? > 17 || version < 16 {
            return Err(FdtError::BadVersion);
        }
        let data = &data[..total];
        let (s_off, st_off, rsv) = (h(2)? as usize, h(3)? as usize, h(4)? as usize);
        let st_size = h(8)? as usize;
        // `size_dt_struct` only exists from version 17 (in a version 16
        // header that word is already the reservation block or padding).
        // Without it, the struct block runs to the strings block if that
        // follows it, else to the end; parsing stops at the END token anyway.
        let s_end = if version >= 17 {
            s_off.checked_add(h(9)? as usize).ok_or(FdtError::Truncated)?
        } else if st_off >= s_off {
            st_off
        } else {
            total
        };
        let structs = Span { start: s_off, end: s_end };
        let strings = Span { start: st_off, end: st_off.checked_add(st_size).ok_or(FdtError::Truncated)? };
        if structs.start > structs.end || structs.end > total || strings.end > total || rsv > total {
            return Err(FdtError::Truncated);
        }
        Ok(Self { data, structs, strings, rsvmap: rsv, boot_cpu: h(7)? })
    }

    /// Parses the blob at `ptr`, reading its length from the header.
    ///
    /// # Safety
    /// `ptr` must point to a readable device tree that stays valid and
    /// unmodified for `'src`.
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
    pub fn root(&self) -> Node<'src> {
        Node { fdt: *self, begin: self.structs.start + self.skip_nops(0), parent_cells: Cells::ROOT }
    }

    /// Finds a node by absolute path. A path component without a unit
    /// address (`memory`) matches a node with one (`memory@80000000`).
    pub fn find_node(&self, path: &str) -> Option<Node<'src>> {
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
    pub fn all_nodes(&self) -> AllNodes<'src> {
        AllNodes { fdt: *self, off: self.root().begin, stack: [Cells::ROOT; MAX_DEPTH], depth: 0 }
    }

    /// The first node compatible with any of `compatible`.
    pub fn find_compatible(&self, compatible: &[&str]) -> Option<Node<'src>> {
        self.all_nodes().find(|n| n.compatible().any(|c| compatible.contains(&c)))
    }

    /// The `/chosen` node.
    pub fn chosen(&self) -> Option<Node<'src>> {
        self.find_node("/chosen")
    }

    /// The `bootargs` property of `/chosen`.
    pub fn bootargs(&self) -> Option<&'src str> {
        self.chosen()?.property("bootargs")?.as_str()
    }

    /// `(address, size)` of every RAM range in `device_type = "memory"` nodes.
    pub fn memory(&self) -> impl Iterator<Item = (u64, u64)> + 'src + use<'src> {
        self.all_nodes()
            .filter(|n| n.property("device_type").and_then(|p| p.as_str()) == Some("memory"))
            .flat_map(|n| n.reg().map(|(a, s)| (a, s.unwrap_or(0))))
    }

    /// Entries of the memory reservation block.
    pub fn reservations(&self) -> impl Iterator<Item = (u64, u64)> + 'src + use<'src> {
        let data = self.data;
        let base = self.rsvmap;
        (0usize..)
            .map(move |i| {
                let off = base.checked_add(i.checked_mul(16)?)?;
                Some((be64(data, off)?, be64(data, off.checked_add(8)?)?))
            })
            .map_while(|e| e.filter(|&(a, s)| a != 0 || s != 0))
    }

    /// `[start, end)` of the initial ramdisk, from `/chosen`'s
    /// `linux,initrd-start` and `linux,initrd-end` (one or two cells each).
    pub fn initrd(&self) -> Option<(u64, u64)> {
        let chosen = self.chosen()?;
        let start = chosen.property("linux,initrd-start")?.as_u64()?;
        let end = chosen.property("linux,initrd-end")?.as_u64()?;
        (start < end).then_some((start, end))
    }

    /// Adds RAM, reserved ranges (the reservation block and the static
    /// `/reserved-memory` children, those with a `reg`), the initrd and, if
    /// given, the blob itself to `map`.
    ///
    /// RAM ranges whose end overflows are malformed and skipped; reserved
    /// ranges that overflow are clamped to the top of the address space. If
    /// the map runs out of room, it gives up detail or RAM as
    /// [`MemoryMap::add_lossy`] describes; the result is the number of usable
    /// bytes dropped, worth logging if not zero.
    ///
    /// Dynamic `/reserved-memory` children (a `size` but no `reg`) ask the OS
    /// to allocate a pool, for drivers that want one; firmware uses no memory
    /// for them, so they need no entry here.
    pub fn fill_memory_map<const N: usize>(
        &self,
        map: &mut MemoryMap<N>,
        blob_at: Option<PhysAddr>,
    ) -> Result<u64, osmium_mm::map::MapFull> {
        let mut lost = 0;
        let mut add = |map: &mut MemoryMap<N>, a: u64, s: u64, kind| -> Result<(), osmium_mm::map::MapFull> {
            lost += map.add_lossy(PhysAddr::new(a), PhysAddr::new(a.saturating_add(s)), kind)?;
            Ok(())
        };
        for (a, s) in self.memory() {
            if a.checked_add(s).is_some() {
                add(map, a, s, RegionKind::Usable)?;
            }
        }
        for (a, s) in self.reservations() {
            add(map, a, s, RegionKind::Reserved)?;
        }
        if let Some(rm) = self.find_node("/reserved-memory") {
            for (a, s) in rm.children().flat_map(|c| c.reg()) {
                add(map, a, s.unwrap_or(0), RegionKind::Reserved)?;
            }
        }
        if let Some((start, end)) = self.initrd() {
            add(map, start, end - start, RegionKind::Bootloader)?;
        }
        if let Some(at) = blob_at {
            add(map, at.0, self.total_size() as u64, RegionKind::Bootloader)?;
        }
        Ok(lost)
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

    fn string(&self, nameoff: usize) -> Option<&'src str> {
        cstr(self.data.get(self.strings.start + nameoff..self.strings.end)?)
    }

    /// Parses the property at `off`; returns it and the offset after it.
    fn prop_at(&self, off: usize) -> Option<(Property<'src>, usize)> {
        let len = be32(self.data, off.checked_add(4)?)? as usize;
        let name = self.string(be32(self.data, off.checked_add(8)?)? as usize)?;
        let start = off.checked_add(12)?;
        let end = start.checked_add(len)?;
        let value = self.data.get(start..end)?;
        // `end` is within the blob, so rounding it up cannot overflow.
        Some((Property { name, value }, align4(end)))
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
pub struct Node<'src> {
    fdt: Fdt<'src>,
    /// Offset of the BEGIN_NODE token.
    begin: usize,
    parent_cells: Cells,
}

impl<'src> Node<'src> {
    /// The node's name, including any unit address (`uart@10000000`). The
    /// root's name is empty.
    pub fn name(&self) -> &'src str {
        self.fdt.data.get(self.begin + 4..).and_then(cstr).unwrap_or("")
    }

    fn props_start(&self) -> usize {
        align4(self.begin + 4 + self.name().len() + 1)
    }

    /// The node's properties.
    pub fn properties(&self) -> impl Iterator<Item = Property<'src>> + 'src + use<'src> {
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
    pub fn property(&self, name: &str) -> Option<Property<'src>> {
        self.properties().find(|p| p.name == name)
    }

    /// Cells this node defines for its children's `reg`.
    pub fn child_cells(&self) -> Cells {
        let get = |n: &str, d| self.property(n).and_then(|p| p.as_u32()).unwrap_or(d);
        Cells { address: get("#address-cells", 2), size: get("#size-cells", 1) }
    }

    /// The node's direct children.
    pub fn children(&self) -> impl Iterator<Item = Node<'src>> + 'src + use<'src> {
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
    pub fn compatible(&self) -> impl Iterator<Item = &'src str> + 'src + use<'src> {
        self.property("compatible").into_iter().flat_map(|p| p.as_str_list())
    }

    /// Returns true if `compatible` lists `s`.
    pub fn is_compatible(&self, s: &str) -> bool {
        self.compatible().any(|c| c == s)
    }

    /// `(address, size)` pairs of the `reg` property, decoded with the
    /// parent's cell counts. `size` is `None` when `#size-cells` is 0.
    pub fn reg(&self) -> impl Iterator<Item = (u64, Option<u64>)> + 'src + use<'src> {
        let Cells { address, size } = self.parent_cells;
        let value = self.property("reg").map_or(&[][..], |p| p.value);
        // The cell counts come from the blob: validate them before doing arithmetic on them.
        let usable = address <= 2 && size <= 2 && address + size > 0;
        let stride = if usable { (address + size) as usize * 4 } else { 1 };
        let chunks = if usable { value.chunks_exact(stride) } else { [].chunks_exact(1) };
        chunks.map(move |c| {
            let a = read_cells(&c[..address as usize * 4]);
            let s = (size > 0).then(|| read_cells(&c[address as usize * 4..]));
            (a, s)
        })
    }

    /// Interrupt specifiers of the `interrupts` property, one `u32` each
    /// (the common one-cell case, as on the RISC-V PLIC).
    pub fn interrupts(&self) -> impl Iterator<Item = u32> + 'src + use<'src> {
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
pub struct AllNodes<'src> {
    fdt: Fdt<'src>,
    off: usize,
    /// Child cells of each open ancestor.
    stack: [Cells; MAX_DEPTH],
    depth: usize,
}

impl<'src> Iterator for AllNodes<'src> {
    type Item = Node<'src>;

    fn next(&mut self) -> Option<Node<'src>> {
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
pub struct Property<'src> {
    /// The property name.
    pub name: &'src str,
    /// The raw value.
    pub value: &'src [u8],
}

impl<'src> Property<'src> {
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
    pub fn as_str(&self) -> Option<&'src str> {
        cstr(self.value)
    }

    /// The value as a list of NUL-terminated strings.
    pub fn as_str_list(&self) -> impl Iterator<Item = &'src str> + 'src + use<'src> {
        self.value.split(|&b| b == 0).filter(|s| !s.is_empty()).filter_map(|s| core::str::from_utf8(s).ok())
    }

    /// The value as big-endian `u32` cells.
    pub fn as_u32_cells(&self) -> impl Iterator<Item = u32> + 'src + use<'src> {
        self.value.as_chunks::<4>().0.iter().map(|c| u32::from_be_bytes(*c))
    }
}

#[cfg(all(test, feature = "alloc"))]
mod tests;
