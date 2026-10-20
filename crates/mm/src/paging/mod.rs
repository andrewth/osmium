//! Generic multi-level page tables.
//!
//! [`PageTable`] implements the walk, map, unmap, translate and protect logic
//! once. A [`PageTableFormat`] supplies the entry encoding for one
//! architecture or translation stage; see [`formats`].

pub mod formats;

use core::fmt;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::addr::{PAGE_SIZE, PhysAddr, VirtAddr};
use crate::frame::PhysMapper;

/// Entries per table on every supported format (4 KiB granule).
pub const ENTRIES: usize = 512;

/// Architecture-neutral mapping permissions and attributes.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct MapFlags(u32);

impl MapFlags {
    /// No access.
    pub const NONE: Self = Self(0);
    /// Readable.
    pub const READ: Self = Self(1 << 0);
    /// Writable.
    pub const WRITE: Self = Self(1 << 1);
    /// Executable.
    pub const EXEC: Self = Self(1 << 2);
    /// Accessible from user mode (EL0, U-mode, CPL 3).
    pub const USER: Self = Self(1 << 3);
    /// Shared by all address spaces; not flushed on address-space switch.
    pub const GLOBAL: Self = Self(1 << 4);
    /// Device memory: uncached, no speculation, no execution.
    pub const DEVICE: Self = Self(1 << 5);

    /// Read and write.
    pub const RW: Self = Self(Self::READ.0 | Self::WRITE.0);
    /// Read and execute.
    pub const RX: Self = Self(Self::READ.0 | Self::EXEC.0);

    /// Returns the raw bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Returns true if all flags in `other` are set.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Returns `self` with `other` also set.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns `self` with `other` cleared.
    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }
}

impl core::ops::BitOr for MapFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

impl fmt::Debug for MapFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names = ["R", "W", "X", "U", "G", "DEV"];
        let mut first = true;
        for (i, n) in names.iter().enumerate() {
            if self.0 & (1 << i) != 0 {
                if !first {
                    f.write_str("|")?;
                }
                f.write_str(n)?;
                first = false;
            }
        }
        if first {
            f.write_str("NONE")?;
        }
        Ok(())
    }
}

/// Mapping granularity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PageSize {
    /// 4 KiB, a level-0 leaf.
    Size4K,
    /// 2 MiB, a level-1 leaf.
    Size2M,
    /// 1 GiB, a level-2 leaf.
    Size1G,
}

impl PageSize {
    /// Size in bytes.
    pub const fn bytes(self) -> u64 {
        1 << (12 + 9 * self.level())
    }

    /// Table level at which the leaf lives (0 = last level).
    pub const fn level(self) -> usize {
        match self {
            Self::Size4K => 0,
            Self::Size2M => 1,
            Self::Size1G => 2,
        }
    }

    const fn from_level(level: usize) -> Self {
        match level {
            0 => Self::Size4K,
            1 => Self::Size2M,
            _ => Self::Size1G,
        }
    }
}

/// Entry encoding for one translation format.
///
/// Levels count from 0 (the last level, 4 KiB leaves) up to `LEVELS - 1`
/// (the root). Every format uses 512 eight-byte entries per table.
pub trait PageTableFormat {
    /// Number of levels.
    const LEVELS: usize;
    /// Number of significant input-address bits.
    const VA_BITS: u32;
    /// Whether input addresses are sign-extended (CPU stage 1) or must be
    /// below `2^VA_BITS` (guest-physical stage 2).
    const SIGN_EXTEND: bool;
    /// Highest level at which a leaf (huge page) is allowed.
    const MAX_LEAF_LEVEL: usize;

    /// Encodes an entry pointing at the next-level table at `pa`.
    fn table(pa: PhysAddr) -> u64;
    /// Encodes a leaf mapping `pa` at `level`.
    fn leaf(pa: PhysAddr, flags: MapFlags, level: usize) -> u64;
    /// Returns true if the entry is valid (present).
    fn is_valid(pte: u64) -> bool;
    /// Returns true if a valid entry at `level` is a leaf.
    fn is_leaf(pte: u64, level: usize) -> bool;
    /// Returns the output address of a valid entry.
    fn addr(pte: u64, level: usize) -> PhysAddr;
    /// Decodes the flags of a leaf.
    fn flags(pte: u64, level: usize) -> MapFlags;
}

/// Supplies and reclaims frames for page-table pages.
///
/// # Safety
/// `alloc_table` must return an exclusively owned, page-aligned frame, and
/// `phys_to_virt` must return a pointer valid for reads and writes of a full
/// page for every frame the table uses.
pub unsafe trait TableAlloc: PhysMapper {
    /// Allocates one frame. It need not be zeroed.
    fn alloc_table(&self) -> Option<PhysAddr>;
    /// Frees a frame from `alloc_table`.
    ///
    /// # Safety
    /// The frame must no longer be referenced by any table.
    unsafe fn free_table(&self, pa: PhysAddr);
}

// SAFETY: forwards to `A`.
unsafe impl<A: TableAlloc + ?Sized> TableAlloc for &A {
    fn alloc_table(&self) -> Option<PhysAddr> {
        (**self).alloc_table()
    }
    unsafe fn free_table(&self, pa: PhysAddr) {
        // SAFETY: forwarded contract.
        unsafe { (**self).free_table(pa) }
    }
}

/// Why a mapping could not be made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapError {
    /// An address is not aligned to the page size.
    Misaligned,
    /// The virtual address is outside the format's range.
    InvalidAddress,
    /// The format does not support this page size.
    UnsupportedSize,
    /// The page is already mapped.
    AlreadyMapped,
    /// A larger leaf already covers the address.
    HugePageConflict,
    /// No frame for an intermediate table.
    OutOfMemory,
}

/// Why an existing mapping could not be changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnmapError {
    /// Nothing is mapped at the address.
    NotMapped,
    /// The virtual address is outside the format's range.
    InvalidAddress,
}

/// A TLB invalidation that the caller must perform or explicitly skip.
#[must_use = "flush the TLB, or call `ignore` if this table is not active"]
pub struct Flush(VirtAddr);

impl Flush {
    /// Invalidates the page on the current CPU.
    pub fn flush(self) {
        osmium_arch::mmu::flush_page(self.0.as_usize());
    }

    /// Skips the invalidation: the table is inactive, or the caller will
    /// flush in bulk (or shoot down other CPUs) itself.
    pub fn ignore(self) {}

    /// The page that needs invalidating.
    pub fn addr(&self) -> VirtAddr {
        self.0
    }
}

/// The result of a successful translation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Translation {
    /// Physical address of the queried byte.
    pub pa: PhysAddr,
    /// Leaf flags.
    pub flags: MapFlags,
    /// Size of the leaf that maps it.
    pub size: PageSize,
}

/// A page-table tree in format `F`, whose table pages come from `A`.
///
/// The tree owns its intermediate tables and frees them on drop. It does not
/// own the frames that leaves point at.
pub struct PageTable<F: PageTableFormat, A: TableAlloc> {
    root: PhysAddr,
    alloc: A,
    /// Root entries borrowed from another table (bit `i` = root index `i`):
    /// never freed or modified through this table.
    shared: [u64; ENTRIES / 64],
    _format: PhantomData<F>,
}

impl<F: PageTableFormat, A: TableAlloc> PageTable<F, A> {
    /// Allocates an empty root table.
    pub fn new(alloc: A) -> Result<Self, MapError> {
        let root = Self::new_table(&alloc)?;
        Ok(Self { root, alloc, shared: [0; ENTRIES / 64], _format: PhantomData })
    }

    /// Physical address of the root table, for CR3, TTBR, satp, EPTP or VTTBR.
    pub fn root(&self) -> PhysAddr {
        self.root
    }

    /// The table-frame allocator.
    pub fn allocator(&self) -> &A {
        &self.alloc
    }

    /// Makes this table use `kernel`'s root entries `indices` (and so all
    /// the subtables below them): the usual way to give each process its own
    /// table with the kernel mapped in every one. Later changes inside those
    /// subtables, made through `kernel`, are seen here too; root entries the
    /// kernel creates afterwards are not, so populate them first.
    ///
    /// Shared entries are never freed by this table, and `map`, `unmap`,
    /// `protect` and `split` refuse addresses under them
    /// ([`MapError::InvalidAddress`] / [`UnmapError::InvalidAddress`]).
    ///
    /// # Safety
    /// `kernel` (its subtables, at least) must outlive this table.
    pub unsafe fn share_root_entries<B: TableAlloc>(&mut self, kernel: &PageTable<F, B>, indices: core::ops::Range<usize>) {
        assert!(indices.end <= ENTRIES, "root index out of range");
        let top = F::LEVELS - 1;
        for i in indices {
            let va = VirtAddr::new((i as u64) << (12 + 9 * top));
            let pte = kernel.entry(kernel.root, va, top).load(Ordering::Acquire);
            self.entry(self.root, va, top).store(pte, Ordering::Release);
            self.shared[i / 64] |= 1 << (i % 64);
        }
    }

    fn is_shared(&self, va: VirtAddr) -> bool {
        let i = (va.0 >> (12 + 9 * (F::LEVELS - 1))) as usize % ENTRIES;
        self.shared[i / 64] & (1 << (i % 64)) != 0
    }

    /// Maps the page at `va` to `pa`.
    pub fn map(&mut self, va: VirtAddr, pa: PhysAddr, size: PageSize, flags: MapFlags) -> Result<Flush, MapError> {
        if self.is_shared(va) {
            return Err(MapError::InvalidAddress);
        }
        if size.level() > F::MAX_LEAF_LEVEL || size.level() >= F::LEVELS {
            return Err(MapError::UnsupportedSize);
        }
        if !va.is_aligned(size.bytes()) || !pa.is_aligned(size.bytes()) {
            return Err(MapError::Misaligned);
        }
        self.check(va).map_err(|_| MapError::InvalidAddress)?;
        let mut table = self.root;
        for level in (size.level() + 1..F::LEVELS).rev() {
            let e = self.entry(table, va, level);
            let pte = e.load(Ordering::Acquire);
            table = if !F::is_valid(pte) {
                let next = Self::new_table(&self.alloc)?;
                e.store(F::table(next), Ordering::Release);
                next
            } else if F::is_leaf(pte, level) {
                return Err(MapError::HugePageConflict);
            } else {
                F::addr(pte, level)
            };
        }
        let e = self.entry(table, va, size.level());
        if F::is_valid(e.load(Ordering::Acquire)) {
            return Err(MapError::AlreadyMapped);
        }
        e.store(F::leaf(pa, flags, size.level()), Ordering::Release);
        Ok(Flush(va))
    }

    /// Maps `[va, va + len)` to `[pa, pa + len)` using the largest pages that
    /// alignment and length allow. Returns without flushing: intended for
    /// building tables before activation. On error, already-made mappings
    /// remain.
    pub fn map_range(&mut self, va: VirtAddr, pa: PhysAddr, len: u64, flags: MapFlags) -> Result<(), MapError> {
        if !va.is_aligned(PAGE_SIZE as u64) || !pa.is_aligned(PAGE_SIZE as u64) || !len.is_multiple_of(PAGE_SIZE as u64) {
            return Err(MapError::Misaligned);
        }
        let mut done = 0;
        while done < len {
            let (v, p) = (va + done, pa + done);
            let size = [PageSize::Size1G, PageSize::Size2M, PageSize::Size4K]
                .into_iter()
                .find(|s| {
                    s.level() <= F::MAX_LEAF_LEVEL
                        && s.level() < F::LEVELS
                        && v.is_aligned(s.bytes())
                        && p.is_aligned(s.bytes())
                        && len - done >= s.bytes()
                })
                .unwrap_or(PageSize::Size4K);
            self.map(v, p, size, flags)?.ignore();
            done += size.bytes();
        }
        Ok(())
    }

    /// Removes the leaf that maps `va` and returns what it mapped.
    pub fn unmap(&mut self, va: VirtAddr) -> Result<(Translation, Flush), UnmapError> {
        if self.is_shared(va) {
            return Err(UnmapError::InvalidAddress);
        }
        let (e, level) = self.find_leaf(va)?;
        let pte = e.swap(0, Ordering::AcqRel);
        let size = PageSize::from_level(level);
        let t = Translation { pa: F::addr(pte, level), flags: F::flags(pte, level), size };
        Ok((t, Flush(va.align_down(size.bytes()))))
    }

    /// Replaces the huge-page leaf that maps `va` with a table of 512
    /// next-smaller leaves covering the same range with the same flags, so
    /// that part of it can be unmapped or reprotected. Returns the size of
    /// the leaf now mapping `va`; already-4 KiB mappings are left alone.
    ///
    /// The translation does not change, so no TLB flush is required, but
    /// the caller should flush before relying on the finer granularity.
    pub fn split(&mut self, va: VirtAddr) -> Result<PageSize, MapError> {
        if self.is_shared(va) {
            return Err(MapError::InvalidAddress);
        }
        let (e, level) = self.find_leaf(va).map_err(|_| MapError::InvalidAddress)?;
        if level == 0 {
            return Ok(PageSize::Size4K);
        }
        let pte = e.load(Ordering::Acquire);
        let (base, flags) = (F::addr(pte, level), F::flags(pte, level));
        let table = Self::new_table(&self.alloc)?;
        let child = PageSize::from_level(level - 1);
        for i in 0..ENTRIES as u64 {
            let cva = VirtAddr::new(i << (12 + 9 * (level - 1)));
            self.entry(table, cva, level - 1).store(F::leaf(base + i * child.bytes(), flags, level - 1), Ordering::Relaxed);
        }
        // Re-find the entry: `entry` borrows `self`.
        let (e, _) = self.find_leaf(va).map_err(|_| MapError::InvalidAddress)?;
        e.store(F::table(table), Ordering::Release);
        Ok(child)
    }

    /// Unmaps the 4 KiB page at `va`, splitting huge pages around it first.
    pub fn unmap_4k(&mut self, va: VirtAddr) -> Result<(Translation, Flush), UnmapError> {
        loop {
            match self.translate(va).ok_or(UnmapError::NotMapped)?.size {
                PageSize::Size4K => return self.unmap(va.align_down(PAGE_SIZE as u64)),
                _ => {
                    self.split(va).map_err(|_| UnmapError::NotMapped)?;
                }
            }
        }
    }

    /// Changes the flags of the leaf that maps `va`.
    pub fn protect(&mut self, va: VirtAddr, flags: MapFlags) -> Result<Flush, UnmapError> {
        if self.is_shared(va) {
            return Err(UnmapError::InvalidAddress);
        }
        let (e, level) = self.find_leaf(va)?;
        let pte = e.load(Ordering::Acquire);
        e.store(F::leaf(F::addr(pte, level), flags, level), Ordering::Release);
        Ok(Flush(va.align_down(PageSize::from_level(level).bytes())))
    }

    /// Looks up the physical address and flags for `va`.
    pub fn translate(&self, va: VirtAddr) -> Option<Translation> {
        let (e, level) = self.find_leaf(va).ok()?;
        let pte = e.load(Ordering::Acquire);
        let size = PageSize::from_level(level);
        let offset = va.0 & (size.bytes() - 1);
        Some(Translation { pa: F::addr(pte, level) + offset, flags: F::flags(pte, level), size })
    }

    fn check(&self, va: VirtAddr) -> Result<(), UnmapError> {
        let ok = if F::SIGN_EXTEND { va.is_canonical(F::VA_BITS) } else { va.0 >> F::VA_BITS == 0 };
        if ok { Ok(()) } else { Err(UnmapError::InvalidAddress) }
    }

    fn find_leaf(&self, va: VirtAddr) -> Result<(&AtomicU64, usize), UnmapError> {
        self.check(va)?;
        let mut table = self.root;
        for level in (0..F::LEVELS).rev() {
            let e = self.entry(table, va, level);
            let pte = e.load(Ordering::Acquire);
            if !F::is_valid(pte) {
                return Err(UnmapError::NotMapped);
            }
            if F::is_leaf(pte, level) {
                return Ok((e, level));
            }
            table = F::addr(pte, level);
        }
        unreachable!("level 0 entries are always leaves")
    }

    fn entry(&self, table: PhysAddr, va: VirtAddr, level: usize) -> &AtomicU64 {
        let index = (va.0 >> (12 + 9 * level)) as usize % ENTRIES;
        let base = self.alloc.phys_to_virt(table).cast::<AtomicU64>();
        // SAFETY: `table` is a table frame of this tree, mapped by the
        // allocator's contract; the index is in bounds. Entries are accessed
        // atomically because the hardware walker reads them concurrently.
        unsafe { &*base.add(index) }
    }

    fn new_table(alloc: &A) -> Result<PhysAddr, MapError> {
        let pa = alloc.alloc_table().ok_or(MapError::OutOfMemory)?;
        // SAFETY: a fresh, exclusively owned frame.
        unsafe { alloc.phys_to_virt(pa).write_bytes(0, PAGE_SIZE) };
        Ok(pa)
    }

    fn free_subtree(&self, table: PhysAddr, level: usize) {
        if level > 0 {
            for i in 0..ENTRIES {
                let va = VirtAddr::new((i as u64) << (12 + 9 * level));
                if level == F::LEVELS - 1 && self.is_shared(va) {
                    continue;
                }
                let pte = self.entry(table, va, level).load(Ordering::Relaxed);
                if F::is_valid(pte) && !F::is_leaf(pte, level) {
                    self.free_subtree(F::addr(pte, level), level - 1);
                }
            }
        }
        // SAFETY: called once per table, during drop, when nothing else
        // references the tree.
        unsafe { self.alloc.free_table(table) };
    }
}

impl<F: PageTableFormat, A: TableAlloc> Drop for PageTable<F, A> {
    fn drop(&mut self) {
        self.free_subtree(self.root, F::LEVELS - 1);
    }
}

#[cfg(test)]
mod tests;
