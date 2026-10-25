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
use crate::frame::{OwnedFrame, PhysMapper};

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
            // `find_leaf` filters larger foreign leaves, so this is 2 in practice.
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
    /// Number of contiguous pages in the root table, a power of two. Each
    /// extra page widens the root index by one bit (RISC-V G-stage roots
    /// are 4 pages, 16 KiB aligned).
    const ROOT_PAGES: usize = 1;
    /// Whether replacing a valid leaf with a table needs break-before-make:
    /// invalidate the entry and the TLB before writing the new one.
    /// AArch64 requires it (without FEAT_BBM, a TLB holding both the old
    /// block and the new pages may raise a TLB conflict abort). x86 and
    /// RISC-V allow the replacement in place, followed by a TLB flush.
    const BREAK_BEFORE_MAKE: bool = false;

    /// Encodes an entry pointing at the next-level table at `pa`.
    fn table(pa: PhysAddr) -> u64;
    /// Encodes an entry at `level` pointing at the table at `pa`, one level
    /// down. Formats whose table entries record the child's level (AMD-Vi's
    /// `NextLevel`) override this; the default ignores `level`.
    fn table_at(pa: PhysAddr, _level: usize) -> u64 {
        Self::table(pa)
    }
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

    /// Allocates a root table of `pages` contiguous frames, aligned to its
    /// size. It need not be zeroed. The default supports only one page.
    fn alloc_root(&self, pages: usize) -> Option<PhysAddr> {
        if pages == 1 { self.alloc_table() } else { None }
    }

    /// Frees a root from `alloc_root`. The default frees each page with
    /// `free_table`; allocators that override `alloc_root` may override this.
    ///
    /// # Safety
    /// As for `free_table`.
    unsafe fn free_root(&self, pa: PhysAddr, pages: usize) {
        for i in 0..pages as u64 {
            // SAFETY: forwarded contract.
            unsafe { self.free_table(pa + i * PAGE_SIZE as u64) }
        }
    }

    /// Takes the first reference to `pa`, a user frame that `alloc_table`
    /// just returned. Returns false if this allocator does not count
    /// references, in which case its frames cannot be shared.
    fn claim_frame(&self, _pa: PhysAddr) -> bool {
        false
    }

    /// Adds a reference to a frame that has one. Returns false if this
    /// allocator does not count references, or the frame has none.
    fn retain_frame(&self, _pa: PhysAddr) -> bool {
        false
    }

    /// Drops a reference taken by [`claim_frame`](TableAlloc::claim_frame) or
    /// [`retain_frame`](TableAlloc::retain_frame), freeing the frame with the
    /// last one. The default frees it outright, which is right for an
    /// allocator that never shares frames.
    ///
    /// # Safety
    /// The caller gives up a reference it holds to `pa`, and no table may
    /// map the frame through that reference any more.
    unsafe fn release_frame(&self, pa: PhysAddr) {
        // SAFETY: forwarded contract: the last reference is gone.
        unsafe { self.free_table(pa) }
    }

    /// The number of references to the frame at `pa`, if this allocator
    /// counts them.
    fn frame_refs(&self, _pa: PhysAddr) -> Option<u32> {
        None
    }
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
    fn alloc_root(&self, pages: usize) -> Option<PhysAddr> {
        (**self).alloc_root(pages)
    }
    unsafe fn free_root(&self, pa: PhysAddr, pages: usize) {
        // SAFETY: forwarded contract.
        unsafe { (**self).free_root(pa, pages) }
    }
    fn claim_frame(&self, pa: PhysAddr) -> bool {
        (**self).claim_frame(pa)
    }
    fn retain_frame(&self, pa: PhysAddr) -> bool {
        (**self).retain_frame(pa)
    }
    unsafe fn release_frame(&self, pa: PhysAddr) {
        // SAFETY: forwarded contract.
        unsafe { (**self).release_frame(pa) }
    }
    fn frame_refs(&self, pa: PhysAddr) -> Option<u32> {
        (**self).frame_refs(pa)
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
    /// The flags grant no access (none of `READ`, `WRITE`, `EXEC`). Not every
    /// format can express such a leaf (on RISC-V it would read as a table
    /// pointer), so leave the page unmapped instead.
    NoAccess,
    /// The table owns its leaves: map them with [`PageTable::map_owned`].
    OwnedLeaves,
    /// The table does not own its leaves: map them with [`PageTable::map`].
    UnownedLeaves,
    /// The size is not 4 KiB, which is all an owning table maps.
    OwnedSize,
}

/// Why an existing mapping could not be changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnmapError {
    /// Nothing is mapped at the address.
    NotMapped,
    /// The virtual address is outside the format's range.
    InvalidAddress,
    /// The new flags grant no access; see [`MapError::NoAccess`].
    NoAccess,
    /// The table owns its leaves: use [`PageTable::unmap_owned`] or
    /// [`PageTable::replace_owned`].
    OwnedLeaves,
    /// The table does not own its leaves: use [`PageTable::unmap`].
    UnownedLeaves,
}

/// Whether a leaf with `flags` permits any access.
fn grants_access(flags: MapFlags) -> bool {
    flags.contains(MapFlags::READ) || flags.contains(MapFlags::WRITE) || flags.contains(MapFlags::EXEC)
}

/// A TLB invalidation that the caller must perform or explicitly skip.
#[must_use = "flush the TLB, or call `ignore` if this table is not active"]
#[derive(Debug)]
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
/// The tree owns its intermediate tables and frees them on drop. What its
/// leaves point at is decided by how the tree was made:
///
/// - [`PageTable::new`] makes a table that does not own its leaves. It maps
///   frames it is handed with [`PageTable::map`], and never frees them. This
///   is right for kernel, device and stage-2 tables.
/// - [`PageTable::new_owned`] makes a table that owns one reference to each
///   4 KiB frame it maps. It maps them with [`PageTable::map_owned`], gives
///   them back with [`PageTable::unmap_owned`], and releases the rest on drop.
pub struct PageTable<F: PageTableFormat, A: TableAlloc> {
    root: PhysAddr,
    alloc: A,
    /// Root entries borrowed from another table (bit `i` = root index `i`):
    /// never freed or modified through this table.
    shared: [u64; ENTRIES / 64],
    /// Whether the leaves are owned references (see the type's documentation).
    owned: bool,
    _format: PhantomData<F>,
}

impl<F: PageTableFormat, A: TableAlloc> PageTable<F, A> {
    /// Allocates an empty root table whose leaves are not owned.
    pub fn new(alloc: A) -> Result<Self, MapError> {
        Self::create(alloc, false)
    }

    /// Allocates an empty root table whose leaves are owned references.
    pub fn new_owned(alloc: A) -> Result<Self, MapError> {
        Self::create(alloc, true)
    }

    fn create(alloc: A, owned: bool) -> Result<Self, MapError> {
        let root = alloc.alloc_root(F::ROOT_PAGES).ok_or(MapError::OutOfMemory)?;
        // SAFETY: a fresh, exclusively owned block of `ROOT_PAGES` frames.
        unsafe { alloc.phys_to_virt(root).write_bytes(0, PAGE_SIZE * F::ROOT_PAGES) };
        Ok(Self { root, alloc, shared: [0; ENTRIES / 64], owned, _format: PhantomData })
    }

    /// Whether the leaves are owned references (see [`PageTable::new_owned`]).
    pub fn owns_leaves(&self) -> bool {
        self.owned
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
    ///
    /// Does nothing if the format has a multi-page root (G-stage tables);
    /// indices past the root table are ignored.
    pub unsafe fn share_root_entries<B: TableAlloc>(
        &mut self,
        kernel: &PageTable<F, B>,
        indices: core::ops::Range<usize>,
    ) {
        if F::ROOT_PAGES != 1 {
            return;
        }
        let top = F::LEVELS - 1;
        for i in indices.start..indices.end.min(ENTRIES) {
            let va = VirtAddr::new((i as u64) << (12 + 9 * top));
            let pte = kernel.entry(kernel.root, va, top).load(Ordering::Acquire);
            self.entry(self.root, va, top).store(pte, Ordering::Release);
            if let Some(w) = self.shared.get_mut(i / 64) {
                *w |= 1 << (i % 64);
            }
        }
    }

    fn is_shared(&self, va: VirtAddr) -> bool {
        let i = (va.0 >> (12 + 9 * (F::LEVELS - 1))) as usize % ENTRIES;
        self.shared.get(i / 64).is_some_and(|w| w & (1 << (i % 64)) != 0)
    }

    /// Maps the page at `va` to `pa`, which the table does not own. Refused
    /// by a table that owns its leaves.
    pub fn map(&mut self, va: VirtAddr, pa: PhysAddr, size: PageSize, flags: MapFlags) -> Result<Flush, MapError> {
        if self.owned {
            return Err(MapError::OwnedLeaves);
        }
        self.map_pa(va, pa, size, flags)
    }

    /// Maps the 4 KiB page at `va` to the frame `frame`, whose reference the
    /// table takes over. On failure the frame is handed back, and nothing is
    /// mapped. Refused by a table that does not own its leaves.
    pub fn map_owned(
        &mut self,
        va: VirtAddr,
        frame: OwnedFrame<A>,
        flags: MapFlags,
    ) -> Result<Flush, (MapError, OwnedFrame<A>)> {
        if !self.owned {
            return Err((MapError::UnownedLeaves, frame));
        }
        match self.map_pa(va, frame.pa(), PageSize::Size4K, flags) {
            Ok(flush) => {
                frame.leak();
                Ok(flush)
            }
            Err(e) => Err((e, frame)),
        }
    }

    fn map_pa(&mut self, va: VirtAddr, pa: PhysAddr, size: PageSize, flags: MapFlags) -> Result<Flush, MapError> {
        if self.is_shared(va) {
            return Err(MapError::InvalidAddress);
        }
        if !grants_access(flags) {
            return Err(MapError::NoAccess);
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
                e.store(F::table_at(next, level), Ordering::Release);
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
        if !va.is_aligned(PAGE_SIZE as u64) || !pa.is_aligned(PAGE_SIZE as u64) || !len.is_multiple_of(PAGE_SIZE as u64)
        {
            return Err(MapError::Misaligned);
        }
        // A range that runs past the top of the address space would wrap and map low addresses.
        if va.0.checked_add(len).is_none() || pa.0.checked_add(len).is_none() {
            return Err(MapError::InvalidAddress);
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

    /// Removes the leaf that maps `va` and returns what it mapped. Refused by
    /// a table that owns its leaves.
    pub fn unmap(&mut self, va: VirtAddr) -> Result<(Translation, Flush), UnmapError> {
        if self.owned {
            return Err(UnmapError::OwnedLeaves);
        }
        self.unmap_pa(va)
    }

    /// Removes the 4 KiB leaf that maps `va` and returns its frame's
    /// reference. Refused by a table that does not own its leaves.
    pub fn unmap_owned(&mut self, va: VirtAddr) -> Result<(OwnedFrame<A>, Flush), UnmapError>
    where
        A: Clone,
    {
        if !self.owned {
            return Err(UnmapError::UnownedLeaves);
        }
        // Checked before anything is cleared: a larger leaf is not one frame.
        if self.find_leaf(va)?.1 != 0 {
            return Err(UnmapError::NotMapped);
        }
        let (t, flush) = self.unmap_pa(va)?;
        Ok((OwnedFrame::adopt(self.alloc.clone(), t.pa), flush))
    }

    /// Replaces the 4 KiB leaf that maps `va` with `frame`, and returns the
    /// reference the old leaf held. Nothing needs allocating, so once `va`
    /// is mapped this cannot run out of memory. On failure `frame` is dropped
    /// (and released). Refused by a table that does not own its leaves.
    pub fn replace_owned(
        &mut self,
        va: VirtAddr,
        frame: OwnedFrame<A>,
        flags: MapFlags,
    ) -> Result<(OwnedFrame<A>, Flush), UnmapError>
    where
        A: Clone,
    {
        if !self.owned {
            return Err(UnmapError::UnownedLeaves);
        }
        if self.is_shared(va) {
            return Err(UnmapError::InvalidAddress);
        }
        if !grants_access(flags) {
            return Err(UnmapError::NoAccess);
        }
        let (e, level) = self.find_leaf(va)?;
        if level != 0 {
            return Err(UnmapError::NotMapped);
        }
        let old = e.swap(F::leaf(frame.pa(), flags, 0), Ordering::AcqRel);
        frame.leak();
        Ok((OwnedFrame::adopt(self.alloc.clone(), F::addr(old, 0)), Flush(va.align_down(PAGE_SIZE as u64))))
    }

    /// Takes another reference to the 4 KiB frame that `va` maps, for a
    /// kernel path that must keep the frame past its mapping. Returns `None`
    /// if `va` is not mapped that way, or the allocator does not count
    /// references.
    pub fn share_owned(&self, va: VirtAddr) -> Option<OwnedFrame<A>>
    where
        A: Clone,
    {
        if !self.owned || self.is_shared(va) {
            return None;
        }
        let (e, level) = self.find_leaf(va).ok()?;
        if level != 0 {
            return None;
        }
        let pa = F::addr(e.load(Ordering::Acquire), 0);
        self.alloc.retain_frame(pa).then(|| OwnedFrame::adopt(self.alloc.clone(), pa))
    }

    fn unmap_pa(&mut self, va: VirtAddr) -> Result<(Translation, Flush), UnmapError> {
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
    /// Invalidates the huge page in the TLB with
    /// [`osmium_arch::mmu::flush_page`], which is right for an active stage-1
    /// table (and harmless for an inactive one). See [`PageTable::split_with`]
    /// for the ordering, the hazards of splitting a live mapping, and how to
    /// supply another invalidation (stage 2, or other CPUs).
    pub fn split(&mut self, va: VirtAddr) -> Result<PageSize, MapError> {
        self.split_with(va, |base| osmium_arch::mmu::flush_page(base.as_usize()))
    }

    /// [`PageTable::split`], with `invalidate` performing the TLB
    /// invalidation of the huge page. It is called with the huge page's base
    /// address (invalidating any address inside a huge page drops its TLB
    /// entry on every supported architecture), and not at all if nothing is
    /// split.
    ///
    /// On formats that need break-before-make ([`PageTableFormat::BREAK_BEFORE_MAKE`],
    /// AArch64), the huge-page entry is cleared, then `invalidate` runs, then
    /// the table is installed. In between the range is unmapped, so nothing
    /// may touch it: not the code doing the split, its stack, the page
    /// tables as seen through the [`PhysMapper`], interrupt handlers, or
    /// other CPUs. Splitting a huge page the running kernel lives in (an
    /// identity or direct map holding its stack or tables) faults there;
    /// map such ranges with small pages from the start instead. On other
    /// formats the table replaces the leaf in place and `invalidate` runs
    /// afterwards, before any part of the range is changed further.
    ///
    /// `invalidate` covers the current CPU, plus whatever else it does
    /// itself. If other CPUs may hold the old translation, it must also shoot
    /// them down: this library has no cross-CPU TLB shootdown, so that is the
    /// caller's job. For an inactive table, pass `|_| {}`.
    pub fn split_with(&mut self, va: VirtAddr, invalidate: impl FnOnce(VirtAddr)) -> Result<PageSize, MapError> {
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
            self.entry(table, cva, level - 1)
                .store(F::leaf(base + i * child.bytes(), flags, level - 1), Ordering::Relaxed);
        }
        // Re-find the entry: `entry` borrows `self`.
        let (e, _) = self.find_leaf(va).map_err(|_| MapError::InvalidAddress)?;
        let huge = va.align_down(PageSize::from_level(level).bytes());
        if F::BREAK_BEFORE_MAKE {
            e.store(0, Ordering::Release);
            invalidate(huge);
            e.store(F::table_at(table, level), Ordering::Release);
        } else {
            e.store(F::table_at(table, level), Ordering::Release);
            invalidate(huge);
        }
        Ok(child)
    }

    /// Unmaps the 4 KiB page at `va`, splitting huge pages around it first
    /// with [`PageTable::split`] (which flushes this CPU's TLB as it goes;
    /// mind its break-before-make hazards on AArch64).
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
        if !grants_access(flags) {
            return Err(UnmapError::NoAccess);
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
                // A foreign leaf above 1 GiB (Sv48 512 GiB) has no `PageSize`; leave it alone.
                if level > PageSize::Size1G.level() {
                    return Err(UnmapError::NotMapped);
                }
                return Ok((e, level));
            }
            table = F::addr(pte, level);
        }
        // Only a malformed level-0 entry gets here (every format treats
        // valid level-0 entries as leaves, and `map` never writes one that
        // is not): report it as unmapped rather than trusting it.
        Err(UnmapError::NotMapped)
    }

    fn entry(&self, table: PhysAddr, va: VirtAddr, level: usize) -> &AtomicU64 {
        let index = (va.0 >> (12 + 9 * level)) as usize % Self::entries(level);
        let base = self.alloc.phys_to_virt(table).cast::<AtomicU64>();
        // SAFETY: `table` is a table frame of this tree, mapped by the
        // allocator's contract; the index is in bounds. Entries are accessed
        // atomically because the hardware walker reads them concurrently.
        unsafe { &*base.add(index) }
    }

    /// Entries in a table at `level`: the root may span several pages.
    fn entries(level: usize) -> usize {
        if level == F::LEVELS - 1 { ENTRIES * F::ROOT_PAGES } else { ENTRIES }
    }

    fn new_table(alloc: &A) -> Result<PhysAddr, MapError> {
        let pa = alloc.alloc_table().ok_or(MapError::OutOfMemory)?;
        // SAFETY: a fresh, exclusively owned frame.
        unsafe { alloc.phys_to_virt(pa).write_bytes(0, PAGE_SIZE) };
        Ok(pa)
    }

    fn free_subtree(&self, table: PhysAddr, level: usize) {
        // Leaves are visited only where something may need freeing: tables
        // always, and the leaves of a table that owns them.
        if level > 0 || self.owned {
            for i in 0..Self::entries(level) {
                let va = VirtAddr::new((i as u64) << (12 + 9 * level));
                if level == F::LEVELS - 1 && self.is_shared(va) {
                    continue;
                }
                let pte = self.entry(table, va, level).load(Ordering::Relaxed);
                if !F::is_valid(pte) {
                    continue;
                }
                if !F::is_leaf(pte, level) {
                    if level > 0 {
                        self.free_subtree(F::addr(pte, level), level - 1);
                    }
                } else if self.owned && level == 0 {
                    // SAFETY: the table is being dropped, so this leaf's reference is given up
                    // here, and nothing maps the frame through it any more.
                    unsafe { self.alloc.release_frame(F::addr(pte, level)) };
                }
            }
        }
        // SAFETY: called once per table, during drop, when nothing else
        // references the tree.
        unsafe {
            if level == F::LEVELS - 1 {
                self.alloc.free_root(table, F::ROOT_PAGES);
            } else {
                self.alloc.free_table(table);
            }
        }
    }
}

impl<F: PageTableFormat, A: TableAlloc> Drop for PageTable<F, A> {
    fn drop(&mut self) {
        self.free_subtree(self.root, F::LEVELS - 1);
    }
}

#[cfg(test)]
mod tests;
