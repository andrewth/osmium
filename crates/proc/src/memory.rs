//! User address spaces.

use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::mem::offset_of;
use core::ops::Range;
use core::sync::atomic::{AtomicBool, Ordering};

use osmium_boot::elf::Elf;
use osmium_mm::addr::{PAGE_SIZE, PhysAddr, VirtAddr};
use osmium_mm::paging::{MapError, MapFlags, PageSize, PageTable, PageTableFormat, TableAlloc};
use osmium_sync::IrqSpinLock;
use osmium_sync::arc::ArcTree;
use osmium_sync::fallible::{OutOfMemory, try_arc};
use osmium_sync::intrusive::{Adapter, KeyAdapter, Shared, TreeLink};

use osmium_fs::Errno;

mod filemap;
pub use filemap::FileMapping;
use filemap::FileMaps;

const PAGE: u64 = PAGE_SIZE as u64;

/// The most memory an executable's segments may span together.
const MAX_IMAGE_MEMORY: u64 = 1 << 30;

/// A process's view of memory, with the page-table format erased so that
/// [`crate::Process`] and the system-call layer are not generic.
///
/// Every access checks the process's own page table, so a system call can
/// only reach pages the process itself could: user-accessible, and writable
/// for stores. Copies go through the physical mapping, never through the
/// user's virtual addresses, so they need no SUM, PAN or SMAP handling and
/// work whichever table is active.
pub trait UserMemory: Send + Sync {
    /// Physical address of the root table, for satp, TTBR0 or CR3.
    fn root(&self) -> PhysAddr;
    /// Copies `buf.len()` bytes from user address `va`.
    fn read(&self, va: u64, buf: &mut [u8]) -> Result<(), Errno>;
    /// Copies `data` to user address `va`.
    fn write(&self, va: u64, data: &[u8]) -> Result<(), Errno>;
    /// Maps zeroed, user-accessible pages over `va..va + len` (page-aligned)
    /// with `flags`. Pages already mapped are left as they are.
    fn map_anon(&self, va: u64, len: u64, flags: MapFlags) -> Result<(), Errno>;
    /// Unmaps and frees the pages in `va..va + len` (page-aligned) that this
    /// space allocated. Pages that are not mapped are skipped.
    fn unmap(&self, va: u64, len: u64);
    /// Loads every segment of `elf`, user-accessible, and returns the first
    /// page boundary past the highest one: where the program break starts.
    /// Code is made visible to instruction fetch where the architecture
    /// allows that from here (AArch64); RISC-V still needs a `fence.i` on
    /// the hart that runs it.
    fn load_elf(&self, elf: &Elf<'_>) -> Result<u64, Errno>;
    /// A copy of this space for `fork`: the same kernel mappings, and every
    /// page this space owns shared copy-on-write: writable pages become
    /// read-only in both spaces until one of them writes (see
    /// [`UserMemory::cow_fault`]), and kernel copies to them (`write`) break
    /// the sharing the same way.
    fn fork(&self) -> Result<Arc<dyn UserMemory>, Errno>;
    /// Handles a user write fault at `va`: if the page is a copy-on-write
    /// page, gives this space its own writable copy (or the original, if no
    /// other space still shares it) and returns true, so the faulting
    /// instruction can be retried. Returns false for any other fault.
    fn cow_fault(&self, va: u64) -> bool;
    /// Maps fresh read-only, executable pages at `va` (page-aligned) holding
    /// `code`; the kernel's own stubs, such as the signal return trampoline.
    fn map_code(&self, _va: u64, _code: &[u8]) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }

    /// Records a file mapping over `va..va + len` (page-aligned, inside the
    /// user half and clear of every other mapping). Nothing is read yet: the
    /// pages are loaded when first touched (see [`UserMemory::file_fault`]).
    fn map_file(&self, _va: u64, _len: u64, _map: FileMapping) -> Result<(), Errno> {
        Err(Errno::ENODEV)
    }
    /// Reserves `va..va + len` (page-aligned) with no access: anonymous
    /// memory that [`UserMemory::mprotect`] can later make usable. The
    /// default does nothing, since an unmapped range already faults.
    fn reserve(&self, _va: u64, _len: u64) -> Result<(), Errno> {
        Ok(())
    }
    /// Handles a user fault at `va` in a file mapping or reservation: loads
    /// the page (a read, or a write to a private mapping), or makes a clean
    /// page of a shared mapping writable and records it as dirty. Returns
    /// true if the instruction can be retried; false if `va` is in no
    /// mapping, the access is not allowed, or the page is past the end of
    /// the file.
    fn file_fault(&self, _va: u64, _write: bool) -> bool {
        false
    }
    /// [`UserMemory::unmap`] for `munmap`: also writes back the dirty pages
    /// of shared file mappings and drops the mappings, and reports a failure
    /// to do either. On `ENOMEM` nothing was changed. `len` is page-aligned.
    fn munmap(&self, va: u64, len: u64) -> Result<(), Errno> {
        self.unmap(va, len);
        Ok(())
    }
    /// Changes the access of `va..va + len` (page-aligned) to `prot`, some of
    /// `READ`, `WRITE` and `EXEC`. Pages not loaded yet get it when they are.
    fn mprotect(&self, _va: u64, _len: u64, _prot: MapFlags) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }
    /// Writes the dirty pages of shared file mappings in `va..va + len`
    /// back to their files, and with `sync`, makes them durable.
    fn msync(&self, _va: u64, _len: u64, _sync: bool) -> Result<(), Errno> {
        Ok(())
    }
    /// Writes back every dirty page of every shared file mapping: when the
    /// space is about to be given up.
    fn sync_files(&self) -> Result<(), Errno> {
        Ok(())
    }
}

/// A physical frame holding one user page, freed when the last space that
/// maps it lets go. Spaces share frames only with their forks, so the
/// reference count is the number of spaces mapping it.
struct Frame<A: TableAlloc> {
    pa: PhysAddr,
    alloc: A,
}

impl<A: TableAlloc> Drop for Frame<A> {
    fn drop(&mut self) {
        // SAFETY: the last owner's frame, no longer mapped by anyone.
        unsafe { self.alloc.free_table(self.pa) };
    }
}

/// A page of a space: where it is, the frame behind it, and whether a write
/// must copy that frame first. It is linked into its space's [`Inner::pages`]
/// by address, and while a page is being loaded into a new space, into a
/// [`Fresh`] tree by frame.
///
/// The fields other than the link are only touched under the lock around
/// the space's [`Inner`], or by whoever holds a page that no space holds yet.
struct Page<A: TableAlloc> {
    /// The user address, page-aligned. Set before the page is linked by
    /// address, and not changed while it is.
    va: UnsafeCell<u64>,
    /// Replaced when a write copies the frame.
    frame: UnsafeCell<Arc<Frame<A>>>,
    /// Set when a fork made a writable page read-only: a write fault copies
    /// the frame, or makes it writable again if no one else shares it.
    cow: AtomicBool,
    link: Shared<TreeLink>,
}

// SAFETY: see the type's documentation: all access is serialized by the
// space's lock.
unsafe impl<A: TableAlloc + Send + Sync> Sync for Page<A> {}

impl<A: TableAlloc> Page<A> {
    /// A page over a new frame `pa` (taking ownership of it, even if this
    /// fails), not at any address yet.
    fn new(pa: PhysAddr, alloc: A) -> Result<Arc<Self>, OutOfMemory> {
        Self::sharing(try_arc(Frame { pa, alloc })?, false)
    }

    /// A page over a frame that others map too.
    fn sharing(frame: Arc<Frame<A>>, cow: bool) -> Result<Arc<Self>, OutOfMemory> {
        try_arc(Self {
            va: UnsafeCell::new(0),
            frame: UnsafeCell::new(frame),
            cow: AtomicBool::new(cow),
            link: Shared::new(TreeLink::new()),
        })
    }

    /// Fixes the address, before the page is linked by it.
    fn place(&self, va: u64) {
        // SAFETY: see the type's documentation: the page is not linked.
        unsafe { *self.va.get() = va };
    }

    fn va(&self) -> u64 {
        // SAFETY: see the type's documentation.
        unsafe { *self.va.get() }
    }

    fn frame(&self) -> &Arc<Frame<A>> {
        // SAFETY: as above.
        unsafe { &*self.frame.get() }
    }

    fn is_cow(&self) -> bool {
        self.cow.load(Ordering::Relaxed)
    }

    fn set_cow(&self, cow: bool) {
        self.cow.store(cow, Ordering::Relaxed);
    }
}

/// Pages ordered by user address.
struct ByVa<A>(core::marker::PhantomData<A>);

// SAFETY: `offset_of!` of a `Shared<TreeLink>`, which is a `TreeLink`.
unsafe impl<A: TableAlloc> Adapter<TreeLink> for ByVa<A> {
    type Value = Page<A>;
    const OFFSET: usize = offset_of!(Page<A>, link);
}

impl<A: TableAlloc> KeyAdapter<TreeLink> for ByVa<A> {
    type Key = u64;

    fn key(page: &Page<A>) -> &u64 {
        // SAFETY: see the type's documentation; only used to compare.
        unsafe { &*page.va.get() }
    }
}

/// Pages ordered by frame, while an ELF is being loaded.
struct ByFrame<A>(core::marker::PhantomData<A>);

// SAFETY: as for `ByVa`.
unsafe impl<A: TableAlloc> Adapter<TreeLink> for ByFrame<A> {
    type Value = Page<A>;
    const OFFSET: usize = offset_of!(Page<A>, link);
}

impl<A: TableAlloc> KeyAdapter<TreeLink> for ByFrame<A> {
    type Key = PhysAddr;

    fn key(page: &Page<A>) -> &PhysAddr {
        &page.frame().pa
    }
}

type Fresh<A> = ArcTree<ByFrame<A>>;

/// A user address space in page-table format `F`, with table pages and user
/// pages both drawn from `A`.
///
/// It shares the kernel's root entries, owns every user page it maps, and
/// frees them, and its tables, when dropped. It must not be dropped while
/// active on any CPU; a [`crate::Process`] is dropped only after its task has
/// been switched away from for the last time.
pub struct AddressSpace<F: PageTableFormat, A: TableAlloc + Clone> {
    root: PhysAddr,
    /// The allocator user pages come from (the table holds its own copy).
    alloc: A,
    /// The root entries shared with the kernel.
    shared: Range<usize>,
    inner: IrqSpinLock<Inner<F, A>>,
}

struct Inner<F: PageTableFormat, A: TableAlloc> {
    pt: PageTable<F, A>,
    /// The pages this space maps, by user address. A frame is freed when no
    /// space's pages refer to it.
    pages: ArcTree<ByVa<A>>,
    /// The file mappings and reservations, and which pages of shared ones
    /// are dirty.
    maps: FileMaps,
}

impl<F: PageTableFormat, A: TableAlloc + Clone> AddressSpace<F, A> {
    /// Gives the copy-on-write page at `va` (page-aligned) its own writable
    /// frame. Returns false if it is not one, or memory ran out.
    fn break_cow(&self, inner: &mut Inner<F, A>, va: u64) -> bool {
        let Inner { pt, pages, maps } = inner;
        let Some(page) = pages.find(&va) else { return false };
        if !page.is_cow() {
            return false;
        }
        // A mapping made read-only after the fork stays so.
        if maps.find(va).is_some_and(|v| !v.prot().contains(MapFlags::WRITE)) {
            return false;
        }
        let vaddr = VirtAddr::new(va);
        let Some(t) = pt.translate(vaddr) else { return false };
        let flags = t.flags | MapFlags::WRITE;
        // Only this space can add a reference to its frame (by forking, which
        // takes the lock we hold), so a count of one stays one.
        if Arc::strong_count(page.frame()) > 1 {
            let Some(new) = self.alloc.alloc_table() else { return false };
            // The frame is the copy's from here on; dropping it frees it.
            let Ok(copy) = try_arc(Frame { pa: new, alloc: self.alloc.clone() }) else { return false };
            // SAFETY: both are whole frames reached through the allocator's
            // mapping; `new` is fresh and exclusively ours.
            unsafe {
                core::ptr::copy_nonoverlapping(self.alloc.phys_to_virt(t.pa), self.alloc.phys_to_virt(new), PAGE_SIZE)
            };
            let Ok((_, flush)) = pt.unmap(vaddr) else { return false };
            flush.flush();
            match pt.map(vaddr, new, PageSize::Size4K, flags) {
                Ok(flush) => flush.flush(),
                Err(_) => {
                    if let Ok(flush) = pt.map(vaddr, t.pa, PageSize::Size4K, t.flags) {
                        flush.flush();
                    }
                    return false;
                }
            }
            // SAFETY: under the space's lock, which `inner` proves.
            let old = unsafe { core::mem::replace(&mut *page.frame.get(), copy) };
            drop(old);
            if flags.contains(MapFlags::EXEC) {
                sync_icache(self.alloc.phys_to_virt(new));
            }
        } else {
            match pt.protect(vaddr, flags) {
                Ok(flush) => flush.flush(),
                Err(_) => return false,
            }
        }
        page.set_cow(false);
        true
    }
}

impl<F: PageTableFormat + Send + Sync + 'static, A: TableAlloc + Clone + Send + Sync + 'static> AddressSpace<F, A> {
    /// Unmaps and frees the pages of `va..va + len`, and drops the file
    /// mappings there after writing back what shared ones hold. With
    /// `strict`, running out of memory to split a mapping fails the call
    /// before anything is changed; otherwise the pages go regardless.
    fn unmap_range(&self, va: u64, len: u64, strict: bool) -> Result<(), Errno> {
        debug_assert_threads_pinned();
        let end = va.saturating_add(len);
        // Before the pages go: this is the last chance to save them.
        let saved = self.writeback(va, end);
        let mut inner = self.inner.lock();
        let Inner { pt, pages, maps } = &mut *inner;
        if strict {
            maps.carve(va, end, filemap::Edit::Remove)?;
        } else {
            maps.remove(va, end);
        }
        maps.clear_dirty(va, end);
        // Every user page is one of ours, so visit those rather than each
        // page of a range that may span most of the address space.
        let mut from = va & !(PAGE - 1);
        while let Some(at) = pages.lower_bound(&from).map(Page::va).filter(|&at| at < end) {
            from = at + PAGE;
            match pt.unmap(VirtAddr::new(at)) {
                // The flush is local to this CPU. That is enough because all
                // of a process's threads share one CPU (`clone` pins them),
                // so no other CPU holds a stale TLB entry.
                Ok((_, flush)) => flush.flush(),
                // Mapped, yet it cannot be unmapped: leave it, and its frame.
                Err(_) if pt.translate(VirtAddr::new(at)).is_some() => continue,
                // Not mapped: nothing refers to the frame.
                Err(_) => {}
            }
            // The frame goes with the page, unless a relative still maps it.
            drop(pages.take_key(&at));
        }
        saved
    }
}

impl<F: PageTableFormat + Send + Sync + 'static, A: TableAlloc + Clone + Send + Sync + 'static> AddressSpace<F, A> {
    /// Creates an empty space whose root entries `shared` point at the same
    /// tables as `kernel`'s, so the kernel stays mapped while it is active.
    ///
    /// # Safety
    /// `kernel`'s subtables must outlive the space.
    pub unsafe fn new<B: TableAlloc>(
        alloc: A,
        kernel: &PageTable<F, B>,
        shared: Range<usize>,
    ) -> Result<Self, MapError> {
        let mut pt = PageTable::new(alloc.clone())?;
        // SAFETY: forwarded contract.
        unsafe { pt.share_root_entries(kernel, shared.clone()) };
        Ok(Self {
            root: pt.root(),
            alloc,
            shared,
            inner: IrqSpinLock::new(Inner { pt, pages: ArcTree::new(), maps: FileMaps::default() }),
        })
    }

    /// Whether `va..end` is non-empty, in the lower (user) half, and clear of
    /// the root entries shared with the kernel.
    fn is_user_range(&self, va: u64, end: u64) -> bool {
        let top = 1u64 << (F::VA_BITS - u32::from(F::SIGN_EXTEND));
        if va >= end || end > top {
            return false;
        }
        let shift = 12 + 9 * (F::LEVELS as u32 - 1);
        let (first, last) = ((va >> shift) as usize, ((end - 1) >> shift) as usize);
        last < self.shared.start || first >= self.shared.end
    }

    /// Copies `code` into fresh pages mapped at `va` (page-aligned) with
    /// `flags` plus `USER`, for programs that are flat binaries.
    pub fn load_flat(&self, va: u64, code: &[u8], flags: MapFlags) -> Result<(), MapError> {
        let len = (code.len() as u64).checked_next_multiple_of(PAGE).ok_or(MapError::OutOfMemory)?.max(PAGE);
        self.map_anon(va, len, flags).map_err(|_| MapError::OutOfMemory)?;
        let inner = self.inner.lock();
        // Check no permission: the code may be mapped read-only.
        walk(&inner.pt, va, code.len(), MapFlags::NONE, |dst, off, n| {
            let src = code.get(off..off.saturating_add(n)).ok_or(Errno::EFAULT)?;
            // SAFETY: `dst` points at `n` bytes of a frame this space owns.
            unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), dst, n) };
            Ok(())
        })
        .map_err(|_| MapError::InvalidAddress)
    }
}

impl<F: PageTableFormat + Send + Sync + 'static, A: TableAlloc + Clone + Send + Sync + 'static> UserMemory
    for AddressSpace<F, A>
{
    fn root(&self) -> PhysAddr {
        self.root
    }

    fn read(&self, va: u64, buf: &mut [u8]) -> Result<(), Errno> {
        self.fault_in(va, buf.len(), false)?;
        let inner = self.inner.lock();
        walk(&inner.pt, va, buf.len(), MapFlags::READ, |src, off, n| {
            let to = buf.get_mut(off..off.saturating_add(n)).ok_or(Errno::EFAULT)?;
            // SAFETY: `src` points at `n` bytes of a user-readable frame.
            unsafe { core::ptr::copy_nonoverlapping(src, to.as_mut_ptr(), n) };
            Ok(())
        })
    }

    fn write(&self, va: u64, data: &[u8]) -> Result<(), Errno> {
        self.fault_in(va, data.len(), true)?;
        let mut inner = self.inner.lock();
        let end = va.checked_add(data.len() as u64).ok_or(Errno::EFAULT)?;
        let mut from = va & !(PAGE - 1);
        while from < end
            && let Some(page) = inner.pages.lower_bound(&from)
            && page.va() < end
        {
            let (at, cow) = (page.va(), page.is_cow());
            from = at + PAGE;
            if cow && !self.break_cow(&mut inner, at) {
                return Err(Errno::EFAULT);
            }
        }
        walk(&inner.pt, va, data.len(), MapFlags::WRITE, |dst, off, n| {
            let from = data.get(off..off.saturating_add(n)).ok_or(Errno::EFAULT)?;
            // SAFETY: `dst` points at `n` bytes of a user-writable frame.
            unsafe { core::ptr::copy_nonoverlapping(from.as_ptr(), dst, n) };
            Ok(())
        })
    }

    fn map_anon(&self, va: u64, len: u64, flags: MapFlags) -> Result<(), Errno> {
        if !va.is_multiple_of(PAGE) || !len.is_multiple_of(PAGE) {
            return Err(Errno::EINVAL);
        }
        let end = va.checked_add(len).ok_or(Errno::ENOMEM)?;
        let mut inner = self.inner.lock();
        for page in (va..end).step_by(PAGE_SIZE) {
            if inner.pt.translate(VirtAddr::new(page)).is_some() {
                continue;
            }
            let pa = self.alloc.alloc_table().ok_or(Errno::ENOMEM)?;
            // The page owns the frame from here, and frees it if anything
            // below fails.
            let node = Page::new(pa, self.alloc.clone()).map_err(|_| Errno::ENOMEM)?;
            // SAFETY: a fresh frame, reachable through the allocator's mapping.
            unsafe { self.alloc.phys_to_virt(pa).write_bytes(0, PAGE_SIZE) };
            match inner.pt.map(VirtAddr::new(page), pa, PageSize::Size4K, flags | MapFlags::USER) {
                // The space may be active here, and RISC-V may cache invalid entries.
                Ok(flush) => flush.flush(),
                Err(e) => return Err(if e == MapError::OutOfMemory { Errno::ENOMEM } else { Errno::EINVAL }),
            }
            node.place(page);
            // A page that is not mapped has no node: see `unmap`.
            drop(inner.pages.take_key(&page));
            assert!(inner.pages.insert(node).is_ok(), "the page's slot was just emptied");
        }
        Ok(())
    }

    fn unmap(&self, va: u64, len: u64) {
        // This cannot report a failure, so it unmaps whatever happens.
        let _ = self.unmap_range(va, len, false);
    }

    fn munmap(&self, va: u64, len: u64) -> Result<(), Errno> {
        self.unmap_range(va, len, true)
    }

    fn map_file(&self, va: u64, len: u64, map: FileMapping) -> Result<(), Errno> {
        self.map_file_impl(va, len, map)
    }

    fn reserve(&self, va: u64, len: u64) -> Result<(), Errno> {
        self.reserve_impl(va, len)
    }

    fn file_fault(&self, va: u64, write: bool) -> bool {
        self.file_fault_impl(va, write)
    }

    fn mprotect(&self, va: u64, len: u64, prot: MapFlags) -> Result<(), Errno> {
        self.mprotect_impl(va, len, prot)
    }

    fn msync(&self, va: u64, len: u64, sync: bool) -> Result<(), Errno> {
        self.msync_impl(va, len, sync)
    }

    fn sync_files(&self) -> Result<(), Errno> {
        self.writeback(0, u64::MAX)
    }

    fn load_elf(&self, elf: &Elf<'_>) -> Result<u64, Errno> {
        // The loader writes into any page already mapped, and the kernel's
        // are, through the shared root entries: keep every segment out of
        // them, and bound the total so loading cannot exhaust memory.
        let mut total = 0u64;
        for seg in elf.segments().filter(|s| s.mem_size != 0) {
            let end = seg.vaddr.checked_add(seg.mem_size).ok_or(Errno::ENOEXEC)?;
            if !self.is_user_range(seg.vaddr, end) {
                return Err(Errno::ENOEXEC);
            }
            total = total.saturating_add(seg.mem_size);
        }
        if total > MAX_IMAGE_MEMORY {
            return Err(Errno::ENOMEM);
        }
        let mut inner = self.inner.lock();
        let Inner { pt, pages, .. } = &mut *inner;
        // The frames the loader allocates, until we know which page each is.
        let mut fresh: Fresh<A> = ArcTree::new();
        let loaded = elf.load_into(pt, MapFlags::USER, || {
            let pa = self.alloc.alloc_table()?;
            // The page owns the frame from here, and frees it if the loader
            // then fails to map it.
            let node = Page::new(pa, self.alloc.clone()).ok()?;
            assert!(fresh.insert(node).is_ok(), "frames are distinct");
            Some(pa)
        });
        // Record where each new frame went, so `unmap` and `fork` find it,
        // even after a failure part-way.
        for seg in elf.segments().filter(|s| s.mem_size != 0) {
            let end = seg.vaddr.saturating_add(seg.mem_size);
            for page in (seg.vaddr & !(PAGE - 1)..end).step_by(PAGE_SIZE) {
                let Some(t) = pt.translate(VirtAddr::new(page)) else { continue };
                if let Some(node) = fresh.take_key(&t.pa) {
                    node.place(page);
                    drop(pages.take_key(&page));
                    assert!(pages.insert(node).is_ok(), "the page's slot was just emptied");
                }
                if t.flags.contains(MapFlags::EXEC) {
                    sync_icache(pt.allocator().phys_to_virt(t.pa));
                }
            }
        }
        // What is left in `fresh` was allocated for a page the loader then
        // failed to map: dropping it frees the frame.
        drop(fresh);
        loaded.map_err(|e| if e == MapError::OutOfMemory { Errno::ENOMEM } else { Errno::ENOEXEC })?;
        // Every non-empty segment was checked to end inside the user half above.
        let end = elf.segments().filter(|s| s.mem_size != 0).map(|s| s.vaddr.saturating_add(s.mem_size)).max();
        end.unwrap_or(0).checked_next_multiple_of(PAGE).ok_or(Errno::ENOEXEC)
    }

    fn fork(&self) -> Result<Arc<dyn UserMemory>, Errno> {
        // Making pages read-only flushes this CPU only: see `unmap`.
        debug_assert_threads_pinned();
        let mut guard = self.inner.lock();
        let Inner { pt: parent_pt, pages: parent_pages, maps: parent_maps } = &mut *guard;
        let maps = parent_maps.try_clone()?;
        let mut pt = PageTable::new(self.alloc.clone()).map_err(|_| Errno::ENOMEM)?;
        // SAFETY: our shared root entries are the kernel's, which outlive
        // this space (see `new`) and so the copy, made under the same terms.
        unsafe { pt.share_root_entries(parent_pt, self.shared.clone()) };
        let child = Self {
            root: pt.root(),
            alloc: self.alloc.clone(),
            shared: self.shared.clone(),
            inner: IrqSpinLock::new(Inner { pt, pages: ArcTree::new(), maps }),
        };
        {
            let mut copy = child.inner.lock();
            for page in parent_pages.iter() {
                let va = VirtAddr::new(page.va());
                // A page whose mapping is gone has nothing to share.
                let Some(t) = parent_pt.translate(va) else { continue };
                let mut flags = t.flags;
                let mut cow = page.is_cow();
                // Shared file pages stay shared and writable: that is the point.
                let shared = parent_maps.find(page.va()).is_some_and(|v| v.shared());
                if flags.contains(MapFlags::WRITE) && !shared {
                    flags = flags.difference(MapFlags::WRITE);
                    if !flags.contains(MapFlags::READ) && !flags.contains(MapFlags::EXEC) {
                        flags = flags | MapFlags::READ;
                    }
                    // The parent may be running on this table.
                    parent_pt.protect(va, flags).map_err(|_| Errno::EINVAL)?.flush();
                    cow = true;
                    // Record it now, so if the child's map below fails the
                    // parent can still write the page (a lone share breaks
                    // COW in place).
                    page.set_cow(true);
                }
                // On failure, dropping `child` releases the pages shared so far.
                let node = Page::sharing(page.frame().clone(), cow).map_err(|_| Errno::ENOMEM)?;
                match copy.pt.map(va, t.pa, PageSize::Size4K, flags) {
                    // The copy is not active anywhere yet.
                    Ok(flush) => flush.ignore(),
                    Err(e) => return Err(if e == MapError::OutOfMemory { Errno::ENOMEM } else { Errno::EINVAL }),
                }
                node.place(page.va());
                assert!(copy.pages.insert(node).is_ok(), "a new space has no pages yet");
            }
        }
        let child: Arc<dyn UserMemory> = try_arc(child).map_err(|_| Errno::ENOMEM)?;
        Ok(child)
    }

    fn cow_fault(&self, va: u64) -> bool {
        let mut inner = self.inner.lock();
        self.break_cow(&mut inner, va & !(PAGE - 1))
    }

    fn map_code(&self, va: u64, code: &[u8]) -> Result<(), Errno> {
        if !va.is_multiple_of(PAGE) || code.len() > PAGE_SIZE || !self.is_user_range(va, va + PAGE) {
            return Err(Errno::EINVAL);
        }
        self.load_flat(va, code, MapFlags::RX).map_err(|_| Errno::ENOMEM)?;
        let inner = self.inner.lock();
        let t = inner.pt.translate(VirtAddr::new(va)).ok_or(Errno::EFAULT)?;
        sync_icache(inner.pt.allocator().phys_to_virt(t.pa));
        Ok(())
    }
}

/// Page-table changes flush the TLB of this CPU only, which is enough while
/// every thread of a process runs on one CPU. Checks that the calling task,
/// if it is one of several threads of a process, is pinned to one CPU. Only
/// in kernels: the host tests run without a scheduler.
fn debug_assert_threads_pinned() {
    if cfg!(all(debug_assertions, target_os = "none"))
        && let Some(p) = crate::process::current()
        && p.group.live() > 1
    {
        debug_assert!(
            osmium_sched::current().affinity().count_ones() == 1,
            "threads of one process must be pinned to one CPU: page-table flushes are local"
        );
    }
}

/// Walks `va..va + len` in `pt` page by page, requiring every page to have
/// `need` (plus `USER`, unless `need` is empty), and calls `f(ptr, offset, n)`
/// for each piece.
fn walk<F: PageTableFormat, A: TableAlloc>(
    pt: &PageTable<F, A>,
    va: u64,
    len: usize,
    need: MapFlags,
    mut f: impl FnMut(*mut u8, usize, usize) -> Result<(), Errno>,
) -> Result<(), Errno> {
    let need = if need == MapFlags::NONE { need } else { need | MapFlags::USER };
    va.checked_add(len as u64).ok_or(Errno::EFAULT)?;
    let mut off = 0;
    while off < len {
        let addr = va + off as u64;
        let t = pt.translate(VirtAddr::new(addr)).ok_or(Errno::EFAULT)?;
        if !t.flags.contains(need) {
            return Err(Errno::EFAULT);
        }
        let n = ((PAGE - addr % PAGE) as usize).min(len - off);
        f(pt.allocator().phys_to_virt(t.pa), off, n)?;
        off += n;
    }
    Ok(())
}

/// Makes the code in the page at `page` (a kernel pointer to a user frame,
/// just written) visible to instruction fetch on every CPU. Only AArch64 can
/// do this here; on RISC-V each hart runs `fence.i` before user code instead.
fn sync_icache(page: *mut u8) {
    #[cfg(all(target_arch = "aarch64", target_os = "none"))]
    {
        // The data cache is physically tagged: cleaning lines through the
        // kernel's mapping cleans them for the user's mapping too.
        for line in (page as usize..page as usize + PAGE_SIZE).step_by(64) {
            // SAFETY: cache maintenance on a mapped kernel address.
            unsafe { core::arch::asm!("dc cvau, {}", in(reg) line) };
        }
        // SAFETY: barriers and instruction-cache invalidation only.
        unsafe { core::arch::asm!("dsb ish", "ic ialluis", "dsb ish", "isb") };
    }
    let _ = page;
}
