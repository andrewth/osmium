//! User address spaces.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::mem::offset_of;
use core::ops::Range;
use core::sync::atomic::{AtomicBool, Ordering};

use osmium_boot::elf::Elf;
use osmium_mm::addr::{PAGE_SIZE, PhysAddr, VirtAddr};
use osmium_mm::frame::OwnedFrame;
use osmium_mm::paging::{MapError, MapFlags, PageTable, PageTableFormat, TableAlloc};
use osmium_mm::vma::{VmaError, VmaSpare, VmaTree};
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
    /// Like [`load_elf`](UserMemory::load_elf), with `bias` added to every
    /// address, for a position-independent image. Relocations are not
    /// applied. The default supports only a bias of 0.
    fn load_elf_at(&self, elf: &Elf<'_>, bias: u64) -> Result<u64, Errno> {
        if bias == 0 { self.load_elf(elf) } else { Err(Errno::ENOSYS) }
    }
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
    /// Reserves `va..va + len` (page-aligned) as an area of zeroed,
    /// user-accessible pages with `flags`, without allocating any: each page
    /// gets its frame the first time something touches it (a page fault, see
    /// [`UserMemory::page_fault`], or a kernel copy through `read` or
    /// `write`). Fails with `EINVAL` if the range overlaps an area or a page
    /// that is already there, or is not in the user half.
    fn map_lazy(&self, _va: u64, _len: u64, _flags: MapFlags) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }
    /// Handles a user page fault at `va`, a write if `write`: a page of a
    /// [`map_lazy`](UserMemory::map_lazy) area that has no frame yet gets
    /// one, zeroed; a write to a copy-on-write page is handled as by
    /// [`UserMemory::cow_fault`]. Returns true if the faulting instruction
    /// can be retried, false for any other fault (including an access the
    /// area's flags do not allow).
    fn page_fault(&self, va: u64, write: bool) -> bool {
        write && self.cow_fault(va)
    }
    /// Handles a user write fault at `va` that [`UserMemory::cow_fault`]
    /// refused, on a space whose threads run on several CPUs: if the page is
    /// writable after all, this CPU's TLB held a stale read-only entry for it
    /// (another CPU broke the page's sharing since). Drops that entry and
    /// returns true, so the instruction can be retried.
    fn stale_fault(&self, _va: u64) -> bool {
        false
    }
    /// Maps fresh read-only, executable pages at `va` (page-aligned) holding
    /// `code`; the kernel's own stubs, such as the signal return trampoline.
    fn map_code(&self, _va: u64, _code: &[u8]) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }

    /// Records a file mapping over `va..va + len` (page-aligned, inside the
    /// user half and clear of every other mapping). Nothing is read yet: the
    /// pages are loaded when first touched (see [`UserMemory::page_fault`]).
    fn map_file(&self, _va: u64, _len: u64, _map: FileMapping) -> Result<(), Errno> {
        Err(Errno::ENODEV)
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

/// A page of a space: where it is, the frame behind it, and whether a write
/// must copy that frame first. It is linked into its space's [`Inner::pages`]
/// by address, and while a page is being loaded into a new space, into a
/// [`Fresh`] tree by frame.
///
/// The page does not own its frame: the space's page table holds the frame's
/// reference, and the page only records where the frame is.
///
/// The fields other than the link are only touched under the lock around
/// the space's [`Inner`], or by whoever holds a page that no space holds yet.
struct Page<A: TableAlloc> {
    /// The user address, page-aligned. Set before the page is linked by
    /// address, and not changed while it is.
    va: UnsafeCell<u64>,
    /// The frame behind the page, replaced when a write copies it.
    frame: UnsafeCell<PhysAddr>,
    /// Set when a fork made a writable page read-only: a write fault copies
    /// the frame, or makes it writable again if no one else shares it.
    cow: AtomicBool,
    /// Set when `mprotect` took write access away: a copy-on-write fault or a
    /// kernel copy must not give it back.
    ro: AtomicBool,
    link: Shared<TreeLink>,
    _alloc: core::marker::PhantomData<A>,
}

// SAFETY: see the type's documentation: all access is serialized by the
// space's lock.
unsafe impl<A: TableAlloc + Send + Sync> Sync for Page<A> {}

impl<A: TableAlloc> Page<A> {
    /// A page over frame `pa`, not at any address yet.
    fn new(pa: PhysAddr, cow: bool) -> Result<Arc<Self>, OutOfMemory> {
        try_arc(Self {
            va: UnsafeCell::new(0),
            frame: UnsafeCell::new(pa),
            cow: AtomicBool::new(cow),
            ro: AtomicBool::new(false),
            link: Shared::new(TreeLink::new()),
            _alloc: core::marker::PhantomData,
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

    fn set_frame(&self, pa: PhysAddr) {
        // SAFETY: as above.
        unsafe { *self.frame.get() = pa };
    }

    fn is_cow(&self) -> bool {
        self.cow.load(Ordering::Relaxed)
    }

    fn set_cow(&self, cow: bool) {
        self.cow.store(cow, Ordering::Relaxed);
    }

    fn is_ro(&self) -> bool {
        self.ro.load(Ordering::Relaxed)
    }

    fn set_ro(&self, ro: bool) {
        self.ro.store(ro, Ordering::Relaxed);
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
        // SAFETY: see the type's documentation; only used to compare.
        unsafe { &*page.frame.get() }
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
    /// The file mappings, and which pages of shared ones are dirty.
    maps: FileMaps,
    /// The areas reserved with `map_lazy`, whether or not their pages exist
    /// yet. Pages that were mapped any other way are in no area.
    vmas: VmaTree,
}

impl<F: PageTableFormat, A: TableAlloc + Clone> AddressSpace<F, A> {
    /// Gives the copy-on-write page at `va` (page-aligned) its own writable
    /// frame. Returns false if it is not one, or memory ran out.
    fn break_cow(&self, inner: &mut Inner<F, A>, va: u64, deferred: &mut Deferred<A>) -> bool {
        let Inner { pt, pages, maps, vmas } = inner;
        let Some(page) = pages.find(&va) else { return false };
        if !page.is_cow() || page.is_ro() {
            return false;
        }
        // A mapping made read-only after the fork stays so.
        if maps.find(va).is_some_and(|v| !v.prot().contains(MapFlags::WRITE))
            || vmas.find(va).is_some_and(|v| !v.flags.contains(MapFlags::WRITE))
        {
            return false;
        }
        let vaddr = VirtAddr::new(va);
        let Some(t) = pt.translate(vaddr) else { return false };
        let flags = t.flags | MapFlags::WRITE;
        // Only this space can add a reference to its frame (by forking, which
        // takes the lock we hold), so a count of one stays one.
        if self.alloc.frame_refs(t.pa).unwrap_or(1) > 1 {
            // A frame the batch can hold, reserved before anything changes: the
            // old one is released only once the other CPUs have been shot down.
            if deferred.reserve().is_err() {
                return false;
            }
            let Some(new) = self.alloc.alloc_table() else { return false };
            // The copy's reference is the table's from the moment it is mapped.
            let Some(copy) = OwnedFrame::claim(self.alloc.clone(), new) else { return false };
            // SAFETY: both are whole frames reached through the allocator's mapping; `new` is fresh
            // and exclusively ours.
            unsafe {
                core::ptr::copy_nonoverlapping(self.alloc.phys_to_virt(t.pa), self.alloc.phys_to_virt(new), PAGE_SIZE)
            };
            // Swaps the mapping in one step, so a failure leaves the old one in place.
            let Ok((old, flush)) = pt.replace_owned(vaddr, copy, flags) else { return false };
            flush.flush();
            page.set_frame(new);
            // Other CPUs may still map the old frame: keep its reference until they have been shot
            // down, or the last owner's release could hand it to someone else while a thread of ours
            // can still read it.
            deferred.stale(va);
            deferred.keep(old);
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

impl<F: PageTableFormat, A: TableAlloc + Clone + Send + Sync> AddressSpace<F, A> {
    /// Maps a zeroed page at `page` (aligned) with `flags` plus `USER` and
    /// records it. Any page already recorded there is replaced.
    fn install_zeroed(&self, inner: &mut Inner<F, A>, page: u64, flags: MapFlags) -> Result<(), Errno> {
        let pa = self.alloc.alloc_table().ok_or(Errno::ENOMEM)?;
        // The frame frees itself if anything below fails, until the table takes it.
        let frame = OwnedFrame::claim(self.alloc.clone(), pa).ok_or(Errno::ENOMEM)?;
        let node = Page::new(pa, false).map_err(|_| Errno::ENOMEM)?;
        // SAFETY: a fresh frame, reachable through the allocator's mapping.
        unsafe { self.alloc.phys_to_virt(pa).write_bytes(0, PAGE_SIZE) };
        match inner.pt.map_owned(VirtAddr::new(page), frame, flags | MapFlags::USER) {
            // The space may be active here, and RISC-V may cache invalid entries.
            Ok(flush) => flush.flush(),
            Err((e, _frame)) => return Err(if e == MapError::OutOfMemory { Errno::ENOMEM } else { Errno::EINVAL }),
        }
        node.place(page);
        // A page that is not mapped has no node: see `unmap`.
        drop(inner.pages.take_key(&page));
        assert!(inner.pages.insert(node).is_ok(), "the page's slot was just emptied");
        Ok(())
    }

    /// Gives the pages of `map_lazy` areas in `va..va + len` that have no
    /// frame one, for a kernel copy that is about to go through the page
    /// table. Pages whose area does not allow the access are left, so the
    /// copy fails on them as it would on any unmapped page.
    fn populate(&self, inner: &mut Inner<F, A>, va: u64, len: usize, write: bool) -> Result<(), Errno> {
        let Some(end) = va.checked_add(len as u64) else { return Ok(()) };
        let first = va & !(PAGE - 1);
        let mut from = first;
        while let Some(area) = inner.vmas.first_overlap(from, end) {
            from = area.end;
            if !area.flags.contains(if write { MapFlags::WRITE } else { MapFlags::READ }) {
                continue;
            }
            for page in (area.start.max(first)..area.end.min(end)).step_by(PAGE_SIZE) {
                if inner.pages.find(&page).is_none() {
                    self.install_zeroed(inner, page, area.flags)?;
                }
            }
        }
        Ok(())
    }
}

impl<F: PageTableFormat + Send + Sync + 'static, A: TableAlloc + Clone + Send + Sync + 'static> AddressSpace<F, A> {
    /// Unmaps and frees the pages of `va..va + len`, and drops the file
    /// mappings there after writing back what shared ones hold. With
    /// `strict`, running out of memory to split a mapping fails the call
    /// before anything is changed; otherwise the pages go regardless.
    fn unmap_range(&self, va: u64, len: u64, strict: bool) -> Result<(), Errno> {
        let end = va.saturating_add(len);
        // Before the pages go: this is the last chance to save them.
        let saved = self.writeback(va, end);
        {
            let mut inner = self.inner.lock();
            if strict {
                inner.maps.carve(va, end, filemap::Edit::Remove)?;
            } else {
                inner.maps.remove(va, end);
            }
            inner.maps.clear_dirty(va, end);
            // Made first, so the areas can be cut without failing. If there is
            // no memory for it, the part of an area above the range is lost,
            // and its untouched pages will fault instead of appearing.
            let spare = if inner.vmas.needs_spare(va, end) { VmaSpare::new().ok() } else { None };
            inner.vmas.remove(va & !(PAGE - 1), end, spare);
        }
        let dropped = self.drop_pages(va, end);
        saved.and(dropped)
    }

    /// Unmaps and frees the pages in `va..end`, shooting down other CPUs.
    /// Fails, leaving the rest mapped, if there is no memory to hold the frames.
    fn drop_pages(&self, va: u64, end: u64) -> Result<(), Errno> {
        let mut from = va & !(PAGE - 1);
        loop {
            // Dropped after the lock: shoots down the other CPUs, then frees.
            let mut deferred = Deferred::<A>::new();
            let mut more = false;
            let mut result = Ok(());
            {
                let mut inner = self.inner.lock();
                let Inner { pt, pages, .. } = &mut *inner;
                // Every user page is one of ours, so visit those rather than each
                // page of a range that may span most of the address space.
                while let Some(at) = pages.lower_bound(&from).map(Page::va).filter(|&at| at < end) {
                    if deferred.full() {
                        more = true;
                        break;
                    }
                    if let Err(e) = deferred.reserve() {
                        result = Err(e);
                        break;
                    }
                    from = at + PAGE;
                    match pt.unmap_owned(VirtAddr::new(at)) {
                        // Flush this CPU now, so a thread preempted into this
                        // space here cannot use the page; the others follow
                        // once the lock is released.
                        Ok((frame, flush)) => {
                            flush.flush();
                            deferred.stale(at);
                            // The reference goes with the shootdown.
                            deferred.keep(frame);
                        }
                        // Mapped, yet it cannot be unmapped: leave it, and its frame.
                        Err(_) if pt.translate(VirtAddr::new(at)).is_some() => continue,
                        // Not mapped: nothing refers to the frame.
                        Err(_) => {}
                    }
                    drop(pages.take_key(&at));
                }
            }
            drop(deferred);
            result?;
            if !more {
                return Ok(());
            }
        }
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
        let mut pt = PageTable::new_owned(alloc.clone())?;
        // SAFETY: forwarded contract.
        unsafe { pt.share_root_entries(kernel, shared.clone()) };
        Ok(Self {
            root: pt.root(),
            alloc,
            shared,
            inner: IrqSpinLock::new(Inner {
                pt,
                pages: ArcTree::new(),
                maps: FileMaps::default(),
                vmas: VmaTree::new(),
            }),
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
        let mut inner = self.inner.lock();
        self.populate(&mut inner, va, buf.len(), false)?;
        walk(&inner.pt, va, buf.len(), MapFlags::READ, |src, off, n| {
            let to = buf.get_mut(off..off.saturating_add(n)).ok_or(Errno::EFAULT)?;
            // SAFETY: `src` points at `n` bytes of a user-readable frame.
            unsafe { core::ptr::copy_nonoverlapping(src, to.as_mut_ptr(), n) };
            Ok(())
        })
    }

    fn write(&self, va: u64, data: &[u8]) -> Result<(), Errno> {
        // Declared first so it is dropped (and the shootdown sent) after the lock.
        let mut deferred = Deferred::<A>::new();
        self.fault_in(va, data.len(), true)?;
        let mut inner = self.inner.lock();
        let end = va.checked_add(data.len() as u64).ok_or(Errno::EFAULT)?;
        self.populate(&mut inner, va, data.len(), true)?;
        let mut from = va & !(PAGE - 1);
        while from < end
            && let Some(page) = inner.pages.lower_bound(&from)
            && page.va() < end
        {
            let (at, cow) = (page.va(), page.is_cow());
            from = at + PAGE;
            if cow && !self.break_cow(&mut inner, at, &mut deferred) {
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
            self.install_zeroed(&mut inner, page, flags)?;
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
        self.load_elf_at(elf, 0)
    }

    fn load_elf_at(&self, elf: &Elf<'_>, bias: u64) -> Result<u64, Errno> {
        // The loader writes into any page already mapped, and the kernel's
        // are, through the shared root entries: keep every segment out of
        // them, and bound the total so loading cannot exhaust memory.
        let mut total = 0u64;
        elf.span_at(bias).ok_or(Errno::ENOEXEC)?;
        for seg in elf.segments_at(bias).filter(|s| s.mem_size != 0) {
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
        let loaded = elf.load_into_at(pt, MapFlags::USER, bias, || {
            let pa = self.alloc.alloc_table()?;
            // The frame frees itself if the loader then fails to map it.
            let frame = OwnedFrame::claim(self.alloc.clone(), pa)?;
            let node = Page::new(pa, false).ok()?;
            assert!(fresh.insert(node).is_ok(), "frames are distinct");
            Some(frame)
        });
        // Record where each new frame went, so `unmap` and `fork` find it,
        // even after a failure part-way.
        for seg in elf.segments_at(bias).filter(|s| s.mem_size != 0) {
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
        // What is left in `fresh` is for frames the loader failed to map,
        // which have been released already: the nodes only record addresses.
        drop(fresh);
        loaded.map_err(|e| if e == MapError::OutOfMemory { Errno::ENOMEM } else { Errno::ENOEXEC })?;
        // Every non-empty segment was checked to end inside the user half above.
        let end = elf.segments_at(bias).filter(|s| s.mem_size != 0).map(|s| s.vaddr.saturating_add(s.mem_size)).max();
        end.unwrap_or(0).checked_next_multiple_of(PAGE).ok_or(Errno::ENOEXEC)
    }

    fn fork(&self) -> Result<Arc<dyn UserMemory>, Errno> {
        // Making pages read-only flushes this CPU at once and the others
        // when `deferred` is dropped, after the lock (see `Deferred`).
        let mut deferred = Deferred::<A>::new();
        let mut guard = self.inner.lock();
        let Inner { pt: parent_pt, pages: parent_pages, maps: parent_maps, vmas: parent_vmas } = &mut *guard;
        let maps = parent_maps.try_clone()?;
        let vmas = parent_vmas.try_clone().map_err(|_| Errno::ENOMEM)?;
        let mut pt = PageTable::new_owned(self.alloc.clone()).map_err(|_| Errno::ENOMEM)?;
        // SAFETY: our shared root entries are the kernel's, which outlive
        // this space (see `new`) and so the copy, made under the same terms.
        unsafe { pt.share_root_entries(parent_pt, self.shared.clone()) };
        let child = Self {
            root: pt.root(),
            alloc: self.alloc.clone(),
            shared: self.shared.clone(),
            inner: IrqSpinLock::new(Inner { pt, pages: ArcTree::new(), maps, vmas }),
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
                    deferred.stale(page.va());
                    cow = true;
                    // Record it now, so if the child's map below fails the
                    // parent can still write the page (a lone share breaks
                    // COW in place).
                    page.set_cow(true);
                }
                // On failure, dropping `child` releases the pages shared so far.
                let node = Page::new(t.pa, cow).map_err(|_| Errno::ENOMEM)?;
                node.set_ro(page.is_ro());
                // The copy maps the same frame, through a reference of its own.
                let frame = parent_pt.share_owned(va).ok_or(Errno::ENOMEM)?;
                match copy.pt.map_owned(va, frame, flags) {
                    // The copy is not active anywhere yet.
                    Ok(flush) => flush.ignore(),
                    Err((e, _)) => return Err(if e == MapError::OutOfMemory { Errno::ENOMEM } else { Errno::EINVAL }),
                }
                node.place(page.va());
                assert!(copy.pages.insert(node).is_ok(), "a new space has no pages yet");
            }
        }
        let child: Arc<dyn UserMemory> = try_arc(child).map_err(|_| Errno::ENOMEM)?;
        Ok(child)
    }

    fn cow_fault(&self, va: u64) -> bool {
        let va = va & !(PAGE - 1);
        // Declared first so it is dropped (and the shootdown sent) after the lock.
        let mut deferred = Deferred::<A>::new();
        let mut inner = self.inner.lock();
        self.break_cow(&mut inner, va, &mut deferred)
    }

    fn stale_fault(&self, va: u64) -> bool {
        let va = va & !(PAGE - 1);
        let writable = self
            .inner
            .lock()
            .pt
            .translate(VirtAddr::new(va))
            .is_some_and(|t| t.flags.contains(MapFlags::WRITE | MapFlags::USER));
        if writable {
            osmium_arch::mmu::flush_page(va as usize);
        }
        writable
    }

    fn map_lazy(&self, va: u64, len: u64, flags: MapFlags) -> Result<(), Errno> {
        if !va.is_multiple_of(PAGE) || !len.is_multiple_of(PAGE) {
            return Err(Errno::EINVAL);
        }
        let end = va.checked_add(len).ok_or(Errno::EINVAL)?;
        if !self.is_user_range(va, end) {
            return Err(Errno::EINVAL);
        }
        let mut inner = self.inner.lock();
        if inner.pages.lower_bound(&va).is_some_and(|p| p.va() < end) {
            return Err(Errno::EINVAL);
        }
        inner
            .vmas
            .insert(va, end, flags)
            .map_err(|e| if e == VmaError::OutOfMemory { Errno::ENOMEM } else { Errno::EINVAL })
    }

    fn page_fault(&self, va: u64, write: bool) -> bool {
        let page = va & !(PAGE - 1);
        if self.inner.lock().maps.find(page).is_some() {
            // A file mapping: a private page that is shared by `fork` is copied
            // as any is; otherwise the page is loaded, or a clean shared page
            // made writable, which reads the file without the lock.
            return write && self.cow_fault(va) || self.file_fault_impl(va, write);
        }
        // Declared first so it is dropped (and the shootdown sent) after the lock.
        let mut deferred = Deferred::<A>::new();
        let mut inner = self.inner.lock();
        if inner.pages.find(&page).is_some() {
            // Already has a frame: only a write to a shared one is ours to fix.
            return write && self.break_cow(&mut inner, page, &mut deferred);
        }
        let Some(area) = inner.vmas.find(page) else { return false };
        // A read or fetch may use any readable or executable area.
        let allowed = if write {
            area.flags.contains(MapFlags::WRITE)
        } else {
            area.flags.contains(MapFlags::READ) || area.flags.contains(MapFlags::EXEC)
        };
        allowed && self.install_zeroed(&mut inner, page, area.flags).is_ok()
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

/// Most pages one [`Deferred`] holds back.
const BATCH: usize = 32;

/// What a page-table change leaves to do once the space's lock is released.
///
/// Page-table writes flush the TLB of the CPU that makes them, under the
/// lock. The process's threads may be running on other CPUs, though, with
/// stale entries; dropping the `Deferred` shoots those down
/// ([`osmium_arch::mmu::flush_remote`]) and only then frees the frames the
/// changes released. The shootdown must not run under the space's lock: a
/// CPU waiting for that lock with interrupts off could never acknowledge it.
/// So declare a `Deferred` before the guard it accompanies, which drops it
/// after the guard.
struct Deferred<A: TableAlloc> {
    /// The lowest and highest pages whose mappings changed.
    stale: Option<(u64, u64)>,
    /// References to frames that are no longer mapped here, released with this.
    frames: Vec<OwnedFrame<A>>,
}

impl<A: TableAlloc> Deferred<A> {
    fn new() -> Self {
        Self { stale: None, frames: Vec::new() }
    }

    /// Whether a batch is full: drop it before unmapping more, so that its
    /// shootdown and frees stay bounded.
    fn full(&self) -> bool {
        self.frames.len() >= BATCH
    }

    /// Notes that the mapping of the page at `va` changed.
    fn stale(&mut self, va: u64) {
        self.stale = Some(match self.stale {
            Some((lo, hi)) => (lo.min(va), hi.max(va)),
            None => (va, va),
        });
    }

    /// Makes room for one more frame, so that [`Deferred::keep`] does not
    /// allocate. Fails only when out of memory.
    fn reserve(&mut self) -> Result<(), Errno> {
        self.frames.try_reserve(1).map_err(|_| Errno::ENOMEM)
    }

    /// Holds a reference to a frame that is no longer mapped here until the
    /// shootdown is done. Call [`Deferred::reserve`] first.
    fn keep(&mut self, frame: OwnedFrame<A>) {
        self.frames.push(frame);
    }
}

impl<A: TableAlloc> Drop for Deferred<A> {
    fn drop(&mut self) {
        if let Some((lo, hi)) = self.stale {
            osmium_arch::mmu::flush_remote(lo as usize, ((hi - lo) / PAGE) as usize + 1);
        }
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
