//! User address spaces.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use core::ops::Range;

use osmium_boot::elf::Elf;
use osmium_mm::addr::{PAGE_SIZE, PhysAddr, VirtAddr};
use osmium_mm::paging::{MapError, MapFlags, PageSize, PageTable, PageTableFormat, TableAlloc};
use osmium_sync::IrqSpinLock;

use osmium_fs::Errno;

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
    fn fork(&self) -> Result<Box<dyn UserMemory>, Errno>;
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
}

/// Reference counts of the frames that forked spaces share. A frame that is
/// absent has one owner. Spaces only ever share frames with their forks, so
/// each family of spaces has its own table.
type Shares = Arc<IrqSpinLock<BTreeMap<PhysAddr, u32>>>;

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
    /// The frames shared with forked relatives.
    shares: Shares,
    inner: IrqSpinLock<Inner<F, A>>,
}

struct Inner<F: PageTableFormat, A: TableAlloc> {
    pt: PageTable<F, A>,
    /// The pages this space allocated, by user address, freed with it.
    frames: BTreeMap<u64, PhysAddr>,
    /// Pages that were writable when a fork made them read-only: a write
    /// fault copies them, or makes them writable again if no one shares them.
    cow: BTreeSet<u64>,
}

impl<F: PageTableFormat, A: TableAlloc + Clone> AddressSpace<F, A> {
    /// Drops this space's reference to `pa`, freeing it if it was the last.
    fn release(&self, pa: PhysAddr) {
        let mut shares = self.shares.lock();
        match shares.get_mut(&pa) {
            Some(n) => {
                *n -= 1;
                if *n <= 1 {
                    shares.remove(&pa);
                }
            }
            // SAFETY: the last owner's frame, no longer mapped by anyone.
            None => unsafe { self.alloc.free_table(pa) },
        }
    }

    /// Gives the copy-on-write page at `page` (page-aligned) its own writable
    /// frame. Returns false if it is not one, or memory ran out.
    fn break_cow(&self, inner: &mut Inner<F, A>, page: u64) -> bool {
        if !inner.cow.contains(&page) {
            return false;
        }
        let va = VirtAddr::new(page);
        let Some(t) = inner.pt.translate(va) else { return false };
        let flags = t.flags | MapFlags::WRITE;
        let mut shares = self.shares.lock();
        if shares.get(&t.pa).is_some_and(|&n| n > 1) {
            let Some(new) = self.alloc.alloc_table() else { return false };
            // SAFETY: both are whole frames reached through the allocator's
            // mapping; `new` is fresh and exclusively ours.
            unsafe {
                core::ptr::copy_nonoverlapping(self.alloc.phys_to_virt(t.pa), self.alloc.phys_to_virt(new), PAGE_SIZE)
            };
            let Ok((_, flush)) = inner.pt.unmap(va) else {
                // SAFETY: never mapped.
                unsafe { self.alloc.free_table(new) };
                return false;
            };
            flush.flush();
            match inner.pt.map(va, new, PageSize::Size4K, flags) {
                Ok(flush) => flush.flush(),
                Err(_) => {
                    // SAFETY: never mapped.
                    unsafe { self.alloc.free_table(new) };
                    if let Ok(flush) = inner.pt.map(va, t.pa, PageSize::Size4K, t.flags) {
                        flush.flush();
                    }
                    return false;
                }
            }
            if let Some(n) = shares.get_mut(&t.pa) {
                *n -= 1;
                if *n <= 1 {
                    shares.remove(&t.pa);
                }
            }
            inner.frames.insert(page, new);
            if flags.contains(MapFlags::EXEC) {
                sync_icache(self.alloc.phys_to_virt(new));
            }
        } else {
            shares.remove(&t.pa);
            match inner.pt.protect(va, flags) {
                Ok(flush) => flush.flush(),
                Err(_) => return false,
            }
        }
        inner.cow.remove(&page);
        true
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
            shares: Arc::default(),
            inner: IrqSpinLock::new(Inner { pt, frames: BTreeMap::new(), cow: BTreeSet::new() }),
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
        let len = (code.len() as u64).next_multiple_of(PAGE).max(PAGE);
        self.map_anon(va, len, flags).map_err(|_| MapError::OutOfMemory)?;
        let inner = self.inner.lock();
        // Check no permission: the code may be mapped read-only.
        walk(&inner.pt, va, code.len(), MapFlags::NONE, |dst, off, n| {
            // SAFETY: `dst` points at `n` bytes of a frame this space owns.
            unsafe { core::ptr::copy_nonoverlapping(code[off..].as_ptr(), dst, n) }
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
        let inner = self.inner.lock();
        walk(&inner.pt, va, buf.len(), MapFlags::READ, |src, off, n| {
            // SAFETY: `src` points at `n` bytes of a user-readable frame.
            unsafe { core::ptr::copy_nonoverlapping(src, buf[off..].as_mut_ptr(), n) }
        })
    }

    fn write(&self, va: u64, data: &[u8]) -> Result<(), Errno> {
        let mut inner = self.inner.lock();
        let end = va.checked_add(data.len() as u64).ok_or(Errno::EFAULT)?;
        let mut from = va & !(PAGE - 1);
        while from < end
            && let Some(&page) = inner.cow.range(from..end).next()
        {
            from = page + PAGE;
            if !self.break_cow(&mut inner, page) {
                return Err(Errno::EFAULT);
            }
        }
        walk(&inner.pt, va, data.len(), MapFlags::WRITE, |dst, off, n| {
            // SAFETY: `dst` points at `n` bytes of a user-writable frame.
            unsafe { core::ptr::copy_nonoverlapping(data[off..].as_ptr(), dst, n) }
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
            // SAFETY: a fresh frame, reachable through the allocator's mapping.
            unsafe { self.alloc.phys_to_virt(pa).write_bytes(0, PAGE_SIZE) };
            match inner.pt.map(VirtAddr::new(page), pa, PageSize::Size4K, flags | MapFlags::USER) {
                // The space may be active here, and RISC-V may cache invalid entries.
                Ok(flush) => flush.flush(),
                Err(e) => {
                    // SAFETY: the frame was never mapped.
                    unsafe { self.alloc.free_table(pa) };
                    return Err(if e == MapError::OutOfMemory { Errno::ENOMEM } else { Errno::EINVAL });
                }
            }
            inner.frames.insert(page, pa);
        }
        Ok(())
    }

    fn unmap(&self, va: u64, len: u64) {
        let end = va.saturating_add(len);
        let mut inner = self.inner.lock();
        // Every user page is one of ours, so visit those rather than each
        // page of a range that may span most of the address space.
        let mut from = va & !(PAGE - 1);
        while let Some((&page, _)) = inner.frames.range(from..end).next() {
            from = page + PAGE;
            let Ok((t, flush)) = inner.pt.unmap(VirtAddr::new(page)) else { continue };
            flush.flush();
            inner.cow.remove(&page);
            if inner.frames.remove(&page) == Some(t.pa) {
                // A process is single-threaded, so no other CPU holds a stale
                // TLB entry for the page.
                self.release(t.pa);
            }
        }
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
        let Inner { pt, frames, .. } = &mut *inner;
        let mut fresh = BTreeSet::new();
        let loaded = elf.load_into(pt, MapFlags::USER, || {
            let pa = self.alloc.alloc_table()?;
            fresh.insert(pa);
            Some(pa)
        });
        // Record where each new frame went, so `unmap` and `fork` find it,
        // even after a failure part-way.
        for seg in elf.segments() {
            let end = seg.vaddr.saturating_add(seg.mem_size);
            for page in (seg.vaddr & !(PAGE - 1)..end).step_by(PAGE_SIZE) {
                let Some(t) = pt.translate(VirtAddr::new(page)) else { continue };
                if fresh.remove(&t.pa) {
                    frames.insert(page, t.pa);
                }
                if t.flags.contains(MapFlags::EXEC) {
                    sync_icache(pt.allocator().phys_to_virt(t.pa));
                }
            }
        }
        for pa in fresh {
            // SAFETY: allocated for a page the loader then failed to map.
            unsafe { self.alloc.free_table(pa) };
        }
        loaded.map_err(|e| if e == MapError::OutOfMemory { Errno::ENOMEM } else { Errno::ENOEXEC })?;
        let end = elf.segments().map(|s| s.vaddr.saturating_add(s.mem_size)).max().unwrap_or(0);
        Ok(end.next_multiple_of(PAGE))
    }

    fn fork(&self) -> Result<Box<dyn UserMemory>, Errno> {
        let mut guard = self.inner.lock();
        let inner = &mut *guard;
        let mut pt = PageTable::new(self.alloc.clone()).map_err(|_| Errno::ENOMEM)?;
        // SAFETY: our shared root entries are the kernel's, which outlive
        // this space (see `new`) and so the copy, made under the same terms.
        unsafe { pt.share_root_entries(&inner.pt, self.shared.clone()) };
        let child = Self {
            root: pt.root(),
            alloc: self.alloc.clone(),
            shared: self.shared.clone(),
            shares: self.shares.clone(),
            inner: IrqSpinLock::new(Inner { pt, frames: BTreeMap::new(), cow: BTreeSet::new() }),
        };
        {
            let mut copy = child.inner.lock();
            for (&va, &pa) in &inner.frames {
                let v = VirtAddr::new(va);
                let t = inner.pt.translate(v).expect("owned pages stay mapped");
                let mut flags = t.flags;
                let mut cow = inner.cow.contains(&va);
                if flags.contains(MapFlags::WRITE) {
                    flags = flags.difference(MapFlags::WRITE);
                    if !flags.contains(MapFlags::READ) && !flags.contains(MapFlags::EXEC) {
                        flags = flags | MapFlags::READ;
                    }
                    // The parent may be running on this table.
                    inner.pt.protect(v, flags).map_err(|_| Errno::EINVAL)?.flush();
                    cow = true;
                }
                // On failure, dropping `child` releases the pages shared so far.
                match copy.pt.map(v, pa, PageSize::Size4K, flags) {
                    // The copy is not active anywhere yet.
                    Ok(flush) => flush.ignore(),
                    Err(e) => return Err(if e == MapError::OutOfMemory { Errno::ENOMEM } else { Errno::EINVAL }),
                }
                *self.shares.lock().entry(pa).or_insert(1) += 1;
                copy.frames.insert(va, pa);
                if cow {
                    inner.cow.insert(va);
                    copy.cow.insert(va);
                }
            }
        }
        Ok(Box::new(child))
    }

    fn cow_fault(&self, va: u64) -> bool {
        let mut inner = self.inner.lock();
        self.break_cow(&mut inner, va & !(PAGE - 1))
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

impl<F: PageTableFormat, A: TableAlloc + Clone> Drop for AddressSpace<F, A> {
    fn drop(&mut self) {
        // The table mapping the frames is inactive (see the type's
        // documentation) and dropped with us.
        for pa in core::mem::take(&mut self.inner.get_mut().frames).into_values() {
            self.release(pa);
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
    mut f: impl FnMut(*mut u8, usize, usize),
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
        f(pt.allocator().phys_to_virt(t.pa), off, n);
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
