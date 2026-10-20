//! User address spaces.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
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
    /// A copy of this space for `fork`: the same kernel mappings, and a
    /// fresh copy of every page this space owns, with the same permissions.
    fn fork(&self) -> Result<Box<dyn UserMemory>, Errno>;
}

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
    /// The pages this space allocated, by user address, freed with it.
    frames: BTreeMap<u64, PhysAddr>,
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
        Ok(Self { root: pt.root(), alloc, shared, inner: IrqSpinLock::new(Inner { pt, frames: BTreeMap::new() }) })
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
        let inner = self.inner.lock();
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
            if inner.frames.remove(&page) == Some(t.pa) {
                // SAFETY: our own frame, no longer mapped. A process is
                // single-threaded, so no other CPU holds a stale TLB entry.
                unsafe { self.alloc.free_table(t.pa) };
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
        let Inner { pt, frames } = &mut *inner;
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
        let inner = self.inner.lock();
        let mut pt = PageTable::new(self.alloc.clone()).map_err(|_| Errno::ENOMEM)?;
        // SAFETY: our shared root entries are the kernel's, which outlive
        // this space (see `new`) and so the copy, made under the same terms.
        unsafe { pt.share_root_entries(&inner.pt, self.shared.clone()) };
        let child = Self {
            root: pt.root(),
            alloc: self.alloc.clone(),
            shared: self.shared.clone(),
            inner: IrqSpinLock::new(Inner { pt, frames: BTreeMap::new() }),
        };
        {
            let mut copy = child.inner.lock();
            for (&va, &pa) in &inner.frames {
                let t = inner.pt.translate(VirtAddr::new(va)).expect("owned pages stay mapped");
                // On failure, dropping `child` frees the pages copied so far.
                let new = self.alloc.alloc_table().ok_or(Errno::ENOMEM)?;
                let dst = self.alloc.phys_to_virt(new);
                // SAFETY: both are whole frames reached through the
                // allocator's mapping; `new` is fresh and exclusively ours.
                unsafe { core::ptr::copy_nonoverlapping(self.alloc.phys_to_virt(pa), dst, PAGE_SIZE) };
                match copy.pt.map(VirtAddr::new(va), new, PageSize::Size4K, t.flags) {
                    // The copy is not active anywhere yet.
                    Ok(flush) => flush.ignore(),
                    Err(e) => {
                        // SAFETY: the frame was never mapped.
                        unsafe { self.alloc.free_table(new) };
                        return Err(if e == MapError::OutOfMemory { Errno::ENOMEM } else { Errno::EINVAL });
                    }
                }
                copy.frames.insert(va, new);
                if t.flags.contains(MapFlags::EXEC) {
                    sync_icache(dst);
                }
            }
        }
        Ok(Box::new(child))
    }
}

impl<F: PageTableFormat, A: TableAlloc + Clone> Drop for AddressSpace<F, A> {
    fn drop(&mut self) {
        for &pa in self.inner.get_mut().frames.values() {
            // SAFETY: our own frames; the table mapping them is inactive (see
            // the type's documentation) and dropped with us.
            unsafe { self.alloc.free_table(pa) };
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
