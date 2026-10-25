//! File-backed memory: `mmap` of a file, private or shared, and the
//! reservations `PROT_NONE` makes.
//!
//! # Model
//!
//! `mmap` records a mapping ([`Vma`]) and loads nothing. A page is read from
//! the file when it is first touched: the trap handler passes the fault to
//! [`UserMemory::file_fault`], and copies the kernel makes to or from user
//! memory fault pages in themselves.
//!
//! - **Private** (`MAP_PRIVATE`): the page is a copy of the file's bytes at
//!   the time of the first touch, owned by the space. Writes change only the
//!   copy and never reach the file. `fork` shares the copy copy-on-write like
//!   any other private page.
//! - **Shared** (`MAP_SHARED`): there is no page cache across unrelated
//!   spaces. Each space loads its own copy and writes it back. To know what
//!   to write, a page of a writable shared mapping is first mapped read-only;
//!   the first write faults, records the page as dirty and makes it writable.
//!   `msync`, `munmap` and the end of the process write the dirty pages back
//!   and map them read-only again. `fork` shares the frames themselves
//!   (without copy-on-write), so a parent and its children see each other's
//!   stores at once.
//!
//! Pages wholly past the end of the file fault (Linux would send `SIGBUS`),
//! and writing back never extends the file.
//!
//! # Locking
//!
//! The table of mappings lives in the space's [`Inner`], under its lock, so
//! a page table and the mappings that explain it change together. File I/O
//! never happens under that lock: faults and write-backs copy what they need
//! out, do the I/O, and take the lock again to check that nothing changed.

use alloc::sync::Arc;
use alloc::vec::Vec;

use osmium_fs::{Errno, File};
use osmium_mm::addr::{PAGE_SIZE, VirtAddr};
use osmium_mm::frame::OwnedFrame;
use osmium_mm::paging::{MapFlags, PageTableFormat, TableAlloc};

use super::{AddressSpace, Deferred, Inner, PAGE, Page, sync_icache};

/// What `mmap` asks of the space for a file.
#[derive(Clone)]
pub struct FileMapping {
    /// The file.
    pub file: Arc<dyn File>,
    /// Where in the file the mapping starts (page-aligned).
    pub offset: u64,
    /// `MAP_SHARED`: stores reach the file. Otherwise `MAP_PRIVATE`.
    pub shared: bool,
    /// The access: some of `READ`, `WRITE` and `EXEC`.
    pub prot: MapFlags,
    /// Whether the file was opened for writing, which a shared mapping
    /// needs before it may ever be writable.
    pub writable: bool,
}

/// One mapping: `start..end`, from `off` in the file (none for a reservation,
/// which is zero-filled).
#[derive(Clone)]
pub(super) struct Vma {
    id: u64,
    start: u64,
    end: u64,
    file: Option<Arc<dyn File>>,
    off: u64,
    shared: bool,
    prot: MapFlags,
    writable: bool,
}

impl Vma {
    pub(super) fn prot(&self) -> MapFlags {
        self.prot
    }

    pub(super) fn shared(&self) -> bool {
        self.shared
    }

    /// The part `start..end` of it.
    fn piece(&self, start: u64, end: u64) -> Self {
        Self { start, end, off: self.off.saturating_add(start.saturating_sub(self.start)), ..self.clone() }
    }
}

/// What [`FileMaps::carve`] does to the part it cuts out.
pub(super) enum Edit {
    /// Drops it.
    Remove,
    /// Gives it this access.
    Prot(MapFlags),
}

/// The mappings of a space, by address, and the dirty pages of the shared ones.
#[derive(Default)]
pub(super) struct FileMaps {
    vmas: Vec<Vma>,
    /// Page addresses, sorted.
    dirty: Vec<u64>,
    next_id: u64,
}

impl FileMaps {
    fn is_empty(&self) -> bool {
        self.vmas.is_empty()
    }

    /// The mapping that holds `va`.
    pub(super) fn find(&self, va: u64) -> Option<&Vma> {
        let i = self.vmas.partition_point(|v| v.end <= va);
        self.vmas.get(i).filter(|v| v.start <= va)
    }

    /// The mappings that overlap `from..to`.
    fn overlapping(&self, from: u64, to: u64) -> impl Iterator<Item = &Vma> {
        let i = self.vmas.partition_point(|v| v.end <= from);
        self.vmas.iter().skip(i).take_while(move |v| v.start < to)
    }

    fn insert(&mut self, vma: Vma) -> Result<(), Errno> {
        self.vmas.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
        let i = self.vmas.partition_point(|v| v.start < vma.start);
        self.vmas.insert(i, vma);
        Ok(())
    }

    /// Edits the part of the mappings in `from..to`, splitting those that
    /// stick out. Changes nothing if memory runs out.
    pub(super) fn carve(&mut self, from: u64, to: u64, edit: Edit) -> Result<(), Errno> {
        if self.overlapping(from, to).next().is_none() {
            return Ok(());
        }
        let mut out = Vec::new();
        // Only the first and the last mapping can stick out, adding one each.
        out.try_reserve_exact(self.vmas.len().saturating_add(2)).map_err(|_| Errno::ENOMEM)?;
        for v in self.vmas.drain(..) {
            if v.end <= from || v.start >= to {
                out.push(v);
                continue;
            }
            if v.start < from {
                out.push(v.piece(v.start, from));
            }
            if let Edit::Prot(prot) = edit {
                let mut mid = v.piece(v.start.max(from), v.end.min(to));
                mid.prot = prot;
                out.push(mid);
            }
            if v.end > to {
                out.push(v.piece(to, v.end));
            }
        }
        self.vmas = out;
        Ok(())
    }

    /// [`carve`](Self::carve) with `Edit::Remove` that cannot fail: if memory
    /// runs out where a mapping would split in two, the part after the hole
    /// is dropped too.
    pub(super) fn remove(&mut self, from: u64, to: u64) {
        if self.carve(from, to, Edit::Remove).is_ok() {
            return;
        }
        self.vmas.retain_mut(|v| {
            if v.end <= from || v.start >= to {
                true
            } else if v.start >= from && v.end <= to {
                false
            } else if v.start < from {
                v.end = from;
                true
            } else {
                *v = v.piece(to, v.end);
                true
            }
        });
    }

    fn is_dirty(&self, page: u64) -> bool {
        self.dirty.binary_search(&page).is_ok()
    }

    fn mark_dirty(&mut self, page: u64) -> Result<(), Errno> {
        if let Err(i) = self.dirty.binary_search(&page) {
            self.dirty.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
            self.dirty.insert(i, page);
        }
        Ok(())
    }

    /// The dirty pages in `from..to`.
    fn dirty_in(&self, from: u64, to: u64) -> &[u64] {
        let lo = self.dirty.partition_point(|&d| d < from);
        let hi = self.dirty.partition_point(|&d| d < to);
        self.dirty.get(lo..hi).unwrap_or(&[])
    }

    pub(super) fn clear_dirty(&mut self, from: u64, to: u64) {
        let lo = self.dirty.partition_point(|&d| d < from);
        let hi = self.dirty.partition_point(|&d| d < to);
        self.dirty.drain(lo..hi.max(lo));
    }

    pub(super) fn try_clone(&self) -> Result<Self, Errno> {
        let (mut vmas, mut dirty) = (Vec::new(), Vec::new());
        vmas.try_reserve_exact(self.vmas.len()).map_err(|_| Errno::ENOMEM)?;
        dirty.try_reserve_exact(self.dirty.len()).map_err(|_| Errno::ENOMEM)?;
        vmas.extend(self.vmas.iter().cloned());
        dirty.extend_from_slice(&self.dirty);
        Ok(Self { vmas, dirty, next_id: self.next_id })
    }

    fn add(
        &mut self,
        start: u64,
        end: u64,
        file: Option<(Arc<dyn File>, u64)>,
        shared: bool,
        prot: MapFlags,
        writable: bool,
    ) -> Result<(), Errno> {
        if self.overlapping(start, end).next().is_some() {
            return Err(Errno::EINVAL);
        }
        let id = self.next_id;
        self.next_id = id.wrapping_add(1);
        let (file, off) = match file {
            Some((f, off)) => (Some(f), off),
            None => (None, 0),
        };
        self.insert(Vma { id, start, end, file, off, shared, prot, writable })
    }
}

/// A dirty page being written back.
struct Job<A: TableAlloc> {
    file: Arc<dyn File>,
    /// Where in the file.
    off: u64,
    va: u64,
    /// A reference to the frame, so the write does not race with its unmapping.
    frame: OwnedFrame<A>,
}

impl<F: PageTableFormat + Send + Sync + 'static, A: TableAlloc + Clone + Send + Sync + 'static> AddressSpace<F, A> {
    pub(super) fn map_file_impl(&self, va: u64, len: u64, map: FileMapping) -> Result<(), Errno> {
        let end = va.checked_add(len).ok_or(Errno::EINVAL)?;
        // The part of the file the mapping covers must be addressable too.
        map.offset.checked_add(len).ok_or(Errno::EOVERFLOW)?;
        if !va.is_multiple_of(PAGE) || !len.is_multiple_of(PAGE) || !map.offset.is_multiple_of(PAGE) || len == 0 {
            return Err(Errno::EINVAL);
        }
        let prot = map.prot.difference(MapFlags::USER);
        let writable = map.writable;
        self.inner.lock().maps.add(va, end, Some((map.file, map.offset)), map.shared, prot, writable)
    }

    /// Makes the pages a kernel copy of `va..va + len` will touch present
    /// (and, for a store, writable), loading them from their files.
    pub(super) fn fault_in(&self, va: u64, len: usize, write: bool) -> Result<(), Errno> {
        if len == 0 {
            return Ok(());
        }
        let end = va.checked_add(len as u64).ok_or(Errno::EFAULT)?;
        if self.inner.lock().maps.is_empty() {
            return Ok(());
        }
        let mut page = va & !(PAGE - 1);
        while page < end {
            if self.needs_fault(page, write) && !self.file_fault_impl(page, write) {
                return Err(Errno::EFAULT);
            }
            page = match page.checked_add(PAGE) {
                Some(next) => next,
                None => break,
            };
        }
        Ok(())
    }

    /// Whether `page` is in a mapping and a copy to or from it would fault.
    fn needs_fault(&self, page: u64, write: bool) -> bool {
        let inner = self.inner.lock();
        let Some(v) = inner.maps.find(page) else { return false };
        match inner.pt.translate(VirtAddr::new(page)) {
            None => true,
            Some(t) => write && v.shared && !t.flags.contains(MapFlags::WRITE),
        }
    }

    pub(super) fn file_fault_impl(&self, va: u64, write: bool) -> bool {
        let page = va & !(PAGE - 1);
        let vaddr = VirtAddr::new(page);
        // What is needed to load the page, copied out of the lock.
        let (id, file, off) = {
            let mut guard = self.inner.lock();
            let Inner { pt, maps, .. } = &mut *guard;
            let Some(v) = maps.find(page) else { return false };
            let ok = if write {
                v.prot.contains(MapFlags::WRITE)
            } else {
                v.prot.contains(MapFlags::READ) || v.prot.contains(MapFlags::EXEC)
            };
            if !ok {
                return false;
            }
            let (id, shared, file, off) = (v.id, v.shared, v.file.clone(), v.off.saturating_add(page - v.start));
            if let Some(t) = pt.translate(vaddr) {
                // Present: only the first store to a clean shared page is ours.
                if !(write && shared) || t.flags.contains(MapFlags::WRITE) {
                    return false;
                }
                if maps.mark_dirty(page).is_err() {
                    return false;
                }
                return match pt.protect(vaddr, t.flags | MapFlags::WRITE) {
                    Ok(flush) => {
                        flush.flush();
                        true
                    }
                    Err(_) => false,
                };
            }
            (id, file, off)
        };

        let Some(pa) = self.alloc.alloc_table() else { return false };
        // The frame frees itself on every path out, until the table takes it.
        let Some(frame) = OwnedFrame::claim(self.alloc.clone(), pa) else { return false };
        let Ok(node) = Page::new(pa, false) else { return false };
        // SAFETY: a fresh whole frame, reachable through the allocator's
        // mapping, that nothing else refers to yet.
        let buf = unsafe { core::slice::from_raw_parts_mut(self.alloc.phys_to_virt(pa), PAGE_SIZE) };
        buf.fill(0);
        if let Some(file) = &file {
            let Ok(stat) = file.try_stat() else { return false };
            if off >= stat.size {
                // Wholly past the end.
                return false;
            }
            let n = (stat.size - off).min(PAGE) as usize;
            let mut got = 0;
            while got < n {
                let Some(dst) = buf.get_mut(got..n) else { break };
                match file.read(off + got as u64, dst) {
                    Ok(0) => break,
                    Ok(k) => got += k,
                    Err(_) => return false,
                }
            }
        }

        let mut guard = self.inner.lock();
        let Inner { pt, pages, maps, .. } = &mut *guard;
        // Unmapped, or mapped again as something else, while the lock was off.
        let Some(v) = maps.find(page).filter(|v| v.id == id) else { return false };
        let (shared, prot) = (v.shared, v.prot);
        if pt.translate(vaddr).is_some() {
            // Another thread of the process loaded it first.
            return true;
        }
        let mut flags = prot;
        if shared {
            if write {
                if maps.mark_dirty(page).is_err() {
                    return false;
                }
            } else {
                flags = flags.difference(MapFlags::WRITE);
            }
        }
        if !flags.contains(MapFlags::WRITE) && !flags.contains(MapFlags::READ) && !flags.contains(MapFlags::EXEC) {
            return false;
        }
        match pt.map_owned(vaddr, frame, flags | MapFlags::USER) {
            Ok(flush) => flush.flush(),
            Err(_) => return false,
        }
        node.place(page);
        // A page that is not mapped has no node: see `unmap`.
        drop(pages.take_key(&page));
        if pages.insert(node).is_err() {
            return false;
        }
        if flags.contains(MapFlags::EXEC) {
            sync_icache(self.alloc.phys_to_virt(pa));
        }
        true
    }

    /// Whether anything is mapped in `from..to`, by a file mapping or a page.
    fn anything_in(inner: &Inner<F, A>, from: u64, to: u64) -> bool {
        inner.maps.overlapping(from, to).next().is_some()
            || inner.vmas.overlaps(from, to)
            || inner.pages.lower_bound(&from).is_some_and(|p| p.va() < to)
    }

    pub(super) fn mprotect_impl(&self, va: u64, len: u64, prot: MapFlags) -> Result<(), Errno> {
        let end = va.checked_add(len).ok_or(Errno::ENOMEM)?;
        if !va.is_multiple_of(PAGE) || !len.is_multiple_of(PAGE) {
            return Err(Errno::EINVAL);
        }
        if len == 0 {
            return Ok(());
        }
        // Dropping pages loses what private ones hold, so those cannot lose
        // all access; shared ones are saved first.
        let none = prot == MapFlags::NONE;
        if none {
            self.writeback(va, end)?;
        }
        {
            // Declared first so it is dropped (and the shootdown sent) after the lock.
            let mut deferred = Deferred::<A>::new();
            let mut guard = self.inner.lock();
            if !Self::anything_in(&guard, va, end) {
                return Err(Errno::ENOMEM);
            }
            let Inner { pt, pages, maps, vmas } = &mut *guard;
            for v in maps.overlapping(va, end) {
                if v.shared && prot.contains(MapFlags::WRITE) && !v.writable {
                    return Err(Errno::EACCES);
                }
            }
            if none {
                let mut from = va;
                while let Some(at) = pages.lower_bound(&from).map(Page::va).filter(|&a| a < end) {
                    from = at + PAGE;
                    if !maps.find(at).is_some_and(|v| v.shared) {
                        return Err(Errno::EINVAL);
                    }
                }
            }
            // Areas of lazy anonymous memory take the new access too, so pages
            // that appear later get it. Each piece is atomic; running out of
            // memory part-way leaves the earlier ones changed.
            let mut at = va;
            while let Some(v) = vmas.first_overlap(at, end) {
                at = v.end;
                vmas.protect(v.start.max(va), v.end.min(end), prot).map_err(|_| Errno::ENOMEM)?;
            }
            maps.carve(va, end, Edit::Prot(prot))?;
            if none {
                maps.clear_dirty(va, end);
            } else {
                let mut from = va;
                while let Some(at) = pages.lower_bound(&from).map(Page::va).filter(|&a| a < end) {
                    from = at + PAGE;
                    let mut flags = prot;
                    let cow = pages.find(&at).is_some_and(|p| p.is_cow());
                    let clean = maps.find(at).is_some_and(|v| v.shared) && !maps.is_dirty(at);
                    // A copy-on-write page gets its write access back by faulting,
                    // and a clean shared page by being written to.
                    if cow || clean {
                        flags = flags.difference(MapFlags::WRITE);
                    }
                    if let Ok(flush) = pt.protect(VirtAddr::new(at), flags | MapFlags::USER) {
                        flush.flush();
                        deferred.stale(at);
                    }
                }
            }
        }
        if none {
            // Every page left is shared and was saved above; they reload on a later grant.
            self.drop_pages(va, end)?;
        }
        Ok(())
    }

    pub(super) fn msync_impl(&self, va: u64, len: u64, sync: bool) -> Result<(), Errno> {
        let end = va.checked_add(len).ok_or(Errno::ENOMEM)?;
        let mut files: Vec<Arc<dyn File>> = Vec::new();
        {
            let inner = self.inner.lock();
            if !Self::anything_in(&inner, va, end) {
                return Err(Errno::ENOMEM);
            }
            if sync {
                for v in inner.maps.overlapping(va, end).filter(|v| v.shared) {
                    let Some(f) = &v.file else { continue };
                    if !files.iter().any(|g| Arc::ptr_eq(f, g)) {
                        files.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
                        files.push(f.clone());
                    }
                }
            }
        }
        self.writeback(va, end)?;
        for f in &files {
            f.sync()?;
        }
        Ok(())
    }

    /// Writes the dirty pages of shared mappings in `from..to` to their
    /// files, and maps them read-only again to find the next stores. A page
    /// that cannot be written stays dirty. Returns the first error.
    pub(super) fn writeback(&self, from: u64, to: u64) -> Result<(), Errno> {
        let mut jobs: Vec<Job<A>> = Vec::new();
        {
            // Declared first so it is dropped (and the shootdown sent) after the lock.
            let mut deferred = Deferred::<A>::new();
            let mut guard = self.inner.lock();
            let Inner { pt, pages, maps, .. } = &mut *guard;
            let count = maps.dirty_in(from, to).len();
            if count == 0 {
                return Ok(());
            }
            jobs.try_reserve_exact(count).map_err(|_| Errno::ENOMEM)?;
            for &d in maps.dirty_in(from, to) {
                let Some(v) = maps.find(d) else { continue };
                if pages.find(&d).is_none() {
                    continue;
                }
                let Some(file) = v.file.clone() else { continue };
                // Taken before anything changes: a failure leaves the rest dirty for the next sync.
                let Some(frame) = pt.share_owned(VirtAddr::new(d)) else { return Err(Errno::ENOMEM) };
                // Clean from here on: a store after this faults and marks it again.
                if let Some(t) = pt.translate(VirtAddr::new(d))
                    && let Ok(flush) = pt.protect(VirtAddr::new(d), t.flags.difference(MapFlags::WRITE))
                {
                    flush.flush();
                    deferred.stale(d);
                }
                jobs.push(Job { file, off: v.off.saturating_add(d - v.start), va: d, frame });
            }
            maps.clear_dirty(from, to);
        }
        let mut first = Ok(());
        for job in jobs {
            if let Err(e) = self.write_page(&job) {
                // Try again at the next sync.
                let _ = self.inner.lock().maps.mark_dirty(job.va);
                if first.is_ok() {
                    first = Err(e);
                }
            }
        }
        first
    }

    /// Writes the part of a page that is inside the file; never extends it.
    fn write_page(&self, job: &Job<A>) -> Result<(), Errno> {
        let size = job.file.try_stat()?.size;
        if job.off >= size {
            return Ok(());
        }
        let n = (size - job.off).min(PAGE) as usize;
        // SAFETY: a whole frame, kept alive by `job`, reachable through the
        // allocator's mapping. A user store may race with the read, as it may
        // with any write-back; the bytes are plain data.
        let data = unsafe { core::slice::from_raw_parts(self.alloc.phys_to_virt(job.frame.pa()), PAGE_SIZE) };
        let mut done = 0;
        while done < n {
            let Some(src) = data.get(done..n) else { break };
            match job.file.write(job.off + done as u64, src)? {
                0 => return Err(Errno::EIO),
                k => done += k,
            }
        }
        Ok(())
    }
}
