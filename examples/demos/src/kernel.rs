// SPDX-License-Identifier: GPL-2.0-only
//! Kernel plumbing the example kernels share: the frame allocator, guarded
//! stacks, the clock, CPU bring-up bookkeeping and the random number demo.
//! What is left in each kernel is what differs between platforms.

use core::ops::Range;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering};

use osmium::arch::{MAX_CPUS, cpu};
use osmium::hal::mmio::IoMem;
use osmium::hal::println;
use osmium::hal::timer::{Clock, TickRate};
use osmium::mm::frame::order_for;
use osmium::mm::paging::PageTableFormat;
use osmium::mm::{
    BuddyAllocator, FrameAllocator, LockedFrames, MapFlags, OffsetMapper, PAGE_SIZE, PageSize, PageTable, PhysAddr,
    VirtAddr,
};
use osmium::sched::StackAllocator;
use osmium::sync::{IrqSpinLock, Once};

/// A buddy allocator over identity-mapped RAM.
pub type Frames = LockedFrames<BuddyAllocator<OffsetMapper>, OffsetMapper>;

/// The frame allocator. Every example kernel runs identity-mapped, before
/// and after it turns paging on, so physical address = virtual address.
// SAFETY: the kernels run identity-mapped, so an offset of 0 is right.
pub static FRAMES: Frames =
    unsafe { LockedFrames::new(BuddyAllocator::new(OffsetMapper::new(0)), OffsetMapper::new(0)) };

/// Frames left in [`FRAMES`].
pub fn free_frames() -> usize {
    FRAMES.lock().free_frames()
}

/// A kernel's page table, shared by all its CPUs once paging is on.
pub type KernelTable<F> = IrqSpinLock<Option<PageTable<F, &'static Frames>>>;

/// Hands out stacks from [`FRAMES`] with an unmapped guard page below each,
/// so running off the bottom faults instead of overwriting the memory there.
/// Used for task stacks and for the stacks of secondary CPUs.
pub struct GuardedStacks<F: PageTableFormat + Send + Sync + 'static> {
    table: &'static KernelTable<F>,
    /// Drops the guard page's old (global) translation from every other
    /// CPU's TLB; this CPU's is flushed already.
    flush_others: fn(usize),
}

impl<F: PageTableFormat + Send + Sync + 'static> GuardedStacks<F> {
    /// Stacks whose guard pages are unmapped in `table`, which must map all
    /// of RAM read/write once it is installed.
    pub const fn new(table: &'static KernelTable<F>, flush_others: fn(usize)) -> Self {
        Self { table, flush_others }
    }

    /// A stack of at least `size` bytes for a CPU's first flow of execution,
    /// which it never gives back. Returns its lowest address and its top,
    /// 16-byte aligned.
    pub fn leak(&self, size: usize) -> Option<Range<u64>> {
        let (base, len) = self.alloc(size)?;
        let lo = base.as_ptr() as u64;
        Some(lo..(lo + len as u64) & !15)
    }
}

// SAFETY: blocks come from the frame allocator (exclusive, page aligned) and
// the usable part stays mapped read/write.
unsafe impl<F: PageTableFormat + Send + Sync + 'static> StackAllocator for GuardedStacks<F> {
    fn alloc(&self, size: usize) -> Option<(NonNull<u8>, usize)> {
        let order = order_for(size.checked_add(PAGE_SIZE)?);
        let guard = FRAMES.lock().alloc(order)?;
        let unmapped = {
            let mut pt = self.table.lock();
            pt.as_mut().and_then(|pt| pt.unmap_4k(VirtAddr::new(guard.0)).ok())
        };
        let Some((_, flush)) = unmapped else {
            // SAFETY: just allocated with this order, and not handed out.
            unsafe { FRAMES.lock().dealloc(guard, order) };
            return None;
        };
        flush.flush();
        // The old mapping was global and may be cached on any CPU.
        (self.flush_others)(guard.0 as usize);
        Some((NonNull::new((guard.0 + PAGE_SIZE as u64) as *mut u8)?, (PAGE_SIZE << order) - PAGE_SIZE))
    }

    unsafe fn free(&self, base: NonNull<u8>, len: usize) {
        let guard = base.as_ptr() as u64 - PAGE_SIZE as u64;
        let mapped = {
            let mut pt = self.table.lock();
            let flags = MapFlags::RW | MapFlags::GLOBAL;
            pt.as_mut().and_then(|pt| pt.map(VirtAddr::new(guard), PhysAddr::new(guard), PageSize::Size4K, flags).ok())
        };
        match mapped {
            Some(flush) => {
                flush.flush();
                // SAFETY: the block came from `alloc` with the same order.
                unsafe { FRAMES.lock().dealloc(PhysAddr::new(guard), order_for(len + PAGE_SIZE)) };
            }
            // Without its guard page mapped again the block cannot go back to
            // the allocator, which writes into free frames: keep it.
            None => println!("[guard] could not remap the guard page at {guard:#x}; its stack is leaked"),
        }
    }
}

/// Unmaps the page at `guard` (page-aligned) in `table`, the active kernel
/// table, so that a stack just above it faults when it overflows instead of
/// running into whatever lies below. For stacks set aside before paging was
/// on, such as the boot stack. Returns false if the page could not be
/// unmapped.
pub fn unmap_guard<F: PageTableFormat>(table: &mut PageTable<F, &'static Frames>, guard: u64) -> bool {
    match table.unmap_4k(VirtAddr::new(guard)) {
        Ok((_, flush)) => {
            flush.flush();
            true
        }
        Err(_) => false,
    }
}

/// The lowest address of each CPU's boot stack (its first flow of
/// execution, which becomes its bootstrap task), or 0 if unknown.
static BOOT_STACK_LIMIT: [AtomicUsize; MAX_CPUS] = [const { AtomicUsize::new(0) }; MAX_CPUS];

/// Records the lowest address of this CPU's boot stack, for [`stack_limit`].
pub fn set_boot_stack_limit(lo: usize) {
    if let Some(slot) = BOOT_STACK_LIMIT.get(cpu::current_id()) {
        slot.store(lo, Ordering::Relaxed);
    }
}

/// The lowest valid address of `next`'s kernel stack on this CPU, for the
/// trap entry's overflow check: a spawned task's own stack, or this CPU's
/// boot stack for its bootstrap task (0, no check, if neither is known).
pub fn stack_limit(next: &osmium::sched::Task) -> usize {
    next.kernel_stack_range()
        .map_or_else(|| BOOT_STACK_LIMIT.get(cpu::current_id()).map_or(0, |l| l.load(Ordering::Relaxed)), |r| r.start)
}

/// Identity-maps the device window `base..base + len` in `table`, rounded
/// out to whole pages. Pages that are already mapped are left alone, so
/// windows may share a page (virtio-mmio slots do) or be mapped twice.
pub fn map_device<F: PageTableFormat>(table: &mut PageTable<F, &'static Frames>, base: u64, len: u64) {
    let page = PAGE_SIZE as u64;
    let (start, end) = (base & !(page - 1), base.saturating_add(len).next_multiple_of(page));
    let flags = MapFlags::RW | MapFlags::DEVICE | MapFlags::GLOBAL;
    let (va, pa) = (VirtAddr::new, PhysAddr::new);
    let unmapped = |pt: &PageTable<F, _>, p| pt.translate(va(p)).is_none();
    // In one go where nothing is mapped yet, so large windows get large pages.
    if end > start
        && unmapped(table, start)
        && unmapped(table, end - page)
        && table.map_range(va(start), pa(start), end - start, flags).is_ok()
    {
        return;
    }
    for p in (start..end).step_by(PAGE_SIZE) {
        if unmapped(table, p) && table.map(va(p), pa(p), PageSize::Size4K, flags).map(|f| f.ignore()).is_err() {
            println!("[mmu]   could not map device page {p:#x}");
        }
    }
}

/// Identity-maps the device window `addr..addr + size` in the kernel's
/// `table` (see [`map_device`]) and returns a window onto it. If `table`
/// holds no table yet, only returns the window.
///
/// # Safety
/// `addr..addr + size` must be the registers (or other memory) of a device
/// that the caller owns, and nothing else may use it meanwhile. If `table`
/// is empty, the window must already be reachable at those addresses.
pub unsafe fn map_io<F: PageTableFormat>(table: &KernelTable<F>, addr: u64, size: u64) -> IoMem {
    if let Some(pt) = table.lock().as_mut() {
        map_device(pt, addr, size);
    }
    // SAFETY: mapped as device memory (or reached physically); the caller
    // owns the device.
    unsafe { IoMem::new(addr as *mut u8, size as usize) }
}

/// Spins for up to `timeout_ns` until `done` holds, and says whether it did.
pub fn wait_for(timeout_ns: u64, done: impl Fn() -> bool) -> bool {
    let deadline = now_ns().saturating_add(timeout_ns);
    while !done() {
        if now_ns() > deadline {
            return false;
        }
        core::hint::spin_loop();
    }
    true
}

/// The CPU counter's rate, once the kernel knows it.
static RATE: Once<TickRate> = Once::new();

/// Sets the rate [`now_ns`] converts the CPU counter with. Only the first
/// call counts.
pub fn set_rate(rate: TickRate) {
    RATE.call_once(|| rate);
}

/// The rate given to [`set_rate`], if any.
pub fn rate() -> Option<&'static TickRate> {
    RATE.get()
}

/// Nanoseconds since the CPU counter started; 0 until [`set_rate`].
pub fn now_ns() -> u64 {
    RATE.get().map_or(0, |r| r.ticks_to_ns(cpu::ticks()))
}

/// [`now_ns`] for drivers that take a [`Clock`].
pub struct Uptime;

impl Clock for Uptime {
    fn now_ns(&self) -> u64 {
        now_ns()
    }
}

/// CPUs that have finished bringing themselves up, the boot CPU included.
static ONLINE: AtomicUsize = AtomicUsize::new(1);

/// How many CPUs are online.
pub fn online() -> usize {
    ONLINE.load(Ordering::Acquire)
}

/// Called by a secondary CPU once it is ready for tasks.
pub fn check_in() {
    ONLINE.fetch_add(1, Ordering::Release);
}

/// Waits up to a second for `n` CPUs to be online.
pub fn wait_online(n: usize) -> bool {
    let deadline = now_ns().saturating_add(1_000_000_000);
    while online() < n {
        if now_ns() > deadline {
            return false;
        }
        core::hint::spin_loop();
    }
    true
}

/// The CPUs to bring up besides the boot CPU, `ids` in device-tree or MADT
/// order with `boot` left out, never more than `MAX_CPUS - 1` (the logical
/// CPU ids are indices into per-CPU arrays of that size).
pub fn secondaries<T: PartialEq>(ids: impl Iterator<Item = T>, boot: T) -> impl Iterator<Item = (usize, T)> {
    ids.filter(move |id| *id != boot).take(MAX_CPUS - 1).enumerate().map(|(i, id)| (i + 1, id))
}

/// Seeds a generator from the CPU's random number instructions, draws from
/// it, and runs the TLS self-test on it.
pub fn rand_demo() {
    static RNG: osmium::rand::SharedRng = osmium::rand::SharedRng::new();
    if !osmium::rand::CpuEntropy::available() {
        println!("[rand]  no CPU random number instructions");
        return;
    }
    match RNG.seed(&osmium::rand::CpuEntropy) {
        Ok(()) => match (RNG.next_u64(), RNG.next_u64()) {
            (Ok(a), Ok(b)) if a != b => {
                println!("[rand]  seeded from the CPU; draws differ");
                // Any time will do: the self-test's certificate is valid around it.
                match osmium::tls::self_test(&RNG, 1_800_000_000) {
                    Ok(()) => println!("[tls]   self-test passed: TLS 1.3 handshake and echo"),
                    Err(e) => println!("[tls]   self-test failed: {e}"),
                }
            }
            r => println!("[rand]  seeded, but draws look wrong: {r:?}"),
        },
        Err(e) => println!("[rand]  {e}"),
    }
}

/// Gives `regions` to [`FRAMES`].
///
/// # Safety
/// Each region must be free RAM, identity-mapped (writable through the
/// active table), that nothing else uses from now on.
pub unsafe fn add_ram(regions: impl Iterator<Item = Range<PhysAddr>>) {
    let mut buddy = FRAMES.lock();
    for r in regions {
        // SAFETY: the caller's contract.
        unsafe { buddy.add_region(r.start, r.end) };
    }
}

/// Prints what the frame allocator holds.
pub fn report_frames() {
    let free = free_frames();
    println!("[frame] buddy allocator: {free} free frames ({} MiB)", (free * PAGE_SIZE) >> 20);
}
