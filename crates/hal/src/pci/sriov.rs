//! PCIe extended capabilities and Single Root I/O Virtualization.
//!
//! A physical function with the SR-IOV capability can present up to
//! [`SrIov::total_vfs`] virtual functions: lightweight functions that share
//! its hardware, each with its own configuration space, BARs and routing ID,
//! suitable for handing to a guest. [`Function::sriov`] reads the
//! capability; [`SrIov::enable`] and [`SrIov::disable`] turn the virtual
//! functions on and off in the order Linux does; [`SrIov::vf_address`] says
//! where the virtual functions then answer.
//!
//! Configuration space past the first 256 bytes only exists behind an
//! [`Ecam`](super::Ecam) window (the legacy port access cannot reach it), so
//! everything here reads all-ones, and finds nothing, through a
//! [`ConfigAccess`] that cannot.
//!
//! What this does not do: give the virtual functions' BARs addresses (the
//! caller probes them with [`SrIov::vf_bar`], allocates, and programs them
//! with [`SrIov::set_vf_bar`] before enabling) or make bus numbers
//! available for them (the bridges above must forward them), and it knows
//! nothing of what the physical function's own driver must do for the
//! virtual functions to be useful.

use super::{Address, Bar, BarKind, ConfigAccess, Function, command};
use crate::timer::Clock;

/// Extended capability IDs.
pub mod ext_cap {
    #![allow(missing_docs)]
    pub const SRIOV: u16 = 0x0010;
}

/// Where extended capabilities start, and the size of configuration space.
const EXT_START: u16 = 0x100;
const CONFIG_END: u16 = 0x1000;

// SR-IOV capability registers (offsets from the capability).
const CAPABILITIES: u16 = 0x04;
const CONTROL: u16 = 0x08;
const INITIAL_VFS: u16 = 0x0c;
const TOTAL_VFS: u16 = 0x0e;
const NUM_VFS: u16 = 0x10;
const FIRST_VF_OFFSET: u16 = 0x14;
const VF_STRIDE: u16 = 0x16;
const VF_DEVICE_ID: u16 = 0x1a;
const SUPPORTED_PAGE_SIZES: u16 = 0x1c;
const SYSTEM_PAGE_SIZE: u16 = 0x20;
const VF_BAR0: u16 = 0x24;
const LENGTH: u16 = 0x40;

const CAP_MIGRATION: u32 = 1 << 0;
const CTRL_VF_ENABLE: u16 = 1 << 0;
const CTRL_VF_MEMORY_ENABLE: u16 = 1 << 3;

/// The specification's time for virtual functions to be ready after VF
/// Enable is set, and a safe wait before reusing them after it is cleared.
const ENABLE_WAIT_NS: u64 = 100_000_000;
const DISABLE_WAIT_NS: u64 = 1_000_000_000;

/// Why an SR-IOV operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SrIovError {
    /// The function has no SR-IOV capability.
    NotPresent,
    /// The capability is malformed: no virtual functions, no page size the
    /// function supports, or registers past the end of configuration space.
    BadCapability,
    /// Virtual functions are already enabled.
    AlreadyEnabled,
    /// More virtual functions than the function offers (or, without
    /// migration support, than its initial count).
    TooMany,
    /// The virtual functions' routing IDs would not fit the bus numbers.
    OutOfBuses,
    /// The BAR index is not 0–5.
    BadIndex,
}

/// Iterator over the extended capabilities, as `(id, version, offset)`.
pub struct ExtCapabilities<'f, 'cfg, C: ConfigAccess + ?Sized> {
    func: &'f Function<'cfg, C>,
    next: u16,
    // Bounds the walk on a malformed (cyclic) list.
    budget: u16,
}

impl<C: ConfigAccess + ?Sized> Iterator for ExtCapabilities<'_, '_, C> {
    type Item = (u16, u8, u16);

    fn next(&mut self) -> Option<Self::Item> {
        if self.next < EXT_START || self.next >= CONFIG_END || self.budget == 0 {
            return None;
        }
        self.budget -= 1;
        let offset = self.next;
        let header = self.func.read32(offset);
        // An empty list reads as zero; a function that cannot be read, as all ones.
        if header == 0 || header == !0 {
            return None;
        }
        self.next = (header >> 20) as u16 & !3;
        Some((header as u16, (header >> 16 & 0xf) as u8, offset))
    }
}

impl<'cfg, C: ConfigAccess + ?Sized> Function<'cfg, C> {
    /// Iterates over the extended capability list (PCIe configuration space
    /// from offset 0x100).
    pub fn extended_capabilities(&self) -> ExtCapabilities<'_, 'cfg, C> {
        ExtCapabilities { func: self, next: EXT_START, budget: (CONFIG_END - EXT_START) / 8 }
    }

    /// Offset of the first extended capability with ID `id`.
    pub fn find_extended_capability(&self, id: u16) -> Option<u16> {
        self.extended_capabilities().find(|&(cid, _, _)| cid == id).map(|(_, _, off)| off)
    }

    /// The SR-IOV capability.
    pub fn sriov(&self) -> Result<SrIov, SrIovError> {
        let offset = self.find_extended_capability(ext_cap::SRIOV).ok_or(SrIovError::NotPresent)?;
        if offset + LENGTH > CONFIG_END {
            return Err(SrIovError::BadCapability);
        }
        let (total_vfs, initial_vfs) = (self.read16(offset + TOTAL_VFS), self.read16(offset + INITIAL_VFS));
        let page_sizes = self.read32(offset + SUPPORTED_PAGE_SIZES);
        // No virtual functions, more initially than in all, or no page size to
        // lay the virtual functions' BARs out in.
        if total_vfs == 0 || initial_vfs > total_vfs || page_sizes == 0 {
            return Err(SrIovError::BadCapability);
        }
        Ok(SrIov {
            offset,
            capabilities: self.read32(offset + CAPABILITIES),
            initial_vfs,
            total_vfs,
            vf_device_id: self.read16(offset + VF_DEVICE_ID),
            page_sizes,
        })
    }
}

/// A function's SR-IOV capability, from [`Function::sriov`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SrIov {
    offset: u16,
    capabilities: u32,
    initial_vfs: u16,
    total_vfs: u16,
    vf_device_id: u16,
    page_sizes: u32,
}

impl SrIov {
    /// Configuration-space offset of the capability.
    pub fn offset(&self) -> u16 {
        self.offset
    }

    /// Virtual functions the function offers in all.
    pub fn total_vfs(&self) -> u16 {
        self.total_vfs
    }

    /// Virtual functions that can be enabled at once, unless the function
    /// supports migration (then up to [`total_vfs`](Self::total_vfs)).
    pub fn initial_vfs(&self) -> u16 {
        self.initial_vfs
    }

    /// The device ID the virtual functions present.
    pub fn vf_device_id(&self) -> u16 {
        self.vf_device_id
    }

    /// The system page sizes the function supports, one bit per power of two
    /// (bit `n` is 4 KiB × 2^`n`).
    pub fn page_sizes(&self) -> u32 {
        self.page_sizes
    }

    /// True if virtual functions can migrate (so more than the initial count
    /// can be enabled).
    pub fn supports_migration(&self) -> bool {
        self.capabilities & CAP_MIGRATION != 0
    }

    /// True if virtual functions are enabled.
    pub fn enabled<C: ConfigAccess + ?Sized>(&self, func: &Function<'_, C>) -> bool {
        func.read16(self.offset + CONTROL) & CTRL_VF_ENABLE != 0
    }

    /// How many virtual functions are configured (the NumVFs register).
    pub fn num_vfs<C: ConfigAccess + ?Sized>(&self, func: &Function<'_, C>) -> u16 {
        func.read16(self.offset + NUM_VFS)
    }

    /// Writes a 16-bit register, which shares its dword with the neighbor
    /// (a write must carry that half unchanged).
    fn write16<C: ConfigAccess + ?Sized>(&self, func: &Function<'_, C>, reg: u16, value: u16) {
        let at = self.offset + reg;
        let (shift, keep) = ((at & 2) * 8, func.read32(at & !3));
        func.write32(at & !3, keep & !(0xffff << shift) | (value as u32) << shift);
    }

    /// The virtual function BAR `index` as the function describes it: its
    /// `size` is that of *one* virtual function's BAR, and the whole region
    /// holds [`total_vfs`](Self::total_vfs) of them (or, once enabled,
    /// [`num_vfs`](Self::num_vfs)) one after another. The probe needs virtual
    /// function memory decoding off; do it before enabling.
    pub fn vf_bar<C: ConfigAccess + ?Sized>(
        &self,
        func: &Function<'_, C>,
        index: u8,
    ) -> Result<Option<Bar>, SrIovError> {
        if index >= 6 {
            return Err(SrIovError::BadIndex);
        }
        let at = |i: u8| self.offset + VF_BAR0 + i as u16 * 4;
        let is_64bit = |v: u32| v & 1 == 0 && v >> 1 & 3 == 2;
        // A 64-bit BAR takes two slots, and its second is not a BAR of its own.
        let mut i = 0;
        while i < index {
            i += if is_64bit(func.read32(at(i))) { 2 } else { 1 };
        }
        let off = at(index);
        let lo = func.read32(off);
        let kind = if i != index || lo & 1 != 0 {
            return Ok(None); // the second half of a 64-bit BAR, or I/O (virtual functions have none)
        } else {
            let prefetchable = lo & 8 != 0;
            match lo >> 1 & 3 {
                0 => BarKind::Memory32 { prefetchable },
                2 if index < 5 => BarKind::Memory64 { prefetchable },
                _ => return Ok(None),
            }
        };
        let cmd = func.command();
        func.set_command(cmd & !(command::MEMORY_SPACE | command::IO_SPACE));
        func.write32(off, !0);
        let mask_lo = func.read32(off);
        func.write32(off, lo);
        let (address, mask) = if let BarKind::Memory64 { .. } = kind {
            let hi = func.read32(off + 4);
            func.write32(off + 4, !0);
            let mask_hi = func.read32(off + 4);
            func.write32(off + 4, hi);
            ((hi as u64) << 32 | (lo & !0xf) as u64, (mask_hi as u64) << 32 | (mask_lo & !0xf) as u64)
        } else {
            ((lo & !0xf) as u64, (mask_lo & !0xf) as u64)
        };
        func.set_command(cmd);
        Ok((mask != 0).then(|| Bar { index, kind, address, size: 1 << mask.trailing_zeros() }))
    }

    /// Programs virtual function BAR `bar` (from [`vf_bar`](Self::vf_bar)) to
    /// start its region at `address`, which must be aligned to the size of
    /// one virtual function's BAR.
    ///
    /// # Panics
    ///
    /// If `address` is not aligned to `bar.size`, or is above 4 GiB for a
    /// 32-bit BAR.
    pub fn set_vf_bar<C: ConfigAccess + ?Sized>(&self, func: &Function<'_, C>, bar: &Bar, address: u64) {
        assert!(address.is_multiple_of(bar.size), "virtual function BAR address not aligned to its size");
        let off = self.offset + VF_BAR0 + bar.index as u16 * 4;
        let flags = func.read32(off) & 0xf;
        func.write32(off, address as u32 | flags);
        if let BarKind::Memory64 { .. } = bar.kind {
            func.write32(off + 4, (address >> 32) as u32);
        } else {
            assert!(address >> 32 == 0, "32-bit virtual function BAR above 4 GiB");
        }
    }

    /// Turns on `count` virtual functions and waits the 100 ms the
    /// specification allows them to come up.
    ///
    /// The virtual functions' BARs should have been programmed already
    /// ([`set_vf_bar`](Self::set_vf_bar)); the system page size is set to the
    /// smallest the function supports. Errors leave the function as it was.
    pub fn enable<C: ConfigAccess + ?Sized>(
        &self,
        func: &Function<'_, C>,
        count: u16,
        clock: &dyn Clock,
    ) -> Result<(), SrIovError> {
        if self.enabled(func) || self.num_vfs(func) != 0 {
            return Err(SrIovError::AlreadyEnabled);
        }
        // Without migration, the initial count is also the most, and must be all.
        if count == 0
            || count > self.total_vfs
            || !self.supports_migration() && (count > self.initial_vfs || self.initial_vfs != self.total_vfs)
        {
            return Err(SrIovError::TooMany);
        }
        // The lowest supported page size, which is what the virtual
        // functions' BAR alignment and the offset/stride arithmetic assume.
        func.write32(self.offset + SYSTEM_PAGE_SIZE, self.page_sizes & self.page_sizes.wrapping_neg());
        // Offset and stride are read after NumVFs is written: the function
        // may adjust them to the count.
        self.write16(func, NUM_VFS, count);
        if self.vf_address(func, count - 1).is_none() {
            self.write16(func, NUM_VFS, 0);
            return Err(SrIovError::OutOfBuses);
        }
        let ctrl = func.read16(self.offset + CONTROL);
        self.write16(func, CONTROL, ctrl | CTRL_VF_ENABLE | CTRL_VF_MEMORY_ENABLE);
        wait(clock, ENABLE_WAIT_NS);
        Ok(())
    }

    /// Turns the virtual functions off and waits a second for them to be gone.
    pub fn disable<C: ConfigAccess + ?Sized>(&self, func: &Function<'_, C>, clock: &dyn Clock) {
        if !self.enabled(func) && self.num_vfs(func) == 0 {
            return;
        }
        let ctrl = func.read16(self.offset + CONTROL);
        self.write16(func, CONTROL, ctrl & !(CTRL_VF_ENABLE | CTRL_VF_MEMORY_ENABLE));
        wait(clock, DISABLE_WAIT_NS);
        self.write16(func, NUM_VFS, 0);
    }

    /// Where virtual function `index` (0-based) of `func` answers, once
    /// [`enable`](Self::enable) has set the count: its routing ID is the
    /// physical function's plus the first offset plus the stride for each
    /// function before it. `None` if the routing ID would go past bus 255 or
    /// the registers say nothing (no virtual functions configured).
    pub fn vf_address<C: ConfigAccess + ?Sized>(&self, func: &Function<'_, C>, index: u16) -> Option<Address> {
        let count = self.num_vfs(func);
        if index >= count {
            return None;
        }
        let pf = func.address();
        // Wide enough that nothing the function reports can overflow it.
        let routing = (pf.bus as u64) << 8 | (pf.device as u64) << 3 | pf.function as u64;
        let (first, stride) =
            (func.read16(self.offset + FIRST_VF_OFFSET) as u64, func.read16(self.offset + VF_STRIDE) as u64);
        let id = routing + first + stride * index as u64;
        let bus = u8::try_from(id >> 8).ok()?;
        let devfn = (id & 0xff) as u8;
        Some(Address::new(bus, devfn >> 3, devfn & 7))
    }
}

/// Spins for `ns` of the clock's time.
fn wait(clock: &dyn Clock, ns: u64) {
    let start = clock.now_ns();
    while clock.now_ns().saturating_sub(start) < ns {
        core::hint::spin_loop();
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicU64, Ordering};
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;
    use std::vec::Vec;

    use super::*;
    use crate::pci::reg;

    const PF: Address = Address::new(3, 0, 0);
    const CAP: u16 = 0x140;

    /// A function with an SR-IOV capability that reacts to the registers
    /// the way the specification says.
    #[derive(Default)]
    struct Config {
        space: RefCell<BTreeMap<(Address, u16), u32>>,
        writes: RefCell<Vec<(u16, u32)>>,
        /// VF BAR sizes (per virtual function), by BAR offset.
        bar_sizes: BTreeMap<u16, u64>,
        /// The first offset and stride the function reports once NumVFs is set.
        placement: Cell<(u16, u16)>,
    }

    impl Config {
        fn set(&self, offset: u16, v: u32) {
            self.space.borrow_mut().insert((PF, offset), v);
        }
    }

    impl ConfigAccess for Config {
        fn read32(&self, addr: Address, offset: u16) -> u32 {
            if addr != PF {
                return !0;
            }
            self.space.borrow().get(&(addr, offset)).copied().unwrap_or(0)
        }

        fn write32(&self, addr: Address, offset: u16, value: u32) {
            self.writes.borrow_mut().push((offset, value));
            if (CAP + VF_BAR0 + 16..CAP + VF_BAR0 + 24).contains(&offset) {
                return; // BARs 4 and 5 are not implemented: they read zero
            }
            let mut space = self.space.borrow_mut();
            let mut value = value;
            if let Some(&size) = self.bar_sizes.get(&offset) {
                // A BAR: writing ones reads back the size mask.
                let low = space.get(&(addr, offset)).copied().unwrap_or(0) & 0xf;
                if value == !0 {
                    value = !(size as u32 - 1) & !0xf | low;
                } else {
                    value = value & !(size as u32 - 1) & !0xf | low;
                }
            }
            if offset == CAP + NUM_VFS {
                // NumVFs is the low half; the function fills in offset and stride.
                let (first, stride) = self.placement.get();
                space.insert((addr, CAP + FIRST_VF_OFFSET), first as u32 | (stride as u32) << 16);
            }
            space.insert((addr, offset), value);
        }
    }

    /// A clock that moves 10 ms every time it is read.
    #[derive(Default)]
    struct Ticks(AtomicU64);

    impl Ticks {
        fn get(&self) -> u64 {
            self.0.load(Ordering::Relaxed)
        }
    }

    impl Clock for Ticks {
        fn now_ns(&self) -> u64 {
            self.0.fetch_add(10_000_000, Ordering::Relaxed) + 10_000_000
        }
    }

    fn function() -> Config {
        let cfg = Config::default();
        cfg.set(reg::VENDOR_DEVICE, 0x1003_15b3);
        cfg.set(reg::COMMAND_STATUS, 0x0006);
        cfg.set(reg::HEADER_TYPE, 0x0080_0000);
        // Two unrelated extended capabilities, then SR-IOV, then the end.
        cfg.set(0x100, 0x0001 | 1 << 16 | 0x120 << 20); // advanced error reporting
        cfg.set(0x120, 0x0003 | 1 << 16 | (CAP as u32) << 20); // device serial number
        cfg.set(CAP, 0x0010 | 1 << 16);
        cfg.set(CAP + CAPABILITIES, 0);
        cfg.set(CAP + INITIAL_VFS, 8 | 8 << 16); // initial and total
        cfg.set(CAP + FIRST_VF_OFFSET, 0);
        cfg.set(CAP + VF_DEVICE_ID - 2, 0x1004 << 16);
        cfg.set(CAP + SUPPORTED_PAGE_SIZES, 0b101); // 4 KiB and 16 KiB
        cfg.set(CAP + VF_BAR0, 0b0100); // 64-bit memory
        cfg.set(CAP + VF_BAR0 + 8, 0b1100); // 64-bit prefetchable
        cfg.placement.set((0x80, 2));
        cfg
    }

    fn with_bars(mut cfg: Config) -> Config {
        cfg.bar_sizes.insert(CAP + VF_BAR0, 0x10_0000);
        cfg.bar_sizes.insert(CAP + VF_BAR0 + 8, 0x4000);
        cfg
    }

    #[test]
    fn extended_capabilities_are_walked() {
        let cfg = function();
        let f = Function::new(&cfg, PF).unwrap();
        let caps: Vec<_> = f.extended_capabilities().collect();
        assert_eq!(caps, [(0x0001, 1, 0x100), (0x0003, 1, 0x120), (0x0010, 1, CAP)]);
        assert_eq!(f.find_extended_capability(ext_cap::SRIOV), Some(CAP));
        assert_eq!(f.find_extended_capability(0x0042), None);

        // A cycle is bounded; an unreadable or empty function has none.
        cfg.set(CAP, 0x0010 | 1 << 16 | 0x100 << 20);
        assert_eq!(f.extended_capabilities().count(), 480);
        cfg.set(0x100, 0);
        assert_eq!(f.extended_capabilities().count(), 0);
    }

    #[test]
    fn the_capability_is_read_and_checked() {
        let cfg = function();
        let f = Function::new(&cfg, PF).unwrap();
        let s = f.sriov().unwrap();
        assert_eq!((s.offset(), s.total_vfs(), s.initial_vfs(), s.vf_device_id()), (CAP, 8, 8, 0x1004));
        assert_eq!((s.page_sizes(), s.supports_migration()), (0b101, false));
        assert!(!s.enabled(&f) && s.num_vfs(&f) == 0);

        for (what, reg, value) in [
            ("no virtual functions", CAP + INITIAL_VFS, 0),
            ("more initial than total", CAP + INITIAL_VFS, 9 | 8 << 16),
            ("no page size", CAP + SUPPORTED_PAGE_SIZES, 0),
        ] {
            let cfg = function();
            cfg.set(reg, value);
            let f = Function::new(&cfg, PF).unwrap();
            assert_eq!(f.sriov().err(), Some(SrIovError::BadCapability), "{what}");
        }
        // Registers past the end of configuration space.
        let cfg = function();
        cfg.set(CAP, 0x0010 | 1 << 16);
        cfg.set(0x120, 0x0003 | 1 << 16 | 0xfe0 << 20);
        cfg.set(0xfe0, 0x0010 | 1 << 16);
        assert_eq!(Function::new(&cfg, PF).unwrap().sriov().err(), Some(SrIovError::BadCapability));
    }

    #[test]
    fn vf_bars_are_probed_and_programmed() {
        let cfg = with_bars(function());
        let f = Function::new(&cfg, PF).unwrap();
        let s = f.sriov().unwrap();
        let big = s.vf_bar(&f, 0).unwrap().unwrap();
        assert_eq!((big.kind, big.size, big.address), (BarKind::Memory64 { prefetchable: false }, 0x10_0000, 0));
        assert_eq!(s.vf_bar(&f, 1).unwrap(), None, "the upper half of a 64-bit BAR");
        let small = s.vf_bar(&f, 2).unwrap().unwrap();
        assert_eq!((small.kind, small.size), (BarKind::Memory64 { prefetchable: true }, 0x4000));
        assert_eq!(s.vf_bar(&f, 4).unwrap(), None, "unimplemented");
        assert_eq!(s.vf_bar(&f, 6).err(), Some(SrIovError::BadIndex));
        assert_eq!(f.command() & 2, 2, "memory decoding restored after probing");

        s.set_vf_bar(&f, &big, 0x2_0000_0000);
        s.set_vf_bar(&f, &small, 0x8000_4000);
        assert_eq!(s.vf_bar(&f, 0).unwrap().unwrap().address, 0x2_0000_0000);
        assert_eq!(s.vf_bar(&f, 2).unwrap().unwrap().address, 0x8000_4000);
    }

    #[test]
    #[should_panic(expected = "not aligned")]
    fn vf_bar_alignment_is_enforced() {
        let cfg = with_bars(function());
        let f = Function::new(&cfg, PF).unwrap();
        let s = f.sriov().unwrap();
        let bar = s.vf_bar(&f, 0).unwrap().unwrap();
        s.set_vf_bar(&f, &bar, 0x8008_0000);
    }

    #[test]
    fn enabling_and_disabling() {
        let (cfg, clock) = (function(), Ticks::default());
        let f = Function::new(&cfg, PF).unwrap();
        let s = f.sriov().unwrap();
        s.enable(&f, 4, &clock).unwrap();
        assert!(s.enabled(&f) && s.num_vfs(&f) == 4);
        assert_eq!(cfg.read32(PF, CAP + SYSTEM_PAGE_SIZE), 1, "the smallest page size the function supports");
        // The count first, the enable bits after; the wait follows the enable.
        let writes = cfg.writes.borrow();
        let at = |reg: u16| writes.iter().position(|&(r, _)| r == reg & !3).unwrap();
        assert!(at(CAP + NUM_VFS) < at(CAP + CONTROL));
        let ctrl = writes.iter().rev().find(|&&(r, _)| r == CAP + CONTROL).unwrap().1;
        assert_eq!(ctrl as u16, CTRL_VF_ENABLE | CTRL_VF_MEMORY_ENABLE);
        assert!(clock.get() >= ENABLE_WAIT_NS, "waited for the virtual functions to come up");
        drop(writes);

        // 0x80 and 2 after the physical function at bus 3, device 0, function 0.
        let addrs: Vec<_> = (0..4).map(|i| s.vf_address(&f, i).unwrap()).collect();
        assert_eq!(addrs, [(3, 16, 0), (3, 16, 2), (3, 16, 4), (3, 16, 6)].map(|(b, d, f)| Address::new(b, d, f)));
        assert_eq!(s.vf_address(&f, 4), None, "only the four enabled");

        assert_eq!(s.enable(&f, 2, &clock), Err(SrIovError::AlreadyEnabled));
        let before = clock.get();
        s.disable(&f, &clock);
        assert!(!s.enabled(&f) && s.num_vfs(&f) == 0);
        assert!(clock.get() - before >= DISABLE_WAIT_NS);
        s.disable(&f, &clock); // nothing to do the second time
    }

    #[test]
    fn enabling_is_checked_first() {
        let clock = Ticks::default();
        for (count, migration, initial, total, error) in [
            (0u16, false, 8u16, 8u16, SrIovError::TooMany),
            (9, false, 8, 8, SrIovError::TooMany),
            (9, true, 4, 8, SrIovError::TooMany),
            (5, false, 4, 8, SrIovError::TooMany), // fewer initial than total, and no migration
            (8, false, 4, 8, SrIovError::TooMany),
        ] {
            let cfg = function();
            cfg.set(CAP + INITIAL_VFS, initial as u32 | (total as u32) << 16);
            cfg.set(CAP + CAPABILITIES, migration as u32);
            let f = Function::new(&cfg, PF).unwrap();
            let s = f.sriov().unwrap();
            assert_eq!(s.enable(&f, count, &clock), Err(error), "{count} of {initial}/{total}, migration {migration}");
            assert!(cfg.writes.borrow().is_empty(), "nothing touched");
        }
        // With migration, any count up to the total.
        let cfg = function();
        cfg.set(CAP + INITIAL_VFS, 2 | 8 << 16);
        cfg.set(CAP + CAPABILITIES, 1);
        let f = Function::new(&cfg, PF).unwrap();
        f.sriov().unwrap().enable(&f, 8, &clock).unwrap();

        // Routing IDs that run off the last bus undo the count.
        let cfg = function();
        cfg.placement.set((0xfff0, 0x1000));
        let f = Function::new(&cfg, PF).unwrap();
        let s = f.sriov().unwrap();
        assert_eq!(s.enable(&f, 8, &clock), Err(SrIovError::OutOfBuses));
        assert_eq!(s.num_vfs(&f), 0);
        assert!(!s.enabled(&f));
    }
}
