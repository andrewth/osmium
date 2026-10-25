//! PCI-to-PCI bridge walking.
//!
//! [`for_each_function`](super::for_each_function) scans bus numbers
//! blindly, which only finds devices behind a bridge when firmware has
//! already numbered the buses. [`walk`] does the numbering itself: it scans
//! bus by bus, and on meeting a type 1 header it assigns the bridge's primary,
//! secondary and subordinate bus numbers, descends, and programs the bridge's
//! memory window to cover whatever its subtree's BARs took from the
//! [`BarAllocator`].
//!
//! Limits: only the non-prefetchable memory window is programmed (every
//! memory BAR, prefetchable or not, comes from the one allocator and so lands
//! in it, which is legal); the I/O and prefetchable windows are closed, so
//! I/O BARs behind a bridge stay unreachable. Bridge windows are 32-bit and
//! 1 MiB granular, so the allocator's window must lie below 4 GiB.

use super::{Address, BarAllocator, BarError, ConfigAccess, Function, command};

/// Bridge (type 1) header offsets.
mod off {
    pub const BUSES: u16 = 0x18;
    pub const IO: u16 = 0x1c;
    pub const MEMORY: u16 = 0x20;
    pub const PREFETCH: u16 = 0x24;
    pub const PREFETCH_BASE_HI: u16 = 0x28;
    pub const PREFETCH_LIMIT_HI: u16 = 0x2c;
    pub const IO_HI: u16 = 0x30;
}

/// Bridge memory windows are aligned to and sized in multiples of this.
const WINDOW_GRANULE: u64 = 1 << 20;

/// Why [`walk`] failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalkError {
    /// A BAR could not be placed in the window.
    Bar(BarError),
    /// A bridge window would end above 4 GiB, which type 1 headers cannot
    /// express.
    WindowTooHigh,
}

impl From<BarError> for WalkError {
    fn from(e: BarError) -> Self {
        Self::Bar(e)
    }
}

/// A PCI-to-PCI bridge: a function with a type 1 header.
pub struct Bridge<'f, 'cfg, C: ConfigAccess + ?Sized> {
    func: &'f Function<'cfg, C>,
}

impl<'f, 'cfg, C: ConfigAccess + ?Sized> Bridge<'f, 'cfg, C> {
    /// Views `func` as a bridge, or `None` if its header is not type 1.
    pub fn new(func: &'f Function<'cfg, C>) -> Option<Self> {
        (func.header_type() == 1).then_some(Self { func })
    }

    /// The bus the bridge sits on.
    pub fn primary_bus(&self) -> u8 {
        self.func.read8(off::BUSES)
    }

    /// The bus directly behind the bridge.
    pub fn secondary_bus(&self) -> u8 {
        self.func.read8(off::BUSES + 1)
    }

    /// The highest bus number behind the bridge.
    pub fn subordinate_bus(&self) -> u8 {
        self.func.read8(off::BUSES + 2)
    }

    /// Sets the bus numbers. The secondary latency timer byte is cleared.
    pub fn set_buses(&self, primary: u8, secondary: u8, subordinate: u8) {
        self.func.write32(off::BUSES, primary as u32 | (secondary as u32) << 8 | (subordinate as u32) << 16);
    }

    /// Changes only the subordinate bus number.
    pub fn set_subordinate(&self, subordinate: u8) {
        self.set_buses(self.primary_bus(), self.secondary_bus(), subordinate);
    }

    /// The forwarded non-prefetchable memory range as `(base, end)`
    /// inclusive, or `None` if the window is closed.
    pub fn memory_window(&self) -> Option<(u32, u32)> {
        let v = self.func.read32(off::MEMORY);
        let base = (v & 0xfff0) << 16;
        let end = (v & 0xfff0_0000) | 0xf_ffff;
        (base <= end).then_some((base, end))
    }

    /// Forwards `[base, end]` (both inclusive; `base` aligned to 1 MiB and
    /// `end + 1` too) downstream.
    pub fn set_memory_window(&self, base: u32, end: u32) {
        self.func.write32(off::MEMORY, (base >> 16) & 0xfff0 | (end & 0xfff0_0000));
    }

    /// Closes the I/O, memory and prefetchable windows.
    pub fn close_windows(&self) {
        // Base above limit disables a window. The status half of the I/O
        // dword is write-1-to-clear, so it is written as zero.
        self.func.write32(off::IO, 0x00f0);
        self.func.write32(off::IO_HI, 0);
        self.func.write32(off::MEMORY, 0x0000_fff0);
        self.func.write32(off::PREFETCH, 0x0000_fff0);
        self.func.write32(off::PREFETCH_BASE_HI, 0);
        self.func.write32(off::PREFETCH_LIMIT_HI, 0);
    }
}

/// What [`walk`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WalkSummary {
    /// The highest bus number in use under the root bus.
    pub last_bus: u8,
    /// Bridges visited.
    pub bridges: usize,
}

/// Enumerates the hierarchy under bus `root`, numbering buses and sizing
/// bridge windows as it goes. `alloc` supplies addresses for unassigned
/// memory BARs (pass the host bridge's window); `f` is called once per
/// function, endpoints right after their BARs are placed and bridges after
/// everything behind them has been visited.
///
/// Bus numbers are always reassigned from `root + 1` in depth-first order,
/// whatever the firmware left; a bridge that would need a bus beyond
/// `cfg.max_bus()` is closed and not descended into. Memory decoding and
/// bus mastering are enabled on each bridge so downstream devices can reach
/// the host.
pub fn walk<C: ConfigAccess + ?Sized>(
    cfg: &C,
    root: u8,
    alloc: &mut BarAllocator,
    mut f: impl FnMut(Function<'_, C>),
) -> Result<WalkSummary, WalkError> {
    let mut state = State { last_bus: root, bridges: 0 };
    state.scan(cfg, root, alloc, &mut f)?;
    Ok(WalkSummary { last_bus: state.last_bus, bridges: state.bridges })
}

struct State {
    /// The highest bus number handed out so far.
    last_bus: u8,
    bridges: usize,
}

impl State {
    fn scan<C: ConfigAccess + ?Sized>(
        &mut self,
        cfg: &C,
        bus: u8,
        alloc: &mut BarAllocator,
        f: &mut dyn FnMut(Function<'_, C>),
    ) -> Result<(), WalkError> {
        for device in 0..32 {
            let Some(f0) = Function::new(cfg, Address::new(bus, device, 0)) else {
                continue;
            };
            let functions = if f0.is_multi_function() { 8 } else { 1 };
            self.visit(cfg, f0, alloc, f)?;
            for function in 1..functions {
                if let Some(func) = Function::new(cfg, Address::new(bus, device, function)) {
                    self.visit(cfg, func, alloc, f)?;
                }
            }
        }
        Ok(())
    }

    fn visit<C: ConfigAccess + ?Sized>(
        &mut self,
        cfg: &C,
        func: Function<'_, C>,
        alloc: &mut BarAllocator,
        f: &mut dyn FnMut(Function<'_, C>),
    ) -> Result<(), WalkError> {
        if func.header_type() != 1 {
            if func.header_type() == 0 {
                alloc.assign(&func)?;
            }
            f(func);
            return Ok(());
        }
        self.bridges += 1;
        let primary = func.address().bus;
        let bridge = Bridge { func: &func };
        bridge.close_windows();
        if self.last_bus >= cfg.max_bus() {
            // No bus number left for the far side.
            bridge.set_buses(primary, 0, 0);
            f(func);
            return Ok(());
        }
        self.last_bus += 1;
        let secondary = self.last_bus;
        // Let configuration cycles through to everything that may lie behind
        // while the subtree is discovered.
        bridge.set_buses(primary, secondary, cfg.max_bus());

        // Everything the subtree allocates falls between these two marks.
        alloc.align_to(WINDOW_GRANULE);
        let base = alloc.next;
        self.scan(cfg, secondary, alloc, f)?;
        bridge.set_subordinate(self.last_bus);
        alloc.align_to(WINDOW_GRANULE);
        if alloc.next > base {
            let end = alloc.next - 1;
            if end > u32::MAX as u64 {
                return Err(WalkError::WindowTooHigh);
            }
            bridge.set_memory_window(base as u32, end as u32);
        }
        func.set_command(func.command() | command::MEMORY_SPACE | command::BUS_MASTER);
        f(func);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::reg;
    use super::*;
    use core::cell::RefCell;
    use std::collections::BTreeMap;
    use std::vec::Vec;

    /// A device in a simulated hierarchy. It answers configuration cycles for
    /// bus `b` only when its parent bridge's secondary bus register equals `b`
    /// (the root bus is 0).
    struct Dev {
        parent: Option<usize>,
        device: u8,
        regs: BTreeMap<u16, u32>,
        /// Sizes of 32-bit memory BARs by register offset.
        bars: BTreeMap<u16, u32>,
    }

    struct Topology {
        devs: RefCell<Vec<Dev>>,
        max_bus: u8,
    }

    impl Topology {
        fn add(&self, parent: Option<usize>, device: u8, header: u8, class: u32, bars: &[(u16, u32)]) -> usize {
            let mut regs = BTreeMap::new();
            regs.insert(reg::VENDOR_DEVICE, 0x1234_8086);
            regs.insert(reg::CLASS_REVISION, class);
            regs.insert(reg::HEADER_TYPE, (header as u32) << 16);
            let mut devs = self.devs.borrow_mut();
            devs.push(Dev { parent, device, regs, bars: bars.iter().copied().collect() });
            devs.len() - 1
        }

        fn find(devs: &[Dev], a: Address) -> Option<usize> {
            devs.iter().position(|d| {
                let bus = match d.parent {
                    None => Some(0),
                    // A bridge whose secondary bus is still 0 decodes nothing.
                    Some(p) => {
                        devs.get(p).and_then(|p| p.regs.get(&off::BUSES)).map(|v| (v >> 8) as u8).filter(|&b| b != 0)
                    }
                };
                a.function == 0 && d.device == a.device && bus == Some(a.bus)
            })
        }
    }

    impl ConfigAccess for Topology {
        fn read32(&self, a: Address, offset: u16) -> u32 {
            let devs = self.devs.borrow();
            Self::find(&devs, a).and_then(|i| devs.get(i)).map_or(!0, |d| d.regs.get(&offset).copied().unwrap_or(0))
        }
        fn write32(&self, a: Address, offset: u16, value: u32) {
            let mut devs = self.devs.borrow_mut();
            let Some(d) = Self::find(&devs, a).and_then(|i| devs.get_mut(i)) else { return };
            let value = match d.bars.get(&offset) {
                Some(&size) => value & !(size - 1),
                None if (reg::BAR0..reg::BAR0 + 24).contains(&offset) && d.regs[&reg::HEADER_TYPE] == 0 => 0,
                None if offset == reg::VENDOR_DEVICE || offset == reg::CLASS_REVISION => return,
                None => value,
            };
            d.regs.insert(offset, value);
        }
        fn max_bus(&self) -> u8 {
            self.max_bus
        }
    }

    const BRIDGE: u32 = 0x0604_0000;
    const NIC: u32 = 0x0200_0000;

    /// ```text
    /// bus 0: 1 bridge A, 2 NIC (4K), 3 bridge C (empty)
    /// bus 1 (A): 0 NIC (64K), 1 bridge B
    /// bus 2 (B): 0 NIC (2M)
    /// ```
    fn build(max_bus: u8) -> Topology {
        let t = Topology { devs: RefCell::new(Vec::new()), max_bus };
        let a = t.add(None, 1, 1, BRIDGE, &[]);
        t.add(Some(a), 0, 0, NIC, &[(reg::BAR0, 0x1_0000)]);
        let b = t.add(Some(a), 1, 1, BRIDGE, &[]);
        t.add(Some(b), 0, 0, NIC, &[(reg::BAR0, 0x20_0000)]);
        t.add(None, 2, 0, NIC, &[(reg::BAR0, 0x1000)]);
        t.add(None, 3, 1, BRIDGE, &[]);
        t
    }

    fn window(t: &Topology, i: usize) -> (u32, u32) {
        let v = t.devs.borrow()[i].regs[&off::MEMORY];
        ((v & 0xfff0) << 16, (v & 0xfff0_0000) | 0xf_ffff)
    }

    #[test]
    fn numbers_buses_and_sizes_windows() {
        let t = build(15);
        let mut alloc = BarAllocator::new(0x4000_0000, 0x1000_0000);
        let mut seen = Vec::new();
        let s = walk(&t, 0, &mut alloc, |f| seen.push(f.address())).unwrap();
        assert_eq!(s, WalkSummary { last_bus: 3, bridges: 3 });
        assert_eq!(seen.len(), 6);
        assert!(seen.contains(&Address::new(2, 0, 0)), "found behind two bridges");

        let devs = t.devs.borrow();
        let buses = |i: usize| devs[i].regs[&off::BUSES] & 0xff_ffff;
        assert_eq!(buses(0), 0x02_01_00, "A: pri 0, sec 1, sub 2");
        assert_eq!(buses(2), 0x02_02_01, "B: pri 1, sec 2, sub 2");
        assert_eq!(buses(5), 0x03_03_00, "C: pri 0, sec 3, sub 3");
        drop(devs);

        let (bb, be) = window(&t, 2);
        let (ab, ae) = window(&t, 0);
        assert!(be - bb + 1 >= 0x20_0000, "B's window covers its NIC (plus alignment padding)");
        assert!(ab <= bb && be <= ae, "A's window contains B's");
        let devs = t.devs.borrow();
        let behind_b = devs[3].regs[&reg::BAR0];
        assert!((bb..=be).contains(&behind_b));
        assert!((ab..=ae).contains(&devs[1].regs[&reg::BAR0]));
        let root_nic = devs[4].regs[&reg::BAR0];
        assert!(root_nic != 0 && !(ab..=ae).contains(&root_nic), "root NIC lies outside A's window");
        assert_eq!(devs[0].regs[&reg::COMMAND_STATUS] & 6, 6);
        // C had nothing behind it: base above limit.
        assert_eq!(devs[5].regs[&off::MEMORY], 0xfff0);
    }

    #[test]
    fn bridge_accessors() {
        let t = build(15);
        let mut alloc = BarAllocator::new(0x4000_0000, 0x1000_0000);
        walk(&t, 0, &mut alloc, |_| {}).unwrap();
        let f = Function::new(&t, Address::new(0, 1, 0)).unwrap();
        let b = Bridge::new(&f).unwrap();
        assert_eq!((b.primary_bus(), b.secondary_bus(), b.subordinate_bus()), (0, 1, 2));
        let (base, end) = b.memory_window().unwrap();
        assert_eq!(base % 0x10_0000, 0);
        assert!(end > base);
        let c = Function::new(&t, Address::new(0, 3, 0)).unwrap();
        assert_eq!(Bridge::new(&c).unwrap().memory_window(), None);
        let nic = Function::new(&t, Address::new(0, 2, 0)).unwrap();
        assert!(Bridge::new(&nic).is_none());
    }

    #[test]
    fn runs_out_of_bus_numbers() {
        let t = build(1);
        let mut alloc = BarAllocator::new(0x4000_0000, 0x1000_0000);
        let s = walk(&t, 0, &mut alloc, |_| {}).unwrap();
        assert_eq!(s.last_bus, 1);
        let devs = t.devs.borrow();
        assert_eq!(devs[0].regs[&off::BUSES] & 0xff_ffff, 0x01_01_00, "A gets bus 1");
        assert_eq!(devs[2].regs[&off::BUSES] >> 8 & 0xff, 0, "B has no bus left");
        assert_eq!(devs[5].regs[&off::BUSES] >> 8 & 0xff, 0, "C has no bus left");
    }

    #[test]
    fn window_above_4g_is_an_error() {
        let t = build(15);
        let mut alloc = BarAllocator::new(0x1_0000_0000, 0x1000_0000);
        assert_eq!(walk(&t, 0, &mut alloc, |_| {}), Err(WalkError::Bar(BarError::OutOfSpace)));
    }
}
