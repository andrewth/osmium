#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::unreachable)]
//! A guest can issue any access to any device register: every offset and size
//! must read as something and write as nothing, never panic.

use std::sync::Arc;

use osmium_virt::devices::{
    Pl011, Uart16550, VirtualGicV2, VirtualIoApic, VirtualLapic, VirtualPic, VirtualPit, VirtualPlic,
};
use osmium_virt::memory::GuestMemory;
use osmium_virt::virtio::{VirtioConsole, VirtioMmio};
use osmium_virt::x86::pc::pvh_entry;
use osmium_virt::{BusDevice, GuestPhysAddr};

/// Reads and writes every size at a spread of offsets, including ones near the top of the address space.
fn hammer(dev: &dyn BusDevice, window: u64) {
    let mut offsets: Vec<u64> = (0..window.min(0x3000)).collect();
    offsets.extend((0..64).map(|i| window.wrapping_add(i)));
    offsets.extend([0x1_0000, 0x20_0000, 0x20_1000, 0x40_0000, u64::MAX - 8, u64::MAX - 1, u64::MAX]);
    for off in offsets {
        for size in [0usize, 1, 2, 3, 4, 8, 16, 33] {
            let mut buf = vec![0xa5u8; size];
            dev.read(off, &mut buf);
            dev.write(off, &vec![0xffu8; size]);
            dev.write(off, &vec![0u8; size]);
        }
    }
}

#[test]
fn devices_survive_any_access() {
    let pic = Arc::new(VirtualPic::new(|_| {}));
    hammer(&*pic.master(), 2);
    hammer(&*pic.slave(), 2);

    let gic = Arc::new(VirtualGicV2::with_cpus(2, 64, |_, _| {}));
    hammer(&*gic.distributor_for(0), 0x1000);
    hammer(&*gic.cpu_interface_for(1), 0x1000);
    // A window for a CPU that does not exist.
    hammer(&*gic.distributor_for(9), 0x1000);
    hammer(&*gic.cpu_interface_for(99), 0x1000);

    hammer(&VirtualPlic::new(32, 2, |_, _| {}), 0x40_0000);
    hammer(&VirtualPlic::new(0, 0, |_, _| {}), 0x40_0000);
    hammer(&VirtualIoApic::new(0, |_| {}), 0x20);
    hammer(&VirtualLapic::new(0, 1_000_000, || 0, |_| {}), 0x1000);
    hammer(&VirtualLapic::new(0, 0, || 1_000_000_000, |_| {}), 0x1000);
    let pit = Arc::new(VirtualPit::new(|| 5_000_000, |_| {}));
    hammer(&*pit, 4);
    hammer(&*pit.port_b(), 1);
    hammer(&Pl011::new(|_| {}), 0x1000);
    hammer(&Uart16550::new(|_| {}), 8);

    let mem = Arc::new(GuestMemory::new());
    let con = VirtioMmio::new(VirtioConsole::new(|_| {}), mem, |_| {});
    hammer(&con, 0x1000);
}

#[test]
fn guest_memory_rejects_wrapping_ranges() {
    let mut backing = vec![0u8; 0x1000];
    let mut mem = GuestMemory::new();
    // SAFETY: `backing` outlives `mem` and is not otherwise accessed.
    assert!(unsafe { mem.add_region(GuestPhysAddr(0x1000), backing.as_mut_ptr(), 0x1000) });
    // A region that would wrap the address space is refused.
    // SAFETY: as above.
    assert!(!unsafe { mem.add_region(GuestPhysAddr(u64::MAX - 4), backing.as_mut_ptr(), 0x1000) });
    let mut b = [0u8; 16];
    assert!(mem.read(GuestPhysAddr(u64::MAX - 3), &mut b).is_err());
    assert!(mem.write(GuestPhysAddr(u64::MAX), &b).is_err());
    assert!(mem.read(GuestPhysAddr(0x1ff8), &mut b).is_err());
    assert!(mem.read(GuestPhysAddr(0x1ff0), &mut b).is_ok());
    drop(mem);
    drop(backing);
}

#[test]
fn pvh_entry_ignores_truncated_notes() {
    assert_eq!(pvh_entry(&[]), None);
    assert_eq!(pvh_entry(&[4, 0, 0, 0, 4, 0, 0, 0, 18, 0, 0, 0, b'X', b'e', b'n', 0]), None, "no entry word");
    let mut note = vec![4, 0, 0, 0, 4, 0, 0, 0, 18, 0, 0, 0, b'X', b'e', b'n', 0, 0x78, 0x56, 0x34, 0x12];
    assert_eq!(pvh_entry(&note), Some(0x1234_5678));
    note.truncate(18);
    assert_eq!(pvh_entry(&note), None);
}
