//! Garbage in, no panic out: PCI capability parsing and USB descriptor walking over random bytes.
#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use osmium_hal::mmio::IoMem;
use osmium_hal::pci::{Address, ConfigAccess, Function};
use osmium_hal::usb::{
    ConfigurationDescriptor, Descriptors, DeviceDescriptor, EndpointDescriptor, InterfaceDescriptor,
};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

/// A function's 4 KiB configuration space, with writes absorbed.
struct RandomConfig(Vec<u32>);

impl ConfigAccess for RandomConfig {
    fn read32(&self, _: Address, offset: u16) -> u32 {
        self.0.get(offset as usize / 4).copied().unwrap_or(!0)
    }
    fn write32(&self, _: Address, _: u16, _: u32) {}
}

#[test]
fn pci_capabilities_over_random_config_space() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for round in 0..4000 {
        let mut space: Vec<u32> = (0..1024).map(|_| rng.next() as u32).collect();
        // Make most functions present, with a capability list and sometimes an extended one.
        space[0] = 0x0010_1b36;
        space[1] |= 1 << 20;
        space[3] &= !0x007f_0000;
        // Plant plausible capability IDs so the MSI, MSI-X and SR-IOV paths run.
        if round % 2 == 0 {
            let at = 0x40 + (rng.next() as usize % 0x30) * 4;
            let id = [0x05, 0x11][rng.next() as usize % 2];
            space[at / 4] = space[at / 4] & !0xff | id;
            space[0x34 / 4] = at as u32;
        }
        if round % 3 == 0 {
            space[0x100 / 4] = 0x0001_0010 | ((rng.next() as u32 & 0xff) << 22);
        }
        let cfg = RandomConfig(space);
        let f = Function::new(&cfg, Address::new(0, 1, 0)).unwrap();
        let _ = f.capabilities().count();
        let _ = f.extended_capabilities().count();
        for i in 0..8 {
            let _ = f.bar(i);
        }
        let _ = f.class();
        if let Ok(msi) = f.msi() {
            let _ = (msi.max_vectors(), msi.is_64bit(), msi.per_vector_masking());
            let _ = msi.is_pending(&f, rng.next() as u8);
        }
        if let Ok(msix) = f.msix() {
            let mut mem = vec![0u32; 256];
            // SAFETY: the window covers a local buffer that outlives its use.
            let io = unsafe { IoMem::new(mem.as_mut_ptr().cast(), 1024) };
            if let Ok(t) = msix.table(&io) {
                let _ = t.message(rng.next() as u16);
                let _ = t.set_masked(rng.next() as u16, true);
            }
            if let Ok(p) = msix.pba(&io) {
                let _ = p.is_pending(rng.next() as u16);
            }
        }
        if let Ok(sriov) = f.sriov() {
            for i in 0..8 {
                let _ = sriov.vf_bar(&f, i);
            }
            for i in [0, 1, 255, 0xffff] {
                let _ = sriov.vf_address(&f, i);
            }
        }
    }
}

#[test]
fn usb_descriptors_over_random_bytes() {
    let mut rng = Rng(0x1234_5678_9abc_def1);
    for _ in 0..20000 {
        let n = rng.next() as usize % 80;
        let mut buf = rng.bytes(n);
        // Bias towards walkable descriptors.
        if buf.len() > 2 && rng.next() % 2 == 0 {
            buf[0] = (rng.next() % 12) as u8;
            buf[1] = (rng.next() % 6) as u8;
        }
        for d in Descriptors::new(&buf) {
            let _ = d;
        }
        let _ = ConfigurationDescriptor::parse(&buf);
        let _ = InterfaceDescriptor::parse(&buf);
        let _ = EndpointDescriptor::parse(&buf);
        if let Ok(d) = DeviceDescriptor::parse(&buf) {
            let _ = d.max_packet_size0();
        }
    }
}
