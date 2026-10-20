//! Booting PC guests the PVH way: the `hvm_start_info` a PVH kernel finds
//! in `ebx`, its memory map, and the ACPI tables (RSDP, XSDT and a MADT
//! listing the local APICs and the I/O APIC) it reads its CPUs and
//! interrupt routing from.

use alloc::vec;
use alloc::vec::Vec;

/// `hvm_start_info.magic`.
const PVH_MAGIC: u32 = 0x336e_c578;
/// `XEN_ELFNOTE_PHYS32_ENTRY`: the note a PVH kernel's 32-bit entry is in.
const PHYS32_ENTRY: u32 = 18;

/// A PC guest's machine, as its PVH start information and ACPI tables
/// describe it.
pub struct PcBoot<'src> {
    /// Number of CPUs; their local APIC IDs are 0, 1, ...
    pub cpus: u32,
    /// RAM as (base, size).
    pub memory: &'src [(u64, u64)],
    /// The I/O APIC as (ID, MMIO address); its GSIs start at 0.
    pub ioapic: Option<(u8, u32)>,
    /// Kernel command line.
    pub cmdline: &'src str,
}

/// The blob [`PcBoot::build`] writes, and where its parts are.
pub struct PcBootBlob {
    /// Bytes to copy into guest RAM at the address passed to `build`.
    pub bytes: Vec<u8>,
    /// Guest-physical address of the `hvm_start_info` (the kernel's `ebx`).
    pub start_info: u64,
    /// Guest-physical address of the RSDP.
    pub rsdp: u64,
}

fn put(buf: &mut [u8], at: usize, v: &[u8]) {
    buf[at..at + v.len()].copy_from_slice(v);
}

/// Sets byte `at` so that `bytes` sums to zero.
fn checksum(bytes: &mut [u8], at: usize) {
    bytes[at] = 0;
    let sum = bytes.iter().fold(0u8, |s, &b| s.wrapping_add(b));
    bytes[at] = sum.wrapping_neg();
}

/// An ACPI table: the 36-byte header (revision 1, OEM "OSMIUM") and `body`.
fn table(sig: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut t = vec![0u8; 36 + body.len()];
    put(&mut t, 0, sig);
    let len = t.len() as u32;
    put(&mut t, 4, &len.to_le_bytes());
    t[8] = 1;
    put(&mut t, 10, b"OSMIUM");
    put(&mut t, 16, b"OSMIUMVM");
    put(&mut t, 24, &1u32.to_le_bytes());
    put(&mut t, 28, b"OSMM");
    put(&mut t, 32, &1u32.to_le_bytes());
    put(&mut t, 36, body);
    checksum(&mut t, 9);
    t
}

impl PcBoot<'_> {
    /// Lays out the start info, memory map, command line and ACPI tables
    /// for guest-physical address `at` (16-byte aligned, inside RAM the
    /// guest leaves alone until it has read them, such as its first page
    /// above zero).
    pub fn build(&self, at: u64) -> PcBootBlob {
        // MADT: local APIC address, flags (PC-AT compatible: 8259s present),
        // then one processor-local APIC per CPU and the I/O APIC.
        let mut madt = Vec::new();
        madt.extend_from_slice(&0xfee0_0000u32.to_le_bytes());
        madt.extend_from_slice(&1u32.to_le_bytes());
        for c in 0..self.cpus {
            madt.extend_from_slice(&[0, 8, c as u8, c as u8]);
            madt.extend_from_slice(&1u32.to_le_bytes()); // enabled
        }
        if let Some((id, addr)) = self.ioapic {
            madt.extend_from_slice(&[1, 12, id, 0]);
            madt.extend_from_slice(&addr.to_le_bytes());
            madt.extend_from_slice(&0u32.to_le_bytes()); // GSI base
        }
        let madt = table(b"APIC", &madt);

        // Offsets in the blob.
        let info_off = 0usize;
        let memmap_off = 64;
        let cmdline_off = memmap_off + 24 * self.memory.len();
        let rsdp_off = (cmdline_off + self.cmdline.len() + 1).next_multiple_of(16);
        let xsdt_off = rsdp_off + 36;
        let madt_off = (xsdt_off + 36 + 8).next_multiple_of(8);
        let mut b = vec![0u8; madt_off + madt.len()];
        let gpa = |off: usize| at + off as u64;

        // hvm_start_info, version 1.
        put(&mut b, info_off, &PVH_MAGIC.to_le_bytes());
        put(&mut b, info_off + 4, &1u32.to_le_bytes());
        put(&mut b, info_off + 24, &gpa(cmdline_off).to_le_bytes());
        put(&mut b, info_off + 32, &gpa(rsdp_off).to_le_bytes());
        put(&mut b, info_off + 40, &gpa(memmap_off).to_le_bytes());
        put(&mut b, info_off + 48, &(self.memory.len() as u32).to_le_bytes());
        for (i, &(base, size)) in self.memory.iter().enumerate() {
            let e = memmap_off + 24 * i;
            put(&mut b, e, &base.to_le_bytes());
            put(&mut b, e + 8, &size.to_le_bytes());
            put(&mut b, e + 16, &1u32.to_le_bytes()); // RAM
        }
        put(&mut b, cmdline_off, self.cmdline.as_bytes());

        // XSDT with the MADT as its one entry.
        let xsdt = table(b"XSDT", &gpa(madt_off).to_le_bytes());
        put(&mut b, xsdt_off, &xsdt);
        put(&mut b, madt_off, &madt);

        // RSDP, revision 2: the first 20 bytes checksum, then all 36.
        let mut r = [0u8; 36];
        put(&mut r, 0, b"RSD PTR ");
        put(&mut r, 9, b"OSMIUM");
        r[15] = 2;
        put(&mut r, 20, &36u32.to_le_bytes());
        put(&mut r, 24, &gpa(xsdt_off).to_le_bytes());
        checksum(&mut r[..20], 8);
        checksum(&mut r, 32);
        put(&mut b, rsdp_off, &r);

        PcBootBlob { bytes: b, start_info: gpa(info_off), rsdp: gpa(rsdp_off) }
    }
}

/// The 32-bit PVH entry point a kernel image advertises in its
/// `XEN_ELFNOTE_PHYS32_ENTRY` note, found by scanning `image` (an ELF file)
/// for the note.
pub fn pvh_entry(image: &[u8]) -> Option<u32> {
    // namesz 4, descsz 4 (or 8), type 18, "Xen\0", then the entry.
    image.windows(16).enumerate().find_map(|(i, w)| {
        let le = |o: usize| u32::from_le_bytes(w[o..o + 4].try_into().expect("fixed-width slice"));
        (le(0) == 4 && matches!(le(4), 4 | 8) && le(8) == PHYS32_ENTRY && &w[12..16] == b"Xen\0")
            .then(|| image.get(i + 16..i + 20))
            .flatten()
            .map(|e| u32::from_le_bytes(e.try_into().expect("fixed-width slice")))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use osmium_boot::acpi::{Acpi, Madt};
    use osmium_boot::pvh::StartInfo;

    #[test]
    fn parses_back() {
        let pc = PcBoot {
            cpus: 2,
            memory: &[(0, 0xa_0000), (0x10_0000, 0x3f0_0000)],
            ioapic: Some((2, 0xfec0_0000)),
            cmdline: "console=ttyS0",
        };
        let at = 0x1000;
        let blob = pc.build(at);
        // Parse it back with osmium-boot, as an osmium guest would.
        let mut ram = vec![0u8; 0x1000];
        ram.extend_from_slice(&blob.bytes);
        let read = |pa: u64, len: usize| ram.get(pa as usize..pa as usize + len);
        let off = blob.start_info as usize;
        let mm = 0x1000 + 64;
        let info = StartInfo::parse(&ram[off..off + 56], &ram[mm..mm + 48], &[], None).unwrap();
        assert_eq!(info.rsdp().map(|p| p.0), Some(blob.rsdp));
        assert_eq!(info.memory_map().count(), 2);
        let acpi = Acpi::new(blob.rsdp, read).unwrap();
        let madt = acpi.find(b"APIC").and_then(Madt::parse).unwrap();
        let ids: Vec<u8> = madt.local_apics().filter(|c| c.enabled).map(|c| c.apic_id as u8).collect();
        assert_eq!(ids, [0, 1]);
        let io = madt.io_apics().next().unwrap();
        assert_eq!((io.addr, io.gsi_base), (0xfec0_0000, 0));
    }

    #[test]
    fn finds_the_pvh_note() {
        let mut image = vec![0u8; 64];
        image.extend_from_slice(&[4, 0, 0, 0, 4, 0, 0, 0, 18, 0, 0, 0]);
        image.extend_from_slice(b"Xen\0");
        image.extend_from_slice(&0x0010_0abcu32.to_le_bytes());
        assert_eq!(pvh_entry(&image), Some(0x0010_0abc));
        assert_eq!(pvh_entry(&[0; 64]), None);
    }
}
