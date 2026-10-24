//! Garbage in, no panic out: every firmware and image parser fed random, truncated and mutated input from a
//! fixed seed. Valid seeds are mutated so the fuzzing reaches past the first header check.
#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use osmium_boot::acpi::{Acpi, Dmar, Ivrs, Madt, Mcfg};
use osmium_boot::elf::Elf;
use osmium_boot::fdt::{Fdt, FdtWriter};
use osmium_boot::multiboot2::BootInfo;
use osmium_boot::pe;
use osmium_boot::pvh::StartInfo;
use osmium_mm::{MemoryMap, PhysAddr};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        self.next() as usize % n.max(1)
    }

    fn upto(&mut self, max: usize) -> Vec<u8> {
        let n = self.below(max);
        self.bytes(n)
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }

    /// `seed` with a few bytes replaced (some with boundary values), and sometimes truncated.
    fn mutate(&mut self, seed: &[u8]) -> Vec<u8> {
        let mut v = seed.to_vec();
        for _ in 0..1 + self.below(6) {
            if v.is_empty() {
                break;
            }
            let at = self.below(v.len());
            v[at] = match self.below(4) {
                0 => 0,
                1 => 0xff,
                _ => self.next() as u8,
            };
        }
        if self.below(4) == 0 {
            v.truncate(self.below(v.len() + 1));
        }
        v
    }
}

fn sample_fdt() -> Vec<u8> {
    let mut w = FdtWriter::new();
    w.reserve_memory(0x1000, 0x1000);
    w.begin_node("");
    w.property_u32("#address-cells", 2);
    w.property_u32("#size-cells", 2);
    w.property_string("compatible", "riscv-virtio");
    w.begin_node("chosen");
    w.property_string("bootargs", "console=ttyS0");
    w.property_u64("linux,initrd-start", 0x8400_0000);
    w.property_u64("linux,initrd-end", 0x8410_0000);
    w.end_node();
    w.begin_node("memory@80000000");
    w.property_string("device_type", "memory");
    w.property_cells("reg", &[0, 0x8000_0000, 0, 0x800_0000]);
    w.end_node();
    w.begin_node("reserved-memory");
    w.begin_node("resv@80000000");
    w.property_cells("reg", &[0, 0x8000_0000, 0, 0x4_0000]);
    w.end_node();
    w.end_node();
    w.begin_node("soc");
    w.begin_node("uart@10000000");
    w.property_string("compatible", "ns16550a");
    w.property_cells("reg", &[0, 0x1000_0000, 0, 0x100]);
    w.property_cells("interrupts", &[10]);
    w.end_node();
    w.end_node();
    w.end_node();
    w.finish(0)
}

fn walk_fdt(blob: &[u8]) {
    let Ok(fdt) = Fdt::new(blob) else { return };
    let _ = fdt.bootargs();
    let _ = fdt.initrd();
    let _ = fdt.memory().count();
    let _ = fdt.reservations().count();
    let _ = fdt.find_node("/soc/uart");
    let _ = fdt.find_compatible(&["ns16550a"]);
    for n in fdt.all_nodes().take(10_000) {
        let _ = n.name();
        let _ = n.properties().count();
        let _ = n.children().count();
        let _ = n.reg().count();
        let _ = n.compatible().count();
        let _ = n.interrupts().count();
        for p in n.properties() {
            let _ = (p.as_u32(), p.as_u64(), p.as_str(), p.as_str_list().count(), p.as_u32_cells().count());
        }
    }
    let mut map = MemoryMap::<8>::new();
    let _ = fdt.fill_memory_map(&mut map, Some(PhysAddr::new(0x8000_0000)));
}

#[test]
fn fdt_survives_garbage() {
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    let seed = sample_fdt();
    walk_fdt(&seed);
    for _ in 0..20_000 {
        walk_fdt(&rng.mutate(&seed));
    }
    for _ in 0..2000 {
        let n = rng.below(300);
        let mut v = rng.bytes(n);
        // A plausible header so the walk gets past validation.
        if v.len() >= 40 {
            v[..4].copy_from_slice(&0xd00d_feedu32.to_be_bytes());
            let n = v.len() as u32;
            v[4..8].copy_from_slice(&n.to_be_bytes());
            v[20..24].copy_from_slice(&17u32.to_be_bytes());
            v[24..28].copy_from_slice(&16u32.to_be_bytes());
        }
        walk_fdt(&v);
    }
}

/// A table with a correct checksum around `body`.
fn acpi_table(sig: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut t = sig.to_vec();
    t.extend_from_slice(&(36 + body.len() as u32).to_le_bytes());
    t.extend_from_slice(&[1, 0]);
    t.extend_from_slice(&[0; 26]);
    t.extend_from_slice(body);
    let sum = t.iter().fold(0u8, |a, &b| a.wrapping_add(b));
    t[9] = 0u8.wrapping_sub(sum);
    t
}

fn parse_acpi_tables(memory: &[u8]) {
    let read = |pa: u64, len: usize| -> Option<&[u8]> {
        let start = usize::try_from(pa).ok()?;
        memory.get(start..start.checked_add(len)?)
    };
    let Ok(acpi) = Acpi::new(0, read) else { return };
    for t in acpi.tables() {
        let _ = (t.signature(), t.body().len());
        if let Some(madt) = Madt::parse(t) {
            let _ = madt.local_apics().count();
            let _ = madt.io_apics().count();
            let _ = madt.overrides().count();
            let _ = madt.isa_irq(9);
        }
        if let Some(m) = Mcfg::parse(t) {
            let _ = m.entries().count();
        }
        if let Some(d) = Dmar::parse(t) {
            let _ = d.units().count();
        }
        if let Some(i) = Ivrs::parse(t) {
            let _ = i.units().count();
        }
    }
}

/// Memory holding an RSDP at 0, an RSDT at 0x40 and four tables after it, with `bodies` for the tables.
fn acpi_memory(bodies: [&[u8]; 4]) -> Vec<u8> {
    let sigs = [b"APIC", b"MCFG", b"DMAR", b"IVRS"];
    let mut mem = vec![0u8; 0x40];
    let mut entries = Vec::new();
    let mut tables = Vec::new();
    let mut at = 0x200u32;
    for (sig, body) in sigs.iter().zip(bodies) {
        entries.extend_from_slice(&at.to_le_bytes());
        let t = acpi_table(sig, body);
        at += t.len() as u32;
        tables.push(t);
    }
    let rsdt = acpi_table(b"RSDT", &entries);
    mem[..8].copy_from_slice(b"RSD PTR ");
    mem[16..20].copy_from_slice(&0x40u32.to_le_bytes());
    let sum = mem[..20].iter().fold(0u8, |a, &b| a.wrapping_add(b));
    mem[8] = 0u8.wrapping_sub(sum);
    mem.extend_from_slice(&rsdt);
    mem.resize(0x200, 0);
    for t in tables {
        mem.extend_from_slice(&t);
    }
    mem
}

#[test]
fn acpi_survives_garbage() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let madt = [
        &0xfee0_0000u32.to_le_bytes()[..],
        &[1, 0, 0, 0],
        &[0, 8, 0, 0, 1, 0, 0, 0],
        &[5, 12, 0, 0, 0, 0, 0, 0xfe, 0, 0, 0, 0],
    ]
    .concat();
    let mcfg = [&[0u8; 8][..], &[0, 0, 0, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0, 0, 0, 0]].concat();
    let dmar = [&[0u8; 12][..], &[0, 0, 16, 0, 1, 0, 0, 0, 0, 0, 0x10, 0, 0, 0, 0, 0]].concat();
    let ivrs =
        [&[0u8; 12][..], &[0x10, 0, 24, 0, 8, 0, 0, 0, 0, 0, 0x20, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]].concat();
    let seed = acpi_memory([&madt, &mcfg, &dmar, &ivrs]);
    parse_acpi_tables(&seed);
    for _ in 0..30_000 {
        let m = rng.mutate(&seed);
        parse_acpi_tables(&m);
    }
    // Garbage bodies behind valid checksums reach every table parser.
    for _ in 0..10_000 {
        let bodies = [rng.bytes(80), rng.bytes(80), rng.bytes(80), rng.bytes(80)];
        parse_acpi_tables(&acpi_memory([&bodies[0], &bodies[1], &bodies[2], &bodies[3]]));
    }
}

fn sample_elf() -> Vec<u8> {
    let mut f = vec![0u8; 0x200];
    f[..4].copy_from_slice(b"\x7fELF");
    f[4] = 2;
    f[5] = 1;
    f[16..18].copy_from_slice(&2u16.to_le_bytes());
    f[18..20].copy_from_slice(&62u16.to_le_bytes());
    f[24..32].copy_from_slice(&0x40_1000u64.to_le_bytes());
    f[32..40].copy_from_slice(&64u64.to_le_bytes());
    f[54..56].copy_from_slice(&56u16.to_le_bytes());
    f[56..58].copy_from_slice(&2u16.to_le_bytes());
    for (at, flags, off, va, filesz, memsz) in
        [(64usize, 5u32, 0x180u64, 0x40_1000u64, 4u64, 4u64), (120, 6, 0x184, 0x40_2000, 2, 0x102)]
    {
        f[at..at + 4].copy_from_slice(&1u32.to_le_bytes());
        f[at + 4..at + 8].copy_from_slice(&flags.to_le_bytes());
        f[at + 8..at + 16].copy_from_slice(&off.to_le_bytes());
        f[at + 16..at + 24].copy_from_slice(&va.to_le_bytes());
        f[at + 32..at + 40].copy_from_slice(&filesz.to_le_bytes());
        f[at + 40..at + 48].copy_from_slice(&memsz.to_le_bytes());
        f[at + 48..at + 56].copy_from_slice(&0x1000u64.to_le_bytes());
    }
    f
}

#[test]
fn elf_survives_garbage() {
    let mut rng = Rng(0xdead_beef_cafe_f00d);
    let seed = sample_elf();
    for _ in 0..30_000 {
        let m = rng.mutate(&seed);
        if let Ok(elf) = Elf::new(&m) {
            let _ = (elf.machine(), elf.entry(), elf.is_pie());
            for s in elf.segments() {
                let _ = (s.vaddr, s.data.len(), s.mem_size);
            }
        }
    }
    for _ in 0..5000 {
        let g = rng.upto(200);
        let _ = Elf::new(&g);
    }
}

fn sample_pe() -> Vec<u8> {
    let mut f = vec![0u8; 0x400];
    f[0..2].copy_from_slice(b"MZ");
    f[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    f[0x40..0x44].copy_from_slice(b"PE\0\0");
    f[0x44..0x46].copy_from_slice(&0x8664u16.to_le_bytes());
    f[0x46..0x48].copy_from_slice(&2u16.to_le_bytes());
    f[0x54..0x56].copy_from_slice(&240u16.to_le_bytes());
    let o = 0x58;
    f[o..o + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
    f[o + 16..o + 20].copy_from_slice(&0x1000u32.to_le_bytes());
    f[o + 24..o + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
    f[o + 32..o + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    f[o + 56..o + 60].copy_from_slice(&0x3000u32.to_le_bytes());
    f[o + 60..o + 64].copy_from_slice(&0x200u32.to_le_bytes());
    f[o + 68..o + 70].copy_from_slice(&10u16.to_le_bytes());
    f[o + 108..o + 112].copy_from_slice(&16u32.to_le_bytes());
    f[o + 152..o + 156].copy_from_slice(&0x2000u32.to_le_bytes());
    f[o + 156..o + 160].copy_from_slice(&12u32.to_le_bytes());
    for (i, (va, raw)) in [(0x1000u32, 0x200u32), (0x2000, 0x300)].iter().enumerate() {
        let h = o + 240 + i * 40;
        f[h + 8..h + 12].copy_from_slice(&0x100u32.to_le_bytes());
        f[h + 12..h + 16].copy_from_slice(&va.to_le_bytes());
        f[h + 16..h + 20].copy_from_slice(&0x100u32.to_le_bytes());
        f[h + 20..h + 24].copy_from_slice(&raw.to_le_bytes());
    }
    f[0x300..0x304].copy_from_slice(&0x1000u32.to_le_bytes());
    f[0x304..0x308].copy_from_slice(&12u32.to_le_bytes());
    f[0x308..0x30A].copy_from_slice(&((10u16 << 12) | 8).to_le_bytes());
    f
}

#[test]
fn pe_survives_garbage() {
    let mut rng = Rng(0x0123_4567_89ab_cdef);
    let seed = sample_pe();
    let mut mem = vec![0u8; 0x4000];
    for _ in 0..30_000 {
        let m = rng.mutate(&seed);
        if let Ok(info) = pe::parse(&m, pe::MACHINE_X86_64) {
            // Destinations both big enough and too small for the image.
            let dest_len = if rng.below(4) == 0 { rng.below(0x4000) } else { 0x4000 };
            let dest = &mut mem[..dest_len];
            if pe::load(&m, &info, dest, 0x20_0000).is_ok() {
                let n = pe::count_fixups(dest, &info).unwrap_or(0);
                let mut fixups = vec![pe::Fixup { rva: 0, reserved: 0, value: 0 }; n + 1];
                let _ = pe::collect_fixups(dest, &info, &mut fixups);
                pe::rebase(dest, &fixups, 0x1000);
            }
        }
    }
    for _ in 0..5000 {
        let g = rng.upto(300);
        let _ = pe::parse(&g, pe::MACHINE_X86_64);
    }
}

#[test]
fn multiboot2_and_pvh_survive_garbage() {
    let mut rng = Rng(0x1357_9bdf_2468_ace0);
    // Multiboot2: a total size and tags of random type and size.
    let mut seed = vec![0u8; 8];
    for (typ, payload) in
        [(1u32, &b"root=/dev/vda\0"[..]), (3, &[0, 0, 0x20, 0, 0, 0, 0x30, 0, b'm', 0]), (8, &[0u8; 30][..])]
    {
        seed.extend_from_slice(&typ.to_le_bytes());
        seed.extend_from_slice(&(8 + payload.len() as u32).to_le_bytes());
        seed.extend_from_slice(payload);
        while seed.len() % 8 != 0 {
            seed.push(0);
        }
    }
    let total = seed.len() as u32;
    seed[..4].copy_from_slice(&total.to_le_bytes());
    for round in 0..30_000 {
        let m = if round % 3 == 0 {
            let mut g = rng.upto(120);
            if g.len() >= 4 {
                let n = g.len() as u32;
                g[..4].copy_from_slice(&n.to_le_bytes());
            }
            g
        } else {
            rng.mutate(&seed)
        };
        if let Ok(info) = BootInfo::new(&m) {
            let _ = (info.cmdline(), info.loader_name(), info.rsdp(), info.framebuffer());
            let _ = info.modules().count();
            let _ = info.memory_map().count();
            let _ = info.tags().count();
            let mut map = MemoryMap::<8>::new();
            let _ = info.fill_memory_map(&mut map, Some(PhysAddr::new(0x1000)));
        }
        let (h, a, b) = (rng.bytes(60), rng.upto(100), rng.upto(100));
        let mut h = h;
        h[..4].copy_from_slice(&0x336e_c578u32.to_le_bytes());
        let c = rng.upto(20);
        if let Ok(info) = StartInfo::parse(&h, &a, &b, Some(&c)) {
            let _ = (info.version(), info.cmdline(), info.rsdp());
            let _ = info.memory_map().count();
            let _ = info.modules().count();
            let mut map = MemoryMap::<8>::new();
            let _ = info.fill_memory_map(&mut map);
        }
    }
}
