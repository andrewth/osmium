//! A minimal ACPI table reader: enough to find CPUs, I/O APICs and PCI
//! ECAM windows without an AML interpreter.
//!
//! Tables are read through a caller-supplied function that turns a physical
//! address and length into a byte slice, so the reader works identity-mapped
//! at boot or through any later mapping.
//!
//! ```ignore
//! let acpi = Acpi::new(rsdp, |pa, len| Some(unsafe { core::slice::from_raw_parts(pa as *const u8, len) }))?;
//! let madt = Madt::parse(acpi.find(b"APIC").unwrap()).unwrap();
//! for cpu in madt.local_apics().filter(|c| c.enabled) { /* start it */ }
//! ```

use crate::{le32, le64};

/// Why the tables could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcpiError {
    /// No `RSD PTR ` signature or bad checksum.
    BadRsdp,
    /// The RSDT/XSDT is unreadable or its checksum is wrong.
    BadRoot,
    /// The physical-memory reader refused a range.
    Unreadable,
}

/// A system description table, header included.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Table<'src> {
    /// The whole table, `length` bytes.
    pub data: &'src [u8],
}

const HEADER: usize = 36;
/// Largest table length believed. Real tables are at most a few hundred
/// KiB (the DSDT is usually the biggest).
const MAX_TABLE: usize = 1 << 20;

impl<'src> Table<'src> {
    /// The four-byte signature (`b"APIC"`, `b"MCFG"`, ...).
    pub fn signature(&self) -> [u8; 4] {
        self.data[..4].try_into().expect("fixed-width slice")
    }

    /// Table contents after the standard header.
    pub fn body(&self) -> &'src [u8] {
        &self.data[HEADER..]
    }
}

fn checksum_ok(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |a, &b| a.wrapping_add(b)) == 0
}

/// The ACPI root: the RSDT or XSDT found through the RSDP.
pub struct Acpi<'src, F> {
    read: F,
    root: Table<'src>,
    /// True for the XSDT (64-bit entries).
    wide: bool,
}

impl<'src, F: Fn(u64, usize) -> Option<&'src [u8]>> Acpi<'src, F> {
    /// Validates the RSDP at physical address `rsdp` and its root table.
    ///
    /// `read(pa, len)` should return exactly `len` bytes; a slice of any
    /// other length counts as unreadable.
    pub fn new(rsdp: u64, read: F) -> Result<Self, AcpiError> {
        let r = Self::read_exact(&read, rsdp, 20).ok_or(AcpiError::Unreadable)?;
        if &r[..8] != b"RSD PTR " || !checksum_ok(r) {
            return Err(AcpiError::BadRsdp);
        }
        let (root_pa, wide) = if r[15] >= 2 {
            let r2 = Self::read_exact(&read, rsdp, 36).ok_or(AcpiError::Unreadable)?;
            if !checksum_ok(r2) {
                return Err(AcpiError::BadRsdp);
            }
            (le64(r2, 24).ok_or(AcpiError::BadRsdp)?, true)
        } else {
            (le32(r, 16).ok_or(AcpiError::BadRsdp)? as u64, false)
        };
        let root = Self::table_at(&read, root_pa).ok_or(AcpiError::BadRoot)?;
        Ok(Self { read, root, wide })
    }

    /// Calls `read`, rejecting slices of the wrong length.
    fn read_exact(read: &F, pa: u64, len: usize) -> Option<&'src [u8]> {
        read(pa, len).filter(|d| d.len() == len)
    }

    fn table_at(read: &F, pa: u64) -> Option<Table<'src>> {
        let len = le32(Self::read_exact(read, pa, HEADER)?, 4)? as usize;
        // A length shorter than the header, or implausibly long (a corrupt
        // header could otherwise ask for gigabytes), is malformed.
        if !(HEADER..=MAX_TABLE).contains(&len) {
            return None;
        }
        let data = Self::read_exact(read, pa, len)?;
        checksum_ok(data).then_some(Table { data })
    }

    /// Every table listed by the root whose checksum is valid.
    pub fn tables(&self) -> impl Iterator<Item = Table<'src>> + '_ {
        let step = if self.wide { 8 } else { 4 };
        self.root.body().chunks_exact(step).filter_map(move |e| {
            let pa = if self.wide { le64(e, 0)? } else { le32(e, 0)? as u64 };
            Self::table_at(&self.read, pa)
        })
    }

    /// The first table with signature `sig`.
    pub fn find(&self, sig: &[u8; 4]) -> Option<Table<'src>> {
        self.tables().find(|t| &t.signature() == sig)
    }
}

/// A processor's local interrupt controller, from the MADT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalApic {
    /// ACPI processor UID.
    pub processor_uid: u32,
    /// APIC id (x2APIC id for x2APIC entries).
    pub apic_id: u32,
    /// Usable now (as opposed to hot-pluggable later).
    pub enabled: bool,
}

/// An I/O APIC, from the MADT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoApic {
    /// I/O APIC id.
    pub id: u8,
    /// Physical address of its registers.
    pub addr: u64,
    /// First global system interrupt it handles.
    pub gsi_base: u32,
}

/// An ISA interrupt that the platform wires to a different GSI or with
/// non-ISA polarity/trigger, from the MADT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InterruptOverride {
    /// ISA IRQ number.
    pub source: u8,
    /// Global system interrupt it arrives on.
    pub gsi: u32,
    /// Active low (otherwise active high, the ISA default).
    pub active_low: bool,
    /// Level-triggered (otherwise edge, the ISA default).
    pub level: bool,
}

/// The Multiple APIC Description Table (`APIC`).
#[derive(Clone, Copy, Debug)]
pub struct Madt<'src> {
    local_apic_addr: u64,
    entries: &'src [u8],
}

impl<'src> Madt<'src> {
    /// Parses an `APIC` table.
    pub fn parse(t: Table<'src>) -> Option<Self> {
        if &t.signature() != b"APIC" {
            return None;
        }
        let body = t.body();
        let mut addr = le32(body, 0)? as u64;
        let entries = body.get(8..)?;
        // A type-5 entry overrides the 32-bit address.
        for (typ, e) in Self::walk(entries) {
            if typ == 5 {
                addr = le64(e, 4)?;
            }
        }
        Some(Self { local_apic_addr: addr, entries })
    }

    /// Physical address of the local APICs' registers.
    pub fn local_apic_addr(&self) -> u64 {
        self.local_apic_addr
    }

    fn walk(entries: &'src [u8]) -> impl Iterator<Item = (u8, &'src [u8])> + 'src {
        let mut rest = entries;
        core::iter::from_fn(move || {
            let (&typ, &len) = (rest.first()?, rest.get(1)?);
            if len < 2 || len as usize > rest.len() {
                return None;
            }
            let (e, tail) = rest.split_at(len as usize);
            rest = tail;
            Some((typ, e))
        })
    }

    /// Local APICs and x2APICs.
    pub fn local_apics(&self) -> impl Iterator<Item = LocalApic> + 'src {
        Self::walk(self.entries).filter_map(|(typ, e)| match typ {
            0 => Some(LocalApic {
                processor_uid: *e.get(2)? as u32,
                apic_id: *e.get(3)? as u32,
                enabled: le32(e, 4)? & 1 != 0,
            }),
            9 => Some(LocalApic { processor_uid: le32(e, 12)?, apic_id: le32(e, 4)?, enabled: le32(e, 8)? & 1 != 0 }),
            _ => None,
        })
    }

    /// Interrupt source overrides.
    pub fn overrides(&self) -> impl Iterator<Item = InterruptOverride> + 'src {
        Self::walk(self.entries).filter_map(|(typ, e)| {
            let flags = u16::from_le_bytes([*e.get(8)?, *e.get(9)?]);
            (typ == 2).then_some(InterruptOverride {
                source: *e.get(3)?,
                gsi: le32(e, 4)?,
                active_low: flags & 0b11 == 0b11,
                level: flags >> 2 & 0b11 == 0b11,
            })
        })
    }

    /// The GSI and line mode `(gsi, active_low, level)` of ISA IRQ `irq`,
    /// applying any override (identity, active high and edge otherwise).
    pub fn isa_irq(&self, irq: u8) -> (u32, bool, bool) {
        self.overrides()
            .find(|o| o.source == irq)
            .map_or((irq as u32, false, false), |o| (o.gsi, o.active_low, o.level))
    }

    /// I/O APICs.
    pub fn io_apics(&self) -> impl Iterator<Item = IoApic> + 'src {
        Self::walk(self.entries).filter_map(|(typ, e)| {
            (typ == 1)
                .then(|| Some(IoApic { id: *e.get(2)?, addr: le32(e, 4)? as u64, gsi_base: le32(e, 8)? }))
                .flatten()
        })
    }
}

/// One PCI Express ECAM window, from the MCFG.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EcamWindow {
    /// Physical base address (of bus 0, even if `start_bus` is higher).
    pub base: u64,
    /// PCI segment group.
    pub segment: u16,
    /// First bus decoded.
    pub start_bus: u8,
    /// Last bus decoded.
    pub end_bus: u8,
}

/// The PCI Express memory-mapped configuration table (`MCFG`).
#[derive(Clone, Copy, Debug)]
pub struct Mcfg<'src> {
    entries: &'src [u8],
}

impl<'src> Mcfg<'src> {
    /// Parses an `MCFG` table.
    pub fn parse(t: Table<'src>) -> Option<Self> {
        (&t.signature() == b"MCFG").then(|| Some(Self { entries: t.body().get(8..)? })).flatten()
    }

    /// The ECAM windows.
    pub fn entries(&self) -> impl Iterator<Item = EcamWindow> + 'src {
        self.entries.as_chunks::<16>().0.iter().filter_map(|e| {
            Some(EcamWindow {
                base: le64(e, 0)?,
                segment: u16::from_le_bytes([e[8], e[9]]),
                start_bus: e[10],
                end_bus: e[11],
            })
        })
    }
}

/// One DMA-remapping hardware unit, from a `DMAR` DRHD structure (Intel VT-d).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DmaRemapUnit {
    /// PCI segment the unit serves.
    pub segment: u16,
    /// Physical base address of its registers.
    pub base: u64,
    /// True if the unit covers every device in the segment not claimed by
    /// another unit (`INCLUDE_PCI_ALL`).
    pub include_all: bool,
}

/// The DMA Remapping Reporting table (`DMAR`).
#[derive(Clone, Copy, Debug)]
pub struct Dmar<'src> {
    structures: &'src [u8],
}

impl<'src> Dmar<'src> {
    /// Parses a `DMAR` table.
    pub fn parse(t: Table<'src>) -> Option<Self> {
        // Host address width, flags and 10 reserved bytes precede the list.
        (&t.signature() == b"DMAR").then(|| Some(Self { structures: t.body().get(12..)? })).flatten()
    }

    /// The remapping units (DRHD structures), in table order.
    pub fn units(&self) -> impl Iterator<Item = DmaRemapUnit> + 'src {
        let mut rest = self.structures;
        core::iter::from_fn(move || {
            loop {
                let kind = u16::from_le_bytes(rest.get(..2)?.try_into().ok()?);
                let len = u16::from_le_bytes(rest.get(2..4)?.try_into().ok()?) as usize;
                let entry = rest.get(..len).filter(|_| len >= 4)?;
                rest = &rest[len..];
                if kind == 0 {
                    return Some(DmaRemapUnit {
                        segment: u16::from_le_bytes(entry.get(6..8)?.try_into().ok()?),
                        base: le64(entry, 8)?,
                        include_all: entry.get(4)? & 1 != 0,
                    });
                }
            }
        })
    }
}

/// One AMD IOMMU, from an `IVRS` IVHD block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AmdIommuUnit {
    /// PCI segment the unit serves.
    pub segment: u16,
    /// Physical base address of its registers.
    pub base: u64,
    /// The unit's own PCI requester ID.
    pub device_id: u16,
}

/// The I/O Virtualization Reporting Structure (`IVRS`).
#[derive(Clone, Copy, Debug)]
pub struct Ivrs<'src> {
    blocks: &'src [u8],
}

impl<'src> Ivrs<'src> {
    /// Parses an `IVRS` table.
    pub fn parse(t: Table<'src>) -> Option<Self> {
        // IVinfo and 8 reserved bytes precede the blocks.
        (&t.signature() == b"IVRS").then(|| Some(Self { blocks: t.body().get(12..)? })).flatten()
    }

    /// The IOMMUs (IVHD blocks of type 10h, 11h and 40h), in table order.
    pub fn units(&self) -> impl Iterator<Item = AmdIommuUnit> + 'src {
        let mut rest = self.blocks;
        core::iter::from_fn(move || {
            loop {
                let kind = *rest.first()?;
                let len = u16::from_le_bytes(rest.get(2..4)?.try_into().ok()?) as usize;
                let block = rest.get(..len).filter(|_| len >= 4)?;
                rest = &rest[len..];
                if matches!(kind, 0x10 | 0x11 | 0x40) {
                    return Some(AmdIommuUnit {
                        device_id: u16::from_le_bytes(block.get(4..6)?.try_into().ok()?),
                        base: le64(block, 8)?,
                        segment: u16::from_le_bytes(block.get(16..18)?.try_into().ok()?),
                    });
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn table(sig: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut t = Vec::new();
        t.extend_from_slice(sig);
        t.extend_from_slice(&((HEADER + body.len()) as u32).to_le_bytes());
        t.extend_from_slice(&[1, 0]);
        t.extend_from_slice(&[0; 26]);
        t.extend_from_slice(body);
        let sum = t.iter().fold(0u8, |a, &b| a.wrapping_add(b));
        t[9] = 0u8.wrapping_sub(sum);
        t
    }

    #[test]
    fn rsdp_xsdt_madt_mcfg() {
        // Fake physical memory: tables at fixed offsets in one buffer.
        let mut madt_body = Vec::new();
        madt_body.extend_from_slice(&0xfee0_0000u32.to_le_bytes());
        madt_body.extend_from_slice(&1u32.to_le_bytes());
        for (uid, id, flags) in [(0u8, 0u8, 1u32), (1, 1, 1), (2, 2, 0)] {
            madt_body.extend_from_slice(&[0, 8, uid, id]);
            madt_body.extend_from_slice(&flags.to_le_bytes());
        }
        madt_body.extend_from_slice(&[2, 10, 0, 0]); // IRQ0 -> GSI2, defaults
        madt_body.extend_from_slice(&2u32.to_le_bytes());
        madt_body.extend_from_slice(&0u16.to_le_bytes());
        madt_body.extend_from_slice(&[2, 10, 0, 9]); // IRQ9 -> GSI9, level, active low
        madt_body.extend_from_slice(&9u32.to_le_bytes());
        madt_body.extend_from_slice(&0b1111u16.to_le_bytes());
        madt_body.extend_from_slice(&[1, 12, 7, 0]);
        madt_body.extend_from_slice(&0xfec0_0000u32.to_le_bytes());
        madt_body.extend_from_slice(&0u32.to_le_bytes());
        let madt = table(b"APIC", &madt_body);

        let mut mcfg_body = std::vec![0u8; 8];
        mcfg_body.extend_from_slice(&0xb000_0000u64.to_le_bytes());
        mcfg_body.extend_from_slice(&[0, 0, 0, 0xff, 0, 0, 0, 0]);
        let mcfg = table(b"MCFG", &mcfg_body);

        let (madt_at, mcfg_at, xsdt_at) = (0x100u64, 0x200u64, 0x300u64);
        let mut xsdt_body = Vec::new();
        xsdt_body.extend_from_slice(&madt_at.to_le_bytes());
        xsdt_body.extend_from_slice(&mcfg_at.to_le_bytes());
        let xsdt = table(b"XSDT", &xsdt_body);

        let mut rsdp = Vec::new();
        rsdp.extend_from_slice(b"RSD PTR ");
        rsdp.push(0);
        rsdp.extend_from_slice(b"OSMIUM");
        rsdp.push(2);
        rsdp.extend_from_slice(&0u32.to_le_bytes());
        rsdp.extend_from_slice(&36u32.to_le_bytes());
        rsdp.extend_from_slice(&xsdt_at.to_le_bytes());
        rsdp.extend_from_slice(&[0; 4]);
        rsdp[8] = 0u8.wrapping_sub(rsdp[..20].iter().fold(0u8, |a, &b| a.wrapping_add(b)));
        rsdp[32] = 0u8.wrapping_sub(rsdp.iter().fold(0u8, |a, &b| a.wrapping_add(b)));

        let mut mem = std::vec![0u8; 0x400];
        mem[..36].copy_from_slice(&rsdp);
        mem[madt_at as usize..][..madt.len()].copy_from_slice(&madt);
        mem[mcfg_at as usize..][..mcfg.len()].copy_from_slice(&mcfg);
        mem[xsdt_at as usize..][..xsdt.len()].copy_from_slice(&xsdt);
        let read = |pa: u64, len: usize| mem.get(pa as usize..pa as usize + len);

        let acpi = Acpi::new(0, read).unwrap();
        assert_eq!(acpi.tables().count(), 2);
        let m = Madt::parse(acpi.find(b"APIC").unwrap()).unwrap();
        assert_eq!(m.local_apic_addr(), 0xfee0_0000);
        let cpus: Vec<_> = m.local_apics().collect();
        assert_eq!(cpus.len(), 3);
        assert_eq!(cpus.iter().filter(|c| c.enabled).count(), 2);
        assert_eq!(m.io_apics().next(), Some(IoApic { id: 7, addr: 0xfec0_0000, gsi_base: 0 }));
        assert_eq!(m.isa_irq(0), (2, false, false));
        assert_eq!(m.isa_irq(9), (9, true, true));
        assert_eq!(m.isa_irq(4), (4, false, false), "no override: identity");
        let ecam = Mcfg::parse(acpi.find(b"MCFG").unwrap()).unwrap().entries().next().unwrap();
        assert_eq!((ecam.base, ecam.end_bus), (0xb000_0000, 0xff));

        // A reader that returns less than asked for is not trusted (indexing
        // a short RSDP would panic).
        let short = |pa: u64, len: usize| mem.get(pa as usize..pa as usize + len.min(8));
        assert_eq!(Acpi::new(0, short).err(), Some(AcpiError::Unreadable));
        let long = |pa: u64, len: usize| mem.get(pa as usize..pa as usize + len + 1);
        assert_eq!(Acpi::new(0, long).err(), Some(AcpiError::Unreadable));

        // A table claiming more than 1 MiB is skipped before being read.
        let mut big = mem.clone();
        big[mcfg_at as usize + 4..][..4].copy_from_slice(&(2u32 << 20).to_le_bytes());
        let asked = core::cell::Cell::new(0);
        let read = |pa: u64, len: usize| {
            asked.set(asked.get().max(len));
            big.get(pa as usize..pa as usize + len)
        };
        let acpi = Acpi::new(0, read).unwrap();
        assert!(acpi.find(b"MCFG").is_none());
        assert!(acpi.find(b"APIC").is_some());
        assert!(asked.get() <= 0x400);

        // A corrupted table is skipped, a corrupted RSDP rejected.
        mem[madt_at as usize + 40] ^= 1;
        let read = |pa: u64, len: usize| mem.get(pa as usize..pa as usize + len);
        assert!(Acpi::new(0, read).unwrap().find(b"APIC").is_none());
        mem[3] ^= 1;
        let read = |pa: u64, len: usize| mem.get(pa as usize..pa as usize + len);
        assert_eq!(Acpi::new(0, read).err(), Some(AcpiError::BadRsdp));
    }
    #[test]
    fn dmar_and_ivrs_units() {
        // DMAR: a reserved-memory structure (type 1) the walker must skip,
        // then two DRHDs.
        let mut dmar = Vec::from([48u8, 1]);
        dmar.extend_from_slice(&[0; 10]);
        dmar.extend_from_slice(&[1, 0, 8, 0, 0, 0, 0, 0]); // RMRR stub
        for (flags, seg, base) in [(0u8, 0u16, 0xfed9_0000u64), (1, 1, 0xfedb_0000)] {
            dmar.extend_from_slice(&[0, 0, 16, 0, flags, 0]);
            dmar.extend_from_slice(&seg.to_le_bytes());
            dmar.extend_from_slice(&base.to_le_bytes());
        }
        let t = table(b"DMAR", &dmar);
        let units: Vec<_> = Dmar::parse(Table { data: &t }).unwrap().units().collect();
        assert_eq!(
            units,
            [
                DmaRemapUnit { segment: 0, base: 0xfed9_0000, include_all: false },
                DmaRemapUnit { segment: 1, base: 0xfedb_0000, include_all: true },
            ]
        );
        assert!(Ivrs::parse(Table { data: &t }).is_none());

        // IVRS: an IVMD (type 20h) to skip, then a type 11h IVHD.
        let mut ivrs = Vec::from([0u8; 12]);
        ivrs.extend_from_slice(&[0x20, 0, 8, 0, 0, 0, 0, 0]);
        let mut ivhd = Vec::from([0x11u8, 0, 24, 0]);
        ivhd.extend_from_slice(&0x0010u16.to_le_bytes()); // device ID
        ivhd.extend_from_slice(&[0x40, 0]); // capability offset
        ivhd.extend_from_slice(&0xfed8_0000u64.to_le_bytes());
        ivhd.extend_from_slice(&2u16.to_le_bytes()); // segment
        ivhd.extend_from_slice(&[0; 6]);
        ivrs.extend_from_slice(&ivhd);
        let t = table(b"IVRS", &ivrs);
        let units: Vec<_> = Ivrs::parse(Table { data: &t }).unwrap().units().collect();
        assert_eq!(units, [AmdIommuUnit { segment: 2, base: 0xfed8_0000, device_id: 0x10 }]);

        // A truncated structure ends the walk instead of panicking.
        let t = table(b"DMAR", &dmar[..dmar.len() - 5]);
        assert_eq!(Dmar::parse(Table { data: &t }).unwrap().units().count(), 1);
    }
}
