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
pub struct Table<'a> {
    /// The whole table, `length` bytes.
    pub data: &'a [u8],
}

const HEADER: usize = 36;

impl<'a> Table<'a> {
    /// The four-byte signature (`b"APIC"`, `b"MCFG"`, ...).
    pub fn signature(&self) -> [u8; 4] {
        self.data[..4].try_into().unwrap()
    }

    /// Table contents after the standard header.
    pub fn body(&self) -> &'a [u8] {
        &self.data[HEADER..]
    }
}

fn checksum_ok(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |a, &b| a.wrapping_add(b)) == 0
}

/// The ACPI root: the RSDT or XSDT found through the RSDP.
pub struct Acpi<'a, F> {
    read: F,
    root: Table<'a>,
    /// True for the XSDT (64-bit entries).
    wide: bool,
}

impl<'a, F: Fn(u64, usize) -> Option<&'a [u8]>> Acpi<'a, F> {
    /// Validates the RSDP at physical address `rsdp` and its root table.
    pub fn new(rsdp: u64, read: F) -> Result<Self, AcpiError> {
        let r = read(rsdp, 20).ok_or(AcpiError::Unreadable)?;
        if &r[..8] != b"RSD PTR " || !checksum_ok(r) {
            return Err(AcpiError::BadRsdp);
        }
        let (root_pa, wide) = if r[15] >= 2 {
            let r2 = read(rsdp, 36).ok_or(AcpiError::Unreadable)?;
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

    fn table_at(read: &F, pa: u64) -> Option<Table<'a>> {
        let len = le32(read(pa, HEADER)?, 4)? as usize;
        let data = read(pa, len.max(HEADER))?;
        checksum_ok(data).then_some(Table { data })
    }

    /// Every table listed by the root whose checksum is valid.
    pub fn tables(&self) -> impl Iterator<Item = Table<'a>> + '_ {
        let step = if self.wide { 8 } else { 4 };
        self.root.body().chunks_exact(step).filter_map(move |e| {
            let pa = if self.wide { le64(e, 0)? } else { le32(e, 0)? as u64 };
            Self::table_at(&self.read, pa)
        })
    }

    /// The first table with signature `sig`.
    pub fn find(&self, sig: &[u8; 4]) -> Option<Table<'a>> {
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

/// The Multiple APIC Description Table (`APIC`).
#[derive(Clone, Copy, Debug)]
pub struct Madt<'a> {
    local_apic_addr: u64,
    entries: &'a [u8],
}

impl<'a> Madt<'a> {
    /// Parses an `APIC` table.
    pub fn parse(t: Table<'a>) -> Option<Self> {
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

    fn walk(entries: &'a [u8]) -> impl Iterator<Item = (u8, &'a [u8])> + 'a {
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
    pub fn local_apics(&self) -> impl Iterator<Item = LocalApic> + 'a {
        Self::walk(self.entries).filter_map(|(typ, e)| match typ {
            0 => Some(LocalApic { processor_uid: *e.get(2)? as u32, apic_id: *e.get(3)? as u32, enabled: le32(e, 4)? & 1 != 0 }),
            9 => Some(LocalApic { processor_uid: le32(e, 12)?, apic_id: le32(e, 4)?, enabled: le32(e, 8)? & 1 != 0 }),
            _ => None,
        })
    }

    /// I/O APICs.
    pub fn io_apics(&self) -> impl Iterator<Item = IoApic> + 'a {
        Self::walk(self.entries).filter_map(|(typ, e)| {
            (typ == 1).then(|| Some(IoApic { id: *e.get(2)?, addr: le32(e, 4)? as u64, gsi_base: le32(e, 8)? })).flatten()
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
pub struct Mcfg<'a> {
    entries: &'a [u8],
}

impl<'a> Mcfg<'a> {
    /// Parses an `MCFG` table.
    pub fn parse(t: Table<'a>) -> Option<Self> {
        (&t.signature() == b"MCFG").then(|| Some(Self { entries: t.body().get(8..)? })).flatten()
    }

    /// The ECAM windows.
    pub fn entries(&self) -> impl Iterator<Item = EcamWindow> + 'a {
        self.entries.as_chunks::<16>().0.iter().filter_map(|e| {
            Some(EcamWindow { base: le64(e, 0)?, segment: u16::from_le_bytes([e[8], e[9]]), start_bus: e[10], end_bus: e[11] })
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
        let ecam = Mcfg::parse(acpi.find(b"MCFG").unwrap()).unwrap().entries().next().unwrap();
        assert_eq!((ecam.base, ecam.end_bus), (0xb000_0000, 0xff));

        // A corrupted table is skipped, a corrupted RSDP rejected.
        mem[madt_at as usize + 40] ^= 1;
        let read = |pa: u64, len: usize| mem.get(pa as usize..pa as usize + len);
        assert!(Acpi::new(0, read).unwrap().find(b"APIC").is_none());
        mem[3] ^= 1;
        let read = |pa: u64, len: usize| mem.get(pa as usize..pa as usize + len);
        assert_eq!(Acpi::new(0, read).err(), Some(AcpiError::BadRsdp));
    }
}
