//! A host that is a few maps, and helpers for loading compiled test tables.
#![allow(dead_code, clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

use osmium_acpi::aml::{Config, Host, HostError, Interpreter, PciAddress, ROOT, Value};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Access {
    MemR(u64, u8),
    MemW(u64, u8, u64),
    IoR(u16, u8),
    IoW(u16, u8, u64),
    PciR(PciAddress, u16, u8),
    PciW(PciAddress, u16, u8, u64),
    RegionR(u8, u64, u8),
    RegionW(u8, u64, u8, u64),
}

#[derive(Default)]
pub struct TestHost {
    pub mem: BTreeMap<u64, u8>,
    pub io: BTreeMap<u16, u8>,
    pub pci: BTreeMap<(PciAddress, u16), u8>,
    pub other: BTreeMap<(u8, u64), u8>,
    /// Registers behind the index/data port pair 0x70/0x71.
    pub indexed: BTreeMap<u8, u8>,
    pub index: u8,
    pub log: Vec<Access>,
    pub notifications: Vec<(String, u8)>,
    pub debug: Vec<String>,
    pub fatals: Vec<(u8, u32, u64)>,
    pub stalled_us: u64,
    pub slept_ms: u64,
    pub timer: u64,
    /// Interfaces `_OSI` accepts, besides the defaults.
    pub interfaces: Vec<String>,
    /// Spaces for which `serves_region` says yes besides memory, I/O and PCI.
    pub extra_spaces: Vec<u8>,
    /// I/O ports whose bits clear when a 1 is written (status registers).
    pub w1c: Vec<u16>,
    /// Writing `.1` to port `.0` sets bit 0 of the byte at port `.2`, like `ACPI_ENABLE` setting `SCI_EN`.
    pub smi: Option<(u16, u8, u16)>,
    /// A write of the sleep-enable bit to the PM1a control port `.0` sets the wake bit (bit 15) of the
    /// status register at port `.1`.
    pub wake_on_sleep: Option<(u16, u16)>,
}

impl TestHost {
    pub fn poke(&mut self, addr: u64, bytes: &[u8]) {
        for (i, b) in bytes.iter().enumerate() {
            self.mem.insert(addr + i as u64, *b);
        }
    }

    pub fn peek(&self, addr: u64, len: usize) -> Vec<u8> {
        (0..len).map(|i| self.mem.get(&(addr + i as u64)).copied().unwrap_or(0)).collect()
    }

    pub fn clear_log(&mut self) {
        self.log.clear();
    }
}

fn mask(bits: u8) -> u64 {
    if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 }
}

fn load_le(read: impl Fn(u64) -> u8, bits: u8) -> u64 {
    (0..u64::from(bits / 8)).fold(0, |a, i| a | u64::from(read(i)) << (8 * i))
}

impl Host for TestHost {
    fn read_memory(&mut self, addr: u64, bits: u8) -> Result<u64, HostError> {
        self.log.push(Access::MemR(addr, bits));
        Ok(load_le(|i| self.mem.get(&(addr + i)).copied().unwrap_or(0), bits))
    }

    fn write_memory(&mut self, addr: u64, bits: u8, value: u64) -> Result<(), HostError> {
        self.log.push(Access::MemW(addr, bits, value));
        for i in 0..u64::from(bits / 8) {
            self.mem.insert(addr + i, (value >> (8 * i)) as u8);
        }
        Ok(())
    }

    fn read_io(&mut self, port: u16, bits: u8) -> Result<u64, HostError> {
        self.log.push(Access::IoR(port, bits));
        if port == 0x71 {
            return Ok(u64::from(self.indexed.get(&self.index).copied().unwrap_or(0)));
        }
        Ok(load_le(|i| self.io.get(&(port + i as u16)).copied().unwrap_or(0), bits))
    }

    fn write_io(&mut self, port: u16, bits: u8, value: u64) -> Result<(), HostError> {
        self.log.push(Access::IoW(port, bits, value));
        match port {
            0x70 => self.index = value as u8,
            0x71 => {
                self.indexed.insert(self.index, value as u8);
            }
            _ => {
                for i in 0..u16::from(bits / 8) {
                    let byte = (value >> (8 * i)) as u8;
                    let p = port + i;
                    if self.w1c.contains(&p) {
                        let cur = self.io.get(&p).copied().unwrap_or(0);
                        self.io.insert(p, cur & !byte);
                    } else {
                        self.io.insert(p, byte);
                    }
                }
                if let Some((smi_port, cmd, sci)) = self.smi
                    && port == smi_port
                    && value as u8 == cmd
                {
                    *self.io.entry(sci).or_insert(0) |= 1;
                }
                if let Some((cnt, sts)) = self.wake_on_sleep
                    && port == cnt
                    && bits == 16
                    && value & 0x2000 != 0
                {
                    *self.io.entry(sts + 1).or_insert(0) |= 0x80;
                }
            }
        }
        Ok(())
    }

    fn read_pci(&mut self, addr: PciAddress, offset: u16, bits: u8) -> Result<u64, HostError> {
        self.log.push(Access::PciR(addr, offset, bits));
        Ok(load_le(|i| self.pci.get(&(addr, offset + i as u16)).copied().unwrap_or(0), bits))
    }

    fn write_pci(&mut self, addr: PciAddress, offset: u16, bits: u8, value: u64) -> Result<(), HostError> {
        self.log.push(Access::PciW(addr, offset, bits, value));
        for i in 0..u16::from(bits / 8) {
            self.pci.insert((addr, offset + i), (value >> (8 * i)) as u8);
        }
        Ok(())
    }

    fn read_region(&mut self, space: u8, offset: u64, bits: u8) -> Result<u64, HostError> {
        self.log.push(Access::RegionR(space, offset, bits));
        Ok(load_le(|i| self.other.get(&(space, offset + i)).copied().unwrap_or(0), bits) & mask(bits))
    }

    fn write_region(&mut self, space: u8, offset: u64, bits: u8, value: u64) -> Result<(), HostError> {
        self.log.push(Access::RegionW(space, offset, bits, value));
        for i in 0..u64::from(bits / 8) {
            self.other.insert((space, offset + i), (value >> (8 * i)) as u8);
        }
        Ok(())
    }

    fn serves_region(&mut self, space: u8) -> bool {
        space <= 2 || self.extra_spaces.contains(&space)
    }

    fn stall(&mut self, micros: u32) {
        self.stalled_us += u64::from(micros);
    }

    fn sleep(&mut self, millis: u32) {
        self.slept_ms += u64::from(millis);
    }

    fn timer(&mut self) -> u64 {
        self.timer += 10;
        self.timer
    }

    fn notify(&mut self, path: &str, value: u8) {
        self.notifications.push((path.into(), value));
    }

    fn debug(&mut self, message: &str) {
        self.debug.push(message.into());
    }

    fn fatal(&mut self, kind: u8, code: u32, arg: u64) {
        self.fatals.push((kind, code, arg));
    }

    fn supports_interface(&mut self, name: &str) -> bool {
        name == "Module Device" || self.interfaces.iter().any(|i| i == name)
    }
}

/// An interpreter with `table` loaded. Panics if the table does not load.
pub fn load(table: &[u8]) -> Interpreter<TestHost> {
    load_with(TestHost::default(), table)
}

pub fn load_with(host: TestHost, table: &[u8]) -> Interpreter<TestHost> {
    let mut aml = Interpreter::new(host, Config::default());
    aml.load_table(table).expect("table loads");
    aml
}

/// Runs every method named `Tnnn` in the root; each must return 0. Returns how many ran.
pub fn run_numbered_tests(aml: &mut Interpreter<TestHost>) -> usize {
    let tests: Vec<String> = aml
        .namespace()
        .children(ROOT)
        .filter(|(s, _)| s.0[0] == b'T' && s.0[1..].iter().all(u8::is_ascii_digit))
        .map(|(s, _)| s.as_str().to_string())
        .collect();
    let mut failures = Vec::new();
    for t in &tests {
        match aml.evaluate(&format!("\\{t}"), &[]) {
            Ok(Value::Integer(0)) => {}
            other => failures.push(format!("{t}: {other:?}")),
        }
    }
    assert!(failures.is_empty(), "failing tests: {failures:#?}\nwarnings: {:?}", aml.warnings());
    tests.len()
}

// ----- tables -----

/// Gives `t` the checksum that makes its bytes sum to zero.
pub fn seal(mut t: Vec<u8>) -> Vec<u8> {
    let len = t.len() as u32;
    t[4..8].copy_from_slice(&len.to_le_bytes());
    t[9] = 0;
    let sum = t.iter().fold(0u8, |a, &b| a.wrapping_add(b));
    t[9] = 0u8.wrapping_sub(sum);
    t
}

/// A table header followed by `body`.
pub fn table(sig: &[u8; 4], revision: u8, body: &[u8]) -> Vec<u8> {
    let mut t = vec![0u8; 36];
    t[..4].copy_from_slice(sig);
    t[8] = revision;
    t[10..16].copy_from_slice(b"OSMIUM");
    t[16..24].copy_from_slice(b"TESTTBL ");
    t.extend_from_slice(body);
    seal(t)
}

/// The register layout the PM tests use: PM1a events at 0x600 (status, then enable), PM1a control at
/// 0x604, the PM timer at 0x608, GPE block 0 at 0x680 (four status bytes, then four enable bytes), the SMI
/// command port 0xB2 and a reset register at 0xCF9.
pub fn fadt(dsdt: u32) -> Vec<u8> {
    let mut body = vec![0u8; 276 - 36];
    let mut put = |off: usize, bytes: &[u8]| body[off - 36..off - 36 + bytes.len()].copy_from_slice(bytes);
    put(40, &dsdt.to_le_bytes());
    put(46, &9u16.to_le_bytes());
    put(48, &0xB2u32.to_le_bytes());
    put(52, &[0xF1, 0xF0]);
    put(56, &0x600u32.to_le_bytes());
    put(64, &0x604u32.to_le_bytes());
    put(76, &0x608u32.to_le_bytes());
    put(80, &0x680u32.to_le_bytes());
    put(88, &[4, 2, 0, 4, 8, 0, 0]);
    put(112, &(1u32 << 10).to_le_bytes());
    // RESET_REG: system I/O, 8 bits, at 0xCF9; RESET_VALUE 6.
    put(116, &[1, 8, 0, 1, 0xF9, 0x0C, 0, 0, 0, 0, 0, 0]);
    put(128, &[6]);
    table(b"FACP", 6, &body)
}

/// A memory image holding an RSDP at 0, an XSDT at 0x100, the FADT at 0x200, the DSDT at 0x1000 and the
/// SSDTs from 0x8000 on.
pub fn machine_memory(dsdt: &[u8], ssdts: &[&[u8]]) -> Vec<u8> {
    let mut mem = vec![0u8; 0x10000];
    let mut place = |at: usize, t: &[u8]| mem[at..at + t.len()].copy_from_slice(t);
    place(0x200, &fadt(0x1000));
    place(0x1000, dsdt);
    let mut entries = vec![0x200u64];
    for (i, s) in ssdts.iter().enumerate() {
        let at = 0x8000 + i * 0x2000;
        place(at, s);
        entries.push(at as u64);
    }
    let body: Vec<u8> = entries.iter().flat_map(|e| e.to_le_bytes()).collect();
    place(0x100, &table(b"XSDT", 1, &body));
    let mut rsdp = vec![0u8; 36];
    rsdp[..8].copy_from_slice(b"RSD PTR ");
    rsdp[15] = 2;
    rsdp[20..24].copy_from_slice(&36u32.to_le_bytes());
    rsdp[24..32].copy_from_slice(&0x100u64.to_le_bytes());
    rsdp[8] = 0u8.wrapping_sub(rsdp[..20].iter().fold(0u8, |a, &b| a.wrapping_add(b)));
    rsdp[32] = 0u8.wrapping_sub(rsdp.iter().fold(0u8, |a, &b| a.wrapping_add(b)));
    place(0, &rsdp);
    mem
}

/// The reader that `osmium_boot::acpi::Acpi` wants, over a memory image.
pub fn reader<'mem>(mem: &'mem [u8]) -> impl Fn(u64, usize) -> Option<&'mem [u8]> {
    move |pa, len| mem.get(usize::try_from(pa).ok()?..)?.get(..len)
}
