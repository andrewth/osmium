//! A software ConnectX for host tests: PCI configuration space, BAR 0 with
//! the command register, the UAR pages, and enough firmware to check what
//! the driver asks of it.
//!
//! The firmware runs whenever the driver reads the clock, which the driver
//! does while it polls the HCR, so commands complete synchronously and
//! deterministically. The data path is driven from the test instead:
//! [`FakeHca::sent`] plays the send engine and [`FakeHca::deliver`] the
//! receive engine, through the same MTT translations the hardware uses.

use core::cell::RefCell;
use std::collections::BTreeMap;
use std::vec;
use std::vec::Vec;

use osmium_hal::mmio::IoMem;
use osmium_hal::pci::{Address, ConfigAccess, MsiMessage};
use osmium_hal::timer::Clock;

use super::cmd::{HCR, op};
use super::{CONFIG_LEN, RESET, RESET_SEMAPHORE, UAR_LEN, UAR_PAGE};

pub const ADDR: Address = Address::new(0, 3, 0);
pub const MAC: [u8; 6] = [0x00, 0x02, 0xc9, 0x12, 0x34, 0x56];
pub const FW_PAGES: u32 = 16;
pub const AUX_PAGES: u64 = 2;

// Reserved resources reported by QUERY_DEV_CAP.
pub const RSVD_QPS_LOG: u32 = 6;
pub const RSVD_CQS_LOG: u32 = 7;
pub const RSVD_EQS: u32 = 32;
pub const RSVD_UARS: u32 = 8;
pub const RSVD_MTTS_LOG: u32 = 4;
pub const RSVD_MRWS_LOG: u32 = 4;
pub const MTT_ENTRY: u64 = 8;

/// Header values the reset must preserve.
pub const BAR0: u32 = 0xe000_000c;
pub const BAR2: u32 = 0xd000_000c;
pub const PCIE_CAP: usize = 0x60;
pub const DEVCTL: u32 = 0x0000_2810;
/// MSI-X capability: offset in configuration space, table entries, and the
/// table/PBA window (BAR index 0 is not this fake's BAR 0: the table gets
/// its own memory).
pub const MSIX_CAP: usize = 0xa0;
pub const MSIX_ENTRIES: usize = 4;
pub const MSIX_LEN: usize = 0x100;
pub const MSIX_PBA: usize = 0x80;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PortKind {
    Ethernet,
    InfiniBand,
    /// Both; SENSE_PORT reports "unknown" `sense_after` times, then `sensed`.
    Vpi {
        sense_after: u32,
        sensed: u8,
    },
}

#[derive(Debug)]
struct Cq {
    mtt: u64,
    log_size: u32,
    db: u64,
    pi: u32,
    eqn: u32,
    /// The arm doorbell value already used up by an event.
    spent_arm: Option<u64>,
}

#[derive(Debug)]
pub struct Eq {
    mtt: u64,
    log_size: u32,
    pi: u32,
    intr: u32,
    armed: bool,
    /// The doorbell value already used up by an interrupt.
    spent_arm: Option<u32>,
}

/// A frame the send engine took from a queue.
#[derive(Debug, PartialEq, Eq)]
pub struct Sent {
    pub frame: Vec<u8>,
    pub ip_csum: bool,
    pub l4_csum: bool,
    /// (mss, header length) of a segmentation entry; `frame` is then the
    /// whole unsegmented frame.
    pub lso: Option<(u16, usize)>,
}

#[derive(Default, Debug)]
struct Qp {
    state: u8, // 1 INIT, 2 RTR, 3 RTS
    mtt: u64,
    log_sq: u32,
    log_sq_stride: u32,
    log_rq: u32,
    log_rq_stride: u32,
    cqn_send: u32,
    cqn_recv: u32,
    db: u64,
    keep_vlan: bool,
    sched_queue: u32,
    sq_next: u32,
    rq_next: u32,
}

/// What the firmware loses on reset.
#[derive(Default)]
pub struct Firmware {
    pub fa_pages: u64,
    pub running: bool,
    icm_size: u64,
    /// (va, pa, len) of every MAP_ICM block.
    pub icm: Vec<(u64, u64, u64)>,
    pub aux_pages: u64,
    pub hca_up: bool,
    pub init_hca: Vec<u32>,
    mtt: BTreeMap<u64, u64>,
    pub lkey: Option<u32>,
    pub eqs: BTreeMap<u32, Eq>,
    /// The event queue port events go to (MAP_EQ).
    pub async_eqn: Option<u32>,
    pub eq_mapped: bool,
    /// Completion queues with an event to deliver.
    notify: Vec<u32>,
    pub special_qp: Option<u32>,
    cqs: BTreeMap<u32, Cq>,
    qps: BTreeMap<u32, Qp>,
    pub port_mtu: [u32; 2],
    pub promisc_qpn: [Option<u32>; 2],
    pub port_up: [bool; 2],
}

#[derive(Default)]
pub struct State {
    now: u64,
    /// Every opcode issued, in order.
    pub log: Vec<u16>,
    /// Make this opcode fail with this status.
    pub fail: Option<(u16, u8)>,
    /// Make this opcode never complete.
    pub hang: Option<u16>,
    pub semaphore_stuck: bool,
    pub ports: [Option<PortKind>; 2],
    pub dpdp: bool,
    /// Largest LSO frame QUERY_DEV_CAP reports (0: none).
    pub max_gso: u32,
    pub link: [bool; 2],
    sense_calls: u32,
    config: Vec<u32>,
    pub resets: u32,
    /// MSI-X vectors (table entry indices) the function has sent.
    pub msi_sent: Vec<u16>,
    /// Interrupts held back by a masked vector or function.
    pub msi_pending: Vec<u16>,
    back_at: Option<u64>,
    pub fw: Firmware,
}

/// The device. Its registers are heap memory, which the fake reads and
/// writes through raw pointers just as the driver's `IoMem` does.
pub struct FakeHca {
    bar0: *mut u32,
    uar: *mut u32,
    msix: *mut u32,
    _backing: (Vec<u32>, Vec<u32>, Vec<u32>),
    pub state: RefCell<State>,
}

// SAFETY: tests use a FakeHca from one thread only; `Clock` merely requires
// the bound.
unsafe impl Sync for FakeHca {}

fn rd(pa: u64) -> u32 {
    // SAFETY: test DMA memory is identity-mapped and live while in use.
    u32::from_be(unsafe { (pa as *const u32).read_volatile() })
}

fn wr(pa: u64, v: u32) {
    // SAFETY: as above.
    unsafe { (pa as *mut u32).write_volatile(v.to_be()) }
}

impl FakeHca {
    pub fn new(ports: [Option<PortKind>; 2]) -> Self {
        let mut bar0 = vec![0u32; CONFIG_LEN / 4];
        let mut uar = vec![0u32; UAR_LEN / 4];
        let mut msix = vec![0u32; MSIX_LEN / 4];
        // Entries start masked, as after reset.
        for e in 0..MSIX_ENTRIES {
            msix[e * 4 + 3] = 1;
        }
        let mut config = vec![0u32; 64];
        config[0] = 0x1003_15b3;
        config[1] = 0x0010_0006; // capabilities list; memory and bus master on
        config[2] = 0x0200_0000;
        config[4] = BAR0;
        config[6] = BAR2;
        config[13] = PCIE_CAP as u32;
        config[PCIE_CAP / 4] = 0x0002_0010 | (MSIX_CAP as u32) << 8;
        config[MSIX_CAP / 4] = ((MSIX_ENTRIES as u32 - 1) << 16) | 0x11;
        config[MSIX_CAP / 4 + 1] = 0; // table in BAR 0 at 0
        config[MSIX_CAP / 4 + 2] = MSIX_PBA as u32;
        config[PCIE_CAP / 4 + 2] = DEVCTL;
        config[PCIE_CAP / 4 + 4] = 0x0000_0040;
        let state = State { ports, link: [true, false], config, ..State::default() };
        Self {
            bar0: bar0.as_mut_ptr(),
            uar: uar.as_mut_ptr(),
            msix: msix.as_mut_ptr(),
            _backing: (bar0, uar, msix),
            state: RefCell::new(state),
        }
    }

    /// The window the MSI-X table lives in.
    pub fn msix_io(&self) -> IoMem {
        // SAFETY: the window covers this device's MSI-X table memory.
        unsafe { IoMem::new(self.msix.cast(), MSIX_LEN) }
    }

    fn msix_reg(&self, dw: usize) -> u32 {
        // SAFETY: in bounds of the table window.
        unsafe { self.msix.add(dw).read_volatile() }
    }

    /// True if the function can send MSI-X vector `vector` now.
    fn msix_open(&self, s: &State, vector: u16) -> bool {
        let ctrl = s.config[MSIX_CAP / 4] >> 16;
        ctrl & 1 << 15 != 0 && ctrl & 1 << 14 == 0 && self.msix_reg(vector as usize * 4 + 3) & 1 == 0
    }

    /// The message programmed for table entry `vector`.
    pub fn msix_message(&self, vector: u16) -> MsiMessage {
        let e = vector as usize * 4;
        MsiMessage {
            address: (self.msix_reg(e + 1) as u64) << 32 | self.msix_reg(e) as u64,
            data: self.msix_reg(e + 2),
        }
    }

    /// Takes the vectors sent since the last call.
    pub fn take_interrupts(&self) -> Vec<u16> {
        core::mem::take(&mut self.state.borrow_mut().msi_sent)
    }

    pub fn config_io(&self) -> IoMem {
        // SAFETY: the window covers this device's BAR 0 memory.
        unsafe { IoMem::new(self.bar0.cast(), CONFIG_LEN) }
    }

    pub fn uar_io(&self) -> IoMem {
        // SAFETY: the window covers this device's UAR memory.
        unsafe { IoMem::new(self.uar.cast(), UAR_LEN) }
    }

    fn bar(&self, offset: usize) -> u32 {
        // SAFETY: in bounds of BAR 0.
        u32::from_be(unsafe { self.bar0.add(offset / 4).read_volatile() })
    }

    fn set_bar(&self, offset: usize, v: u32) {
        // SAFETY: in bounds of BAR 0.
        unsafe { self.bar0.add(offset / 4).write_volatile(v.to_be()) }
    }

    fn uar_reg(&self, offset: usize) -> u32 {
        // SAFETY: in bounds of the UAR.
        u32::from_be(unsafe { self.uar.add(offset / 4).read_volatile() })
    }

    /// The bus address of byte `off` of the buffer whose MTT entries start
    /// at byte address `mtt`, as the device translates it.
    fn translate(fw: &Firmware, mtt: u64, off: usize) -> u64 {
        let entry = fw.mtt.get(&(mtt + (off / 4096) as u64 * MTT_ENTRY)).expect("unmapped MTT entry");
        assert_eq!(entry & 1, 1, "MTT entry not present");
        (entry & !0xfff) + (off % 4096) as u64
    }

    fn mailbox(&self, n: usize) -> Vec<u32> {
        let pa = (self.bar(HCR) as u64) << 32 | self.bar(HCR + 4) as u64;
        assert_eq!(pa % 4096, 0, "mailbox alignment");
        (0..n).map(|i| rd(pa + 4 * i as u64)).collect()
    }

    fn out_mailbox(&self, data: &[u32]) {
        let pa = (self.bar(HCR + 12) as u64) << 32 | self.bar(HCR + 16) as u64;
        assert_ne!(pa, 0, "output mailbox expected");
        for (i, &d) in data.iter().enumerate() {
            wr(pa + 4 * i as u64, d);
        }
    }

    /// One firmware step: the reset logic and any pending command.
    fn step(&self) {
        let mut s = self.state.borrow_mut();
        s.now += 1_000_000;
        self.set_bar(RESET_SEMAPHORE, s.semaphore_stuck as u32);
        if self.bar(RESET) != 0 {
            assert_eq!(self.bar(RESET), 1, "reset magic");
            self.set_bar(RESET, 0);
            s.resets += 1;
            // Off the bus for a while, and the header lost.
            s.back_at = Some(s.now + 1_300_000_000);
            s.config[1..16].fill(0);
            s.config[PCIE_CAP / 4 + 2] = 0;
            s.fw = Firmware::default();
            self.set_bar(HCR + 24, 0);
        }
        if s.back_at.is_some_and(|t| s.now >= t) {
            s.back_at = None;
        }
        let ctl = self.bar(HCR + 24);
        if ctl & 1 << 23 == 0 {
            return;
        }
        let opcode = (ctl & 0xfff) as u16;
        if s.hang == Some(opcode) {
            return;
        }
        let op_mod = (ctl >> 12) & 0xf;
        let in_mod = self.bar(HCR + 8);
        let in_param = (self.bar(HCR) as u64) << 32 | self.bar(HCR + 4) as u64;
        s.log.push(opcode);
        let mut out = 0;
        let status = match s.fail {
            Some((o, status)) if o == opcode => status,
            _ => match self.command(&mut s, opcode, op_mod, in_mod, in_param) {
                Ok(v) => {
                    out = v;
                    0
                }
                Err(status) => status,
            },
        };
        self.set_bar(HCR + 12, (out >> 32) as u32);
        self.set_bar(HCR + 16, out as u32);
        // Done: status, the same toggle, `go` clear.
        self.set_bar(HCR + 24, (status as u32) << 24 | ctl & 1 << 21);
    }

    fn command(&self, s: &mut State, opcode: u16, op_mod: u32, in_mod: u32, in_param: u64) -> Result<u64, u8> {
        const BAD_OP: u8 = 0x01;
        const BAD_PARAM: u8 = 0x03;
        const BAD_STATE: u8 = 0x10;
        let before_hca = matches!(
            opcode,
            op::QUERY_FW
                | op::MAP_FA
                | op::RUN_FW
                | op::UNMAP_FA
                | op::QUERY_DEV_CAP
                | op::SET_ICM_SIZE
                | op::MAP_ICM
                | op::MAP_ICM_AUX
                | op::UNMAP_ICM
                | op::UNMAP_ICM_AUX
                | op::INIT_HCA
        );
        if !before_hca && !s.fw.hca_up {
            return Err(BAD_STATE);
        }
        let fw = &mut s.fw;
        match opcode {
            op::QUERY_FW => self.out_mailbox(&[FW_PAGES << 16 | 2, 5000 << 16 | 42]),
            op::MAP_FA | op::MAP_ICM | op::MAP_ICM_AUX => {
                assert_eq!(in_mod, 1);
                let m = self.mailbox(4);
                let va = (m[0] as u64) << 32 | m[1] as u64;
                let pa = (m[2] as u64) << 32 | (m[3] & !0xfff) as u64;
                let len = 1u64 << ((m[3] & 0x3f) + 12);
                assert!(
                    va.is_multiple_of(len) && pa.is_multiple_of(len),
                    "block {va:#x}/{pa:#x} not aligned to {len:#x}"
                );
                match opcode {
                    op::MAP_FA if fw.running => return Err(BAD_STATE),
                    op::MAP_FA => fw.fa_pages += len / 4096,
                    _ if !fw.running => return Err(BAD_STATE),
                    op::MAP_ICM_AUX => fw.aux_pages += len / 4096,
                    _ => {
                        assert!(va + len <= fw.icm_size, "MAP_ICM past SET_ICM_SIZE");
                        fw.icm.push((va, pa, len));
                    }
                }
            }
            op::RUN_FW if fw.fa_pages == FW_PAGES as u64 => fw.running = true,
            op::RUN_FW => return Err(BAD_STATE),
            op::UNMAP_FA => {
                fw.fa_pages = 0;
                fw.running = false;
            }
            _ if !fw.running => return Err(BAD_STATE),
            op::QUERY_DEV_CAP => {
                let mut c = [0u32; 64];
                c[4] = RSVD_QPS_LOG << 8;
                c[5] = 6 << 28;
                c[6] = RSVD_EQS << 24 | RSVD_CQS_LOG << 8;
                c[8] = RSVD_MTTS_LOG << 28 | RSVD_MRWS_LOG << 8;
                c[11] = if s.max_gso > 0 { 0x20 | s.max_gso.trailing_zeros() } else { 0 } << 16;
                c[13] = 2;
                c[17] = (s.dpdp as u32) << 12;
                c[18] = RSVD_UARS << 28;
                c[32] = 256;
                c[33] = 128 << 16 | 64;
                c[34] = 64 << 16 | 64;
                c[35] = 64 << 16 | 64;
                c[36] = (MTT_ENTRY as u32) << 16 | 64;
                self.out_mailbox(&c);
            }
            op::SET_ICM_SIZE => {
                fw.icm_size = in_param;
                return Ok(AUX_PAGES);
            }
            op::UNMAP_ICM => {
                let (start, end) = (in_param, in_param + in_mod as u64 * 4096);
                let mut pages = 0;
                fw.icm.retain(|&(va, _, len)| {
                    let hit = (start..end).contains(&va);
                    pages += if hit { len / 4096 } else { 0 };
                    !hit
                });
                assert_eq!(pages, in_mod as u64, "UNMAP_ICM of {in_mod} pages at {in_param:#x}");
            }
            op::UNMAP_ICM_AUX => fw.aux_pages = 0,
            op::INIT_HCA => {
                let c = self.mailbox(128);
                assert_eq!(c[0] >> 24, 2, "INIT_HCA version");
                // Every table must sit in mapped ICM, and the four cMPT
                // windows (one per object type) precede them.
                for (dw, mask) in [
                    (12, !0x1f),
                    (18, !0x1f),
                    (20, !0x1f),
                    (24, !0),
                    (28, !0),
                    (32, !0x1f),
                    (48, !0),
                    (60, !0),
                    (64, !0),
                ] {
                    let base = (c[dw] as u64) << 32 | (c[dw + 1] & mask) as u64;
                    assert!(base >= 4 << 30, "table at dword {dw} overlaps the cMPT windows");
                    assert!(
                        fw.icm.iter().any(|&(va, _, len)| (va..va + len).contains(&base)),
                        "table at dword {dw} unmapped"
                    );
                }
                fw.init_hca = c;
                fw.hca_up = true;
            }
            op::CLOSE_HCA => fw.hca_up = false,
            op::SW2HW_MPT => {
                assert_eq!(in_mod, 1 << RSVD_MRWS_LOG);
                let m = self.mailbox(16);
                assert_eq!(m[0] & 1 << 9, 1 << 9, "physical addressing");
                assert_eq!(m[10] & 1 << 22, 1 << 22, "covers everything");
                fw.lkey = Some(m[2].rotate_left(8));
            }
            op::WRITE_MTT => {
                let m = self.mailbox(4 + 2 * in_mod as usize);
                let base = (m[0] as u64) << 32 | m[1] as u64;
                for i in 0..in_mod as usize {
                    fw.mtt.insert(base + i as u64 * MTT_ENTRY, (m[4 + 2 * i] as u64) << 32 | m[5 + 2 * i] as u64);
                }
            }
            op::SW2HW_EQ => {
                let c = self.mailbox(16);
                let eq = Eq {
                    mtt: (c[6] as u64) << 32 | (c[7] & !7) as u64,
                    log_size: c[3] >> 24 & 0x1f,
                    pi: 0,
                    intr: c[5] & 0xff,
                    armed: c[0] >> 8 & 0xf == 0x9,
                    spent_arm: None,
                };
                fw.eqs.insert(in_mod, eq);
            }
            op::MAP_EQ => {
                assert!(fw.eqs.contains_key(&(in_mod & 0x1ff)), "MAP_EQ of a missing queue");
                fw.eq_mapped = in_mod & 1 << 31 == 0;
                fw.async_eqn = fw.eq_mapped.then_some(in_mod & 0x1ff);
            }
            op::HW2SW_EQ => {
                assert_eq!(op_mod, 1);
                if fw.cqs.values().any(|cq| cq.eqn == in_mod) {
                    return Err(BAD_STATE);
                }
                fw.eqs.remove(&in_mod).ok_or(BAD_STATE)?;
                self.out_mailbox(&[0; 16]);
            }
            op::CONF_SPECIAL_QP => fw.special_qp = Some(in_mod),
            op::QUERY_PORT => {
                let port = s.ports.get(in_mod as usize - 1).copied().flatten().ok_or(BAD_PARAM)?;
                let (ib, eth) = match port {
                    PortKind::Ethernet => (0, 1),
                    PortKind::InfiniBand => (1, 0),
                    PortKind::Vpi { .. } => (1, 1),
                };
                let link = s.link[in_mod as usize - 1] as u32;
                let m = MAC.map(u32::from);
                self.out_mailbox(&[
                    link << 31 | eth << 25 | ib << 24 | 1500,
                    0,
                    0,
                    0,
                    m[0] << 8 | m[1],
                    m[2] << 24 | m[3] << 16 | m[4] << 8 | m[5],
                ]);
            }
            op::SENSE_PORT => {
                let Some(PortKind::Vpi { sense_after, sensed }) = s.ports[in_mod as usize - 1] else {
                    return Err(BAD_PARAM);
                };
                s.sense_calls += 1;
                return Ok(if s.sense_calls > sense_after { sensed as u64 } else { 0 });
            }
            op::SW2HW_CQ => {
                let c = self.mailbox(16);
                assert_eq!(c[3] & 0xff_ffff, UAR_PAGE, "CQ UAR page");
                let eqn = c[5] & 0x1ff;
                assert!(fw.eqs.contains_key(&eqn), "CQ's event queue");
                let cq = Cq {
                    eqn,
                    spent_arm: None,
                    mtt: (c[6] as u64) << 32 | (c[7] & !7) as u64,
                    log_size: c[3] >> 24 & 0x1f,
                    db: (c[14] as u64) << 32 | (c[15] & !7) as u64,
                    pi: 0,
                };
                if fw.cqs.insert(in_mod, cq).is_some() {
                    return Err(BAD_STATE);
                }
            }
            op::HW2SW_CQ => {
                if fw.qps.values().any(|q| q.cqn_send == in_mod || q.cqn_recv == in_mod) {
                    return Err(BAD_STATE);
                }
                fw.cqs.remove(&in_mod).ok_or(BAD_STATE)?;
                self.out_mailbox(&[0; 16]);
            }
            op::RST2INIT_QP => {
                let c = self.mailbox(128);
                assert_eq!(c[2] >> 16 & 0xf, 7, "raw Ethernet service type");
                assert_eq!(c[5] & 0xff_ffff, UAR_PAGE);
                assert_eq!(c[6] & 0xff_ffff, in_mod, "local QPN");
                let qp = Qp {
                    state: 1,
                    mtt: (c[52] as u64 & 0xff) << 32 | (c[53] & !7) as u64,
                    log_sq: c[4] >> 11 & 0xf,
                    log_sq_stride: (c[4] >> 8 & 7) + 4,
                    log_rq: c[4] >> 19 & 0xf,
                    log_rq_stride: (c[4] >> 16 & 7) + 4,
                    cqn_send: c[33] & 0xff_ffff,
                    cqn_recv: c[41] & 0xff_ffff,
                    db: (c[42] as u64) << 32 | (c[43] & !3) as u64,
                    keep_vlan: c[50] & 1 << 30 != 0,
                    ..Qp::default()
                };
                if !fw.cqs.contains_key(&qp.cqn_send) || !fw.cqs.contains_key(&qp.cqn_recv) {
                    return Err(BAD_PARAM);
                }
                fw.qps.insert(in_mod, qp);
            }
            op::INIT2RTR_QP | op::RTR2RTS_QP => {
                let c = self.mailbox(128);
                let qp = fw.qps.get_mut(&in_mod).ok_or(BAD_STATE)?;
                if qp.state != if opcode == op::INIT2RTR_QP { 1 } else { 2 } {
                    return Err(BAD_STATE);
                }
                if opcode == op::INIT2RTR_QP {
                    assert_eq!(c[4] >> 29, 7, "Ethernet MTU");
                    qp.sched_queue = c[16] >> 24;
                }
                qp.state += 1;
            }
            op::TO_RST_QP => {
                fw.qps.remove(&in_mod).ok_or(BAD_STATE)?;
            }
            op::SET_PORT => {
                assert_eq!(op_mod, 1, "Ethernet SET_PORT");
                let port = (in_mod & 0xff) as usize - 1;
                match in_mod >> 8 {
                    0 => fw.port_mtu[port] = self.mailbox(2)[1] & 0xffff,
                    1 => {
                        let c = self.mailbox(8);
                        assert_eq!(c[5] >> 31, 1, "unicast promiscuous");
                        fw.promisc_qpn[port] = Some(c[5] & 0xff_ffff);
                    }
                    _ => return Err(BAD_PARAM),
                }
            }
            op::INIT_PORT => fw.port_up[in_mod as usize - 1] = true,
            op::CLOSE_PORT => fw.port_up[in_mod as usize - 1] = false,
            _ => return Err(BAD_OP),
        }
        Ok(0)
    }

    /// Writes a completion for entry `counter` of `qpn`'s send or receive
    /// queue, and queues an event if its completion queue is armed.
    fn complete(&self, fw: &mut Firmware, qpn: u32, send: bool, counter: u32, len: u32, csum: (u16, u16)) {
        let (status, checksum) = csum;
        let qp = &fw.qps[&qpn];
        let cqn = if send { qp.cqn_send } else { qp.cqn_recv };
        let cq = &fw.cqs[&cqn];
        let n = 1u32 << cq.log_size;
        let ci = rd(cq.db) & 0xff_ffff;
        assert!(cq.pi.wrapping_sub(ci) < n, "completion queue overflow");
        let pa = Self::translate(fw, cq.mtt, (cq.pi % n) as usize * 32);
        wr(pa, qpn);
        wr(pa + 16, (status as u32) << 16);
        wr(pa + 20, len);
        wr(pa + 24, counter << 16 | checksum as u32);
        let owner = (cq.pi / n) & 1;
        wr(pa + 28, owner << 7 | (send as u32) << 6 | if send { 0x0a } else { 0 });
        // Armed by a doorbell (and its record) not yet spent on an event.
        let arm = (self.uar_reg(UAR_PAGE as usize * 4096 + 0x20) as u64) << 32
            | self.uar_reg(UAR_PAGE as usize * 4096 + 0x24) as u64;
        let armed = arm >> 32 & 0xff_ffff == cqn as u64 && arm >> 56 & 3 == 2 && Some(arm) != cq.spent_arm;
        assert!(!armed || rd(cq.db + 4) == (arm >> 32) as u32 & !0xff_ffff | arm as u32 & 0xff_ffff, "arm record");
        let cq = fw.cqs.get_mut(&cqn).unwrap();
        cq.pi += 1;
        if armed {
            cq.spent_arm = Some(arm);
            fw.notify.push(cqn);
        }
    }

    /// Posts a completion event for each notified queue and raises the
    /// interrupt of every armed event queue that received one.
    fn flush_events(&self, s: &mut State) {
        let cqns = core::mem::take(&mut s.fw.notify);
        for cqn in cqns {
            let eqn = s.fw.cqs[&cqn].eqn;
            self.post_event(s, eqn, 0x00, 0, 4, cqn);
        }
    }

    /// Writes an event of `kind` to event queue `eqn` (the dword at byte
    /// `at` is `word`, `head` the low 16 bits of dword 0), then interrupts if it is armed.
    fn post_event(&self, s: &mut State, eqn: u32, kind: u32, head: u32, at: usize, word: u32) {
        let doorbell = 0x800 + 4096 * (eqn as usize / 4) + 8 * (eqn as usize % 4);
        let db = self.uar_reg(doorbell);
        let eq = s.fw.eqs.get_mut(&eqn).unwrap();
        let n = 1u32 << eq.log_size;
        assert!(eq.pi.wrapping_sub(db & 0xff_ffff) & 0xff_ffff < n, "event queue overflow");
        let (mtt, pi, intr) = (eq.mtt, eq.pi, eq.intr as u16);
        eq.pi += 1;
        // Armed at creation, or by a doorbell write not yet spent.
        let rearmed = db & 1 << 31 != 0 && Some(db) != eq.spent_arm;
        let fire = eq.armed || rearmed;
        if fire {
            eq.armed = false;
            eq.spent_arm = Some(db);
        }
        let pa = Self::translate(&s.fw, mtt, (pi % n) as usize * 32);
        wr(pa, kind << 16 | head);
        wr(pa + at as u64, word);
        wr(pa + 28, ((pi / n) & 1) << 7);
        if fire {
            if self.msix_open(s, intr) {
                s.msi_sent.push(intr);
            } else {
                s.msi_pending.push(intr);
            }
        }
    }

    /// Runs the send engine: returns the frames `qpn` has posted (and rung
    /// the doorbell for), completing each.
    pub fn sent(&self, qpn: u32) -> Vec<Vec<u8>> {
        self.sent_ex(qpn).into_iter().map(|f| f.frame).collect()
    }

    /// Like [`sent`](Self::sent), with the offload flags of each entry.
    pub fn sent_ex(&self, qpn: u32) -> Vec<Sent> {
        let mut s = self.state.borrow_mut();
        let mut frames = Vec::new();
        loop {
            let fw = &mut s.fw;
            let qp = &fw.qps[&qpn];
            let (n, stride) = (1u32 << qp.log_sq, 1usize << qp.log_sq_stride);
            let wqe = Self::translate(fw, qp.mtt, (qp.sq_next % n) as usize * stride);
            let ctrl = rd(wqe);
            if ctrl >> 31 != (qp.sq_next / n) & 1 {
                break;
            }
            assert_eq!(self.uar_reg(UAR_PAGE as usize * 4096 + 0x14), qpn << 8, "send doorbell");
            let flags = rd(wqe + 8);
            assert_eq!(flags & 0xe, 0xe, "completion and solicited");
            let (ip_csum, l4_csum) = (flags & 1 << 4 != 0, flags & 1 << 5 != 0);
            let segments = rd(wqe + 4) & 0x3f;
            let (frame, lso) = match ctrl & 0x1f {
                0x0a => {
                    assert_eq!(segments, 2, "control + one data segment");
                    let len = rd(wqe + 16);
                    assert_eq!(Some(rd(wqe + 20)), fw.lkey, "lkey");
                    let addr = (rd(wqe + 24) as u64) << 32 | rd(wqe + 28) as u64;
                    // SAFETY: the driver's transmit buffer, identity-mapped.
                    (unsafe { core::slice::from_raw_parts(addr as *const u8, len as usize) }.to_vec(), None)
                }
                0x0e => {
                    let (mss, hdr) = (rd(wqe + 16) >> 16, (rd(wqe + 16) & 0xffff) as usize);
                    let seg = (4 + hdr).next_multiple_of(16);
                    assert_eq!(segments as usize, 2 + seg / 16, "control + LSO + one data segment");
                    let mut frame = Vec::new();
                    for i in 0..hdr {
                        // The inline header is raw bytes, not big-endian dwords.
                        // SAFETY: inside the send queue entry, identity-mapped.
                        frame.push(unsafe { ((wqe + 20 + i as u64) as *const u8).read_volatile() });
                    }
                    let d = wqe + 16 + seg as u64;
                    let len = rd(d);
                    assert_eq!(Some(rd(d + 4)), fw.lkey, "lkey");
                    let addr = (rd(d + 8) as u64) << 32 | rd(d + 12) as u64;
                    // SAFETY: the driver's LSO staging buffer, identity-mapped.
                    frame.extend_from_slice(unsafe { core::slice::from_raw_parts(addr as *const u8, len as usize) });
                    (frame, Some((mss as u16, hdr)))
                }
                other => panic!("unexpected send opcode {other:#x}"),
            };
            frames.push(Sent { frame, ip_csum, l4_csum, lso });
            let counter = qp.sq_next & 0xffff;
            fw.qps.get_mut(&qpn).unwrap().sq_next += 1;
            let mut fw = core::mem::take(&mut s.fw);
            self.complete(&mut fw, qpn, true, counter, 0, (0, 0));
            s.fw = fw;
        }
        self.flush_events(&mut s);
        frames
    }

    /// Runs the receive engine for one frame arriving on `port`. Returns
    /// false if it was dropped: port down or no receive entry posted.
    pub fn deliver(&self, port: u8, frame: &[u8]) -> bool {
        self.deliver_with(port, frame, 0, 0)
    }

    /// Like [`deliver`](Self::deliver), with the completion's status word and
    /// checksum field.
    pub fn deliver_with(&self, port: u8, frame: &[u8], status: u16, checksum: u16) -> bool {
        let mut s = self.state.borrow_mut();
        let mut fw = core::mem::take(&mut s.fw);
        let delivered = self.receive_engine(&mut fw, port, frame, status, checksum);
        s.fw = fw;
        self.flush_events(&mut s);
        delivered
    }

    fn receive_engine(&self, fw: &mut Firmware, port: u8, frame: &[u8], status: u16, checksum: u16) -> bool {
        let p = port as usize - 1;
        let Some(qpn) = fw.promisc_qpn[p].filter(|_| fw.port_up[p]) else {
            return false;
        };
        let qp = &fw.qps[&qpn];
        assert_eq!(qp.state, 3, "receiving into a QP not in RTS");
        assert!(qp.keep_vlan);
        assert_eq!(qp.sched_queue, 0x83 | (p as u32) << 6);
        let posted = rd(qp.db) & 0xffff;
        if qp.rq_next & 0xffff == posted {
            return false;
        }
        let (n, stride) = (1u32 << qp.log_rq, 1usize << qp.log_rq_stride);
        let sq_len = (1usize << qp.log_sq) << qp.log_sq_stride;
        let wqe = Self::translate(fw, qp.mtt, sq_len + (qp.rq_next % n) as usize * stride);
        let room = rd(wqe);
        assert_eq!(Some(rd(wqe + 4)), fw.lkey);
        assert_eq!(rd(wqe + 20), 0x100, "scatter list terminator");
        let addr = (rd(wqe + 8) as u64) << 32 | rd(wqe + 12) as u64;
        assert!(frame.len() <= room as usize);
        // SAFETY: the driver's receive buffer, identity-mapped.
        unsafe { core::slice::from_raw_parts_mut(addr as *mut u8, frame.len()) }.copy_from_slice(frame);
        let counter = qp.rq_next & 0xffff;
        fw.qps.get_mut(&qpn).unwrap().rq_next += 1;
        self.complete(fw, qpn, false, counter, frame.len() as u32, (status, checksum));
        true
    }

    /// Reports a port state change through the event queue.
    pub fn port_event(&self, port: u8, up: bool) {
        let mut s = self.state.borrow_mut();
        s.link[port as usize - 1] = up;
        let eqn = s.fw.async_eqn.expect("event queue mapped");
        self.post_event(&mut s, eqn, 0x09, if up { 4 } else { 1 }, 12, (port as u32) << 28);
    }

    /// Keeps the flash semaphore taken, as during a firmware update.
    pub fn hold_semaphore(&self) {
        self.state.borrow_mut().semaphore_stuck = true;
        self.set_bar(RESET_SEMAPHORE, 1);
    }

    pub fn qps(&self) -> Vec<u32> {
        self.state.borrow().fw.qps.keys().copied().collect()
    }

    pub fn cqs(&self) -> Vec<u32> {
        self.state.borrow().fw.cqs.keys().copied().collect()
    }

    /// Removes the MSI-X capability from the capability list.
    pub fn remove_msix(&self) {
        self.state.borrow_mut().config[PCIE_CAP / 4] &= !0xff00;
    }

    pub fn config(&self, dw: usize) -> u32 {
        self.state.borrow().config[dw]
    }
}

impl Clock for FakeHca {
    fn now_ns(&self) -> u64 {
        self.step();
        self.state.borrow().now
    }
}

impl ConfigAccess for FakeHca {
    fn read32(&self, addr: Address, offset: u16) -> u32 {
        let s = self.state.borrow();
        if addr != ADDR || s.back_at.is_some() {
            return !0;
        }
        s.config[offset as usize / 4]
    }

    fn write32(&self, addr: Address, offset: u16, value: u32) {
        let mut s = self.state.borrow_mut();
        if addr != ADDR || s.back_at.is_some() {
            return;
        }
        let dw = &mut s.config[offset as usize / 4];
        // The status half of COMMAND_STATUS is read-only here (its
        // capabilities-list bit must survive command writes), except after
        // reset when the whole header is being rebuilt.
        *dw = if offset == 4 && *dw != 0 { (*dw & 0xffff_0000) | (value & 0xffff) } else { value };
    }
}
