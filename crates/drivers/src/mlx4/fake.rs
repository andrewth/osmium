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
use super::{CONFIG_LEN, PD, RESET, RESET_SEMAPHORE, UAR_LEN, UAR_PAGE};

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
    /// The arm record value already used up by an event.
    spent_arm: Option<u32>,
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
    /// The datagram segment of an unreliable datagram send; `frame` is then
    /// the payload.
    pub ud: Option<UdSend>,
    /// An "MLX" entry of a special queue pair: the packet it describes.
    pub mlx: Option<MlxSend>,
}

/// A send entry of queue pair 0 or 1: the control fields, the headers
/// packed inline, and the datagram.
#[derive(Debug, PartialEq, Eq)]
pub struct MlxSend {
    pub vl15: bool,
    pub slr: bool,
    pub sl: u8,
    pub rlid: u16,
    pub packet: Packet,
    pub payload: Vec<u8>,
    /// Entry size in 16-byte units.
    pub size: u32,
}

/// A packet's headers, decoded from the wire format.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Packet {
    pub vl: u8,
    pub sl: u8,
    pub lnh: u8,
    pub dlid: u16,
    pub slid: u16,
    pub length: u16,
    pub grh: Option<PacketGrh>,
    pub opcode: u8,
    pub solicited: bool,
    pub pad: u8,
    pub pkey: u16,
    pub dest_qpn: u32,
    pub psn: u32,
    pub qkey: u32,
    pub src_qpn: u32,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PacketGrh {
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub source: [u8; 16],
    pub dest: [u8; 16],
}

impl Packet {
    /// Decodes LRH, optional GRH, BTH and DETH.
    pub fn decode(h: &[u8]) -> Self {
        let w = |at: usize| u32::from_be_bytes([h[at], h[at + 1], h[at + 2], h[at + 3]]);
        let (lnh, mut at) = (h[1] & 3, 8);
        let grh = (lnh == 3).then(|| {
            let g = PacketGrh {
                traffic_class: (w(8) >> 20) as u8,
                flow_label: w(8) & 0xf_ffff,
                payload_length: (w(12) >> 16) as u16,
                next_header: (w(12) >> 8) as u8,
                hop_limit: w(12) as u8,
                source: h[16..32].try_into().unwrap(),
                dest: h[32..48].try_into().unwrap(),
            };
            assert_eq!(w(8) >> 28, 6, "IP version of the global route header");
            at += 40;
            g
        });
        assert_eq!(h.len(), at + 20, "the header is exactly LRH [GRH] BTH DETH");
        Self {
            vl: h[0] >> 4,
            sl: h[1] >> 4,
            lnh,
            dlid: u16::from_be_bytes([h[2], h[3]]),
            slid: u16::from_be_bytes([h[6], h[7]]),
            length: u16::from_be_bytes([h[4], h[5]]) & 0x7ff,
            grh,
            opcode: h[at],
            solicited: h[at + 1] & 0x80 != 0,
            pad: h[at + 1] >> 4 & 3,
            pkey: u16::from_be_bytes([h[at + 2], h[at + 3]]),
            dest_qpn: w(at + 4) & 0xff_ffff,
            psn: w(at + 8) & 0xff_ffff,
            qkey: w(at + 12),
            src_qpn: w(at + 16) & 0xff_ffff,
        }
    }
}

/// The address vector, queue pair and key of a datagram send entry.
#[derive(Debug, PartialEq, Eq)]
pub struct UdSend {
    pub port: u8,
    pub pd: u32,
    pub dlid: u16,
    pub path_bits: u8,
    pub grh: bool,
    pub sl: u8,
    pub sgid_index: u8,
    pub hop_limit: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub dgid: [u8; 16],
    pub dqpn: u32,
    pub qkey: u32,
}

/// Where a datagram handed to [`FakeHca::deliver_ud`] came from.
#[derive(Clone, Copy, Debug)]
pub struct UdFrom {
    pub lid: u16,
    pub qpn: u32,
    pub sl: u8,
    pub path_bits: u8,
}

/// The state the subnet manager and the link set for an InfiniBand port.
#[derive(Clone, Debug)]
pub struct IbState {
    pub lid: u16,
    pub sm_lid: u16,
    pub sm_sl: u8,
    pub lmc: u8,
    /// 1 down, 2 initializing, 3 armed, 4 active.
    pub state: u8,
    pub gid_prefix: u64,
    pub guids: [u64; 8],
    pub pkeys: [u16; 16],
    /// The SL-to-VL table, a nibble per service level.
    pub sl2vl: [u8; 8],
}

pub const NODE_GUID: u64 = 0x0002_c903_0012_3456;
pub const GID_PREFIX: u64 = 0xfe80_0000_0000_0000;
pub const SM_LID: u16 = 1;
pub const IB_PKEYS: usize = 16;
/// The capability mask the firmware advertises before SET_PORT.
pub const IB_CAPS: u32 = 0x0259_0848;

impl IbState {
    fn new(port: usize) -> Self {
        let mut guids = [0; 8];
        guids[0] = NODE_GUID + 1 + port as u64;
        let mut pkeys = [0; IB_PKEYS];
        pkeys[0] = 0xffff;
        Self { lid: 0, sm_lid: 0, sm_sl: 0, lmc: 0, state: 1, gid_prefix: GID_PREFIX, guids, pkeys, sl2vl: [0; 8] }
    }
}

/// (slid, my_qpn, rqpn, sl, g_path, pkey, GRH) of a received datagram, as
/// MAD_IFC takes them.
pub type WorkCompletion = (u32, u32, u32, u8, u8, u16, [u8; 40]);

/// What a management datagram handed to MAD_IFC came with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MadIfcCall {
    pub port: u32,
    pub op_mod: u32,
    pub wc: Option<WorkCompletion>,
    pub mad: Vec<u8>,
}

/// The hash bucket the firmware puts a multicast GID in (a stand-in for
/// the real function).
pub fn mgid_hash(gid: &[u8; 16]) -> u32 {
    gid.iter().fold(0u32, |a, &b| a.wrapping_mul(31).wrapping_add(b as u32)) & 127
}

/// What a reliable connection's transitions told the firmware, and where
/// its packet sequence numbers stand.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RcCtx {
    pub pkey_index: u32,
    /// Remote access at INIT and at RTR: bit 2 read, bit 1 write, bit 0 atomic.
    pub init_access: u32,
    pub access: u32,
    pub remote_qpn: u32,
    pub dlid: u32,
    pub grh: bool,
    pub path_bits: u32,
    pub sched_queue: u32,
    pub sgid_index: u32,
    pub hop_limit: u32,
    pub tclass_flow: u32,
    pub dgid: [u8; 16],
    pub max_dest_rd_log: u32,
    pub rq_psn: u32,
    pub min_rnr_timer: u32,
    pub ack_timeout: u32,
    pub retry: u32,
    pub rnr_retry: u32,
    pub max_rd_log: u32,
    pub sq_psn: u32,
    /// The path MTU in bytes.
    pub mtu_bytes: u32,
    /// The next packet number this end sends, and expects from the peer.
    pub send_psn: u32,
    pub recv_psn: u32,
}

/// A memory region the adapter holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mr {
    pub key: u32,
    pub start: u64,
    pub len: u64,
    /// The permission bits of the table entry (local read 10, local write 11,
    /// remote read 12, remote write 13, atomic 14).
    pub access: u32,
}

/// What a completion queue entry reports.
#[derive(Clone, Copy)]
enum Cqe {
    /// Success, with this opcode.
    Ok(u32),
    /// Failure, with this syndrome.
    Err(u8),
}

#[derive(Default, Debug)]
struct Qp {
    rc: RcCtx,
    service: u32,
    pkey_index: u32,
    qkey: u32,
    init_optpar: u32,
    state: u8, // 1 INIT, 2 RTR, 3 RTS
    /// Queue pair 0 or 1 ("MLX" service on an InfiniBand port).
    special: bool,
    mtu_msgmax: u32,
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
    /// The capability mask SET_PORT gave each InfiniBand port.
    pub ib_caps: [Option<u32>; 2],
    /// The virtual lane count and MTU limit it asked for.
    pub ib_set: [Option<(u32, u32)>; 2],
    /// INIT_PORT has run on this InfiniBand port.
    pub ib_init: [bool; 2],
    /// The memory regions, by table index.
    pub mrs: BTreeMap<u32, Mr>,
    /// Management datagrams the firmware agent was asked to answer.
    pub mad_ifc: Vec<MadIfcCall>,
    /// Multicast group table entries in use, by index (16 dwords each).
    pub mcg: BTreeMap<u32, [u32; 16]>,
}

#[derive(Default)]
pub struct State {
    pub ib: [Option<IbState>; 2],
    /// SET_PORT refuses more virtual lanes than this (0 means no limit).
    pub ib_max_vls: u32,
    /// Port state changes the agent made, to report as port events.
    port_events: Vec<(u8, bool)>,
    now: u64,
    /// Every opcode issued, in order.
    pub log: Vec<u16>,
    /// Make this opcode fail with this status, after letting it succeed
    /// `fail_skip` times.
    pub fail: Option<(u16, u8)>,
    pub fail_skip: u32,
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
        let ib = [0, 1]
            .map(|p| matches!(ports[p], Some(PortKind::InfiniBand | PortKind::Vpi { .. })).then(|| IbState::new(p)));
        let state = State { ports, link: [true, false], config, ib, ib_max_vls: 4, ..State::default() };
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
        let failing = match s.fail {
            Some((o, status)) if o == opcode && s.fail_skip == 0 => Some(status),
            Some((o, _)) if o == opcode => {
                s.fail_skip -= 1;
                None
            }
            _ => None,
        };
        let status = match failing {
            Some(status) => status,
            None => match self.command(&mut s, opcode, op_mod, in_mod, in_param) {
                Ok(v) => {
                    out = v;
                    0
                }
                Err(status) => status,
            },
        };
        for (port, up) in core::mem::take(&mut s.port_events) {
            if let Some(eqn) = s.fw.async_eqn {
                self.post_event(&mut s, eqn, 0x09, if up { 4 } else { 1 }, 12, (port as u32) << 28);
            }
        }
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
                c[10] = 6 << 16 | 6;
                c[13] = 2;
                c[14] = 31 << 24;
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
                let m = self.mailbox(16);
                assert_eq!(m[0] >> 28, 0xf, "owned by the adapter");
                assert_eq!(m[0] & (1 << 17 | 1 << 9 | 1 << 8), 1 << 17 | 1 << 9 | 1 << 8, "a physical-address region");
                assert_eq!(m[3], PD | 3 << 24, "protection domain");
                let (start, len) = ((m[4] as u64) << 32 | m[5] as u64, (m[6] as u64) << 32 | m[7] as u64);
                let access = m[0] & 0x7c00;
                if in_mod == 1 << RSVD_MRWS_LOG {
                    // The one the work queue entries use: everything, for the adapter only.
                    assert_eq!((start, len, access), (0, u64::MAX, 3 << 10), "local access to everything, no remote");
                    fw.lkey = Some(m[2].rotate_left(8));
                } else {
                    assert!(in_mod > 1 << RSVD_MRWS_LOG && in_mod < 1 << (RSVD_MRWS_LOG + 1), "a window's table entry");
                    assert!(len > 0 && len < u64::MAX, "a window is a bounded range");
                }
                if fw.mrs.insert(in_mod, Mr { key: m[2], start, len, access }).is_some() {
                    return Err(BAD_STATE);
                }
            }
            op::HW2SW_MPT => {
                assert_eq!(op_mod, 1, "no output wanted");
                fw.mrs.remove(&in_mod).ok_or(BAD_STATE)?;
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
                // The InfiniBand MTU capability is 4096, beyond what the
                // driver uses; 4 widths, 8 GIDs and 16 partition keys; 8 VLs.
                self.out_mailbox(&[
                    link << 31 | eth << 25 | ib << 24 | 5 << 16 | 1500,
                    2 << 8 | 3 << 4 | 4,
                    3,
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
                let service = c[2] >> 16 & 0xf;
                assert!(matches!(service, 0 | 3 | 7), "reliable, datagram, or raw/special service type");
                assert_eq!(c[5] & 0xff_ffff, UAR_PAGE);
                assert_eq!(c[6] & 0xff_ffff, in_mod, "local QPN");
                assert_eq!(c[2] >> 28, 1, "entering INIT");
                assert_eq!(c[2] >> 11 & 3, 3, "migrated");
                assert_eq!(c[3] & 0xff_ffff, PD);
                assert_eq!(c[30] >> 28, 8, "acknowledgment request frequency");
                assert_eq!(c[30] >> 11 & 1, 1, "fast registration");
                assert_eq!(c[4] >> 4 & 1, 1, "kernel queue pair");
                let special = fw.special_qp.is_some_and(|base| (base..base + 4).contains(&in_mod));
                let mtu_msgmax = c[4] >> 24;
                match (service, special) {
                    (7, false) => assert_eq!((c[0], mtu_msgmax), (0, 7 << 5 | 31), "raw Ethernet"),
                    (7, true) => assert_eq!((c[0], mtu_msgmax), (0x30, 5 << 5 | 11), "special queue pair"),
                    (3, _) => assert_eq!((c[0], mtu_msgmax), (0x30, 5 << 5 | 13), "datagram queue pair"),
                    // The MTU is the connection's, not known yet; the key and write access are
                    // named, and the read access is held back until there are responder resources.
                    (0, _) => assert_eq!((c[0], mtu_msgmax, c[38] >> 13 & 7), (0x1e, 0, 2), "reliable connection"),
                    _ => unreachable!(),
                }
                let qp = Qp {
                    rc: RcCtx { pkey_index: c[8] & 0xff, init_access: c[38] >> 13 & 7, ..RcCtx::default() },
                    service,
                    special,
                    mtu_msgmax,
                    pkey_index: c[8] & 0xff,
                    qkey: c[44],
                    init_optpar: c[0],
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
                let (from, to) = if opcode == op::INIT2RTR_QP { (1, 2) } else { (2, 3) };
                if qp.state != from {
                    return Err(BAD_STATE);
                }
                assert_eq!(c[2] >> 28, to as u32, "entering the next state");
                assert_eq!(c[2] >> 16 & 0xf, qp.service, "service type in every transition");
                if qp.service == 0 && opcode == op::INIT2RTR_QP {
                    qp.mtu_msgmax = c[4] >> 24;
                }
                assert_eq!(c[4] >> 24, qp.mtu_msgmax, "MTU and message size in every transition");
                if opcode == op::INIT2RTR_QP {
                    qp.sched_queue = c[16] >> 24;
                }
                if qp.service == 0 {
                    let r = &mut qp.rc;
                    match opcode {
                        op::INIT2RTR_QP => {
                            // Primary path, schedule queue, RNR timeout, responder resources, access.
                            assert_eq!(c[0], 1 << 7 | 1 << 16 | 1 << 6 | 1 << 9 | 0xe, "optional parameters");
                            assert_eq!(c[4] >> 24 & 0x1f, 31, "maximum message size from the device");
                            r.mtu_bytes = 128 << (c[4] >> 29);
                            r.remote_qpn = c[7] & 0xff_ffff;
                            r.dlid = c[9] & 0xffff;
                            r.grh = c[9] >> 16 & 0x80 != 0;
                            r.path_bits = c[9] >> 16 & 0x7f;
                            (r.sgid_index, r.hop_limit) = (c[10] >> 16 & 0xff, c[10] & 0xff);
                            r.tclass_flow = c[11];
                            for i in 0..4 {
                                r.dgid[4 * i..4 * i + 4].copy_from_slice(&c[12 + i].to_be_bytes());
                            }
                            r.sched_queue = c[16] >> 24;
                            r.max_dest_rd_log = c[38] >> 21 & 7;
                            r.access = c[38] >> 13 & 7;
                            (r.rq_psn, r.min_rnr_timer) = (c[39] & 0xff_ffff, c[39] >> 24 & 0x1f);
                            r.recv_psn = r.rq_psn;
                        }
                        _ => {
                            assert_eq!(c[0], 1 << 14 | 1 << 12 | 1 << 13 | 1 << 8, "optional parameters");
                            r.ack_timeout = c[10] >> 27;
                            (r.retry, r.rnr_retry, r.max_rd_log) = (c[30] >> 16 & 7, c[30] >> 13 & 7, c[30] >> 21 & 7);
                            r.sq_psn = c[32] & 0xff_ffff;
                            r.send_psn = r.sq_psn;
                        }
                    }
                }
                qp.state = to;
            }
            op::RTS2RTS_QP => {
                let c = self.mailbox(128);
                let qp = fw.qps.get_mut(&in_mod).ok_or(BAD_STATE)?;
                if qp.state != 3 {
                    return Err(BAD_STATE);
                }
                assert_eq!((c[0], c[2] >> 28), (1 << 5, 3), "only the queue key changes, in ready-to-send");
                assert_eq!(qp.service, 3, "queue keys belong to datagram queue pairs");
                qp.qkey = c[44];
            }
            op::TO_RST_QP => {
                assert!(
                    !fw.mcg.values().any(|e| e[8..8 + (e[1] & 0xff_ffff) as usize].contains(&in_mod)),
                    "queue pair {in_mod} destroyed while attached to a multicast group"
                );
                fw.qps.remove(&in_mod).ok_or(BAD_STATE)?;
            }
            op::SET_PORT if op_mod == 0 => {
                let port = in_mod as usize - 1;
                if s.ib[port].is_none() {
                    return Err(BAD_PARAM);
                }
                let m = self.mailbox(2);
                let (vls, mtu) = (m[0] >> 4 & 0xf, m[0] >> 12 & 0xf);
                assert_eq!(m[0] & !(0xf << 4 | 0xf << 12), 1 << 22 | 1 << 21, "change the MTU and VL limits only");
                assert!(matches!(vls, 1 | 2 | 4 | 8), "a VL count");
                if s.ib_max_vls != 0 && vls > s.ib_max_vls {
                    return Err(0x08); // exceeds the device's limits
                }
                fw.ib_caps[port] = Some(m[1]);
                fw.ib_set[port] = Some((vls, mtu));
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
            op::INIT_PORT => {
                let p = in_mod as usize - 1;
                fw.port_up[p] = true;
                // InfiniBand mode is what SET_PORT with operation modifier 0 selected.
                if let (Some(ib), Some(_)) = (&mut s.ib[p], fw.ib_caps[p]) {
                    assert_eq!(in_param, 0, "INIT_PORT takes no parameters");
                    // The port starts when queue pair 0 is ready to receive.
                    let qp0 = fw.special_qp.expect("special queue pairs configured") + p as u32;
                    assert!(fw.qps.get(&qp0).is_some_and(|q| q.state == 2), "INIT_PORT with queue pair 0 in RTR");
                    fw.ib_init[p] = true;
                    if ib.state == 1 && s.link[p] {
                        ib.state = 2;
                    }
                }
            }
            op::CLOSE_PORT => {
                let p = in_mod as usize - 1;
                fw.port_up[p] = false;
                fw.ib_init[p] = false;
                if let (Some(ib), Some(_)) = (&mut s.ib[p], fw.ib_caps[p].take()) {
                    // The link drops and the subnet manager's settings go with it.
                    *ib = IbState { guids: ib.guids, pkeys: ib.pkeys, ..IbState::new(p) };
                }
            }
            op::MAD_IFC => {
                assert!(matches!(op_mod, 3 | 4), "ignore both keys, or check them for a received work completion");
                let port = (in_mod & 0xffff) as usize - 1;
                let ib = s.ib[port].as_mut().ok_or(BAD_PARAM)?;
                let ext = op_mod == 4;
                let m = self.mailbox(if ext { 128 } else { 64 });
                let wc = ext.then(|| {
                    let mut grh = [0u8; 40];
                    for i in 0..10 {
                        grh[4 * i..4 * i + 4].copy_from_slice(&m[80 + i].to_be_bytes());
                    }
                    (in_mod >> 16, m[64], m[66], (m[67] >> 28) as u8, (m[67] >> 16) as u8, m[68] as u16, grh)
                });
                let mad: Vec<u8> = m[..64].iter().flat_map(|d| d.to_be_bytes()).collect();
                fw.mad_ifc.push(MadIfcCall { port: port as u32 + 1, op_mod, wc, mad });
                let caps = fw.ib_caps[port].unwrap_or(IB_CAPS);
                let reply = self.sma(ib, port, caps, &m[..64], &mut s.port_events);
                self.out_mailbox(&reply);
            }
            op::MGID_HASH => {
                let m = self.mailbox(4);
                let gid: Vec<u8> = m.iter().flat_map(|d| d.to_be_bytes()).collect();
                return Ok(mgid_hash(&gid.try_into().unwrap()) as u64);
            }
            op::READ_MCG => {
                assert!(in_mod < 128);
                self.out_mailbox(&fw.mcg.get(&in_mod).copied().unwrap_or([0; 16]));
            }
            op::WRITE_MCG => {
                assert!(in_mod < 128);
                let e: [u32; 16] = self.mailbox(16).try_into().unwrap();
                let count = (e[1] & 0xff_ffff) as usize;
                assert!(count <= 8 && e[1] >> 24 == 0 && e[0] == 0, "entry header");
                if count == 0 {
                    assert!(e.iter().all(|&d| d == 0), "an empty entry is all zeros");
                    fw.mcg.remove(&in_mod);
                } else {
                    let gid: Vec<u8> = e[4..8].iter().flat_map(|d| d.to_be_bytes()).collect();
                    assert_eq!(mgid_hash(&gid.try_into().unwrap()), in_mod, "group in its hash bucket");
                    assert!(e[8 + count..].iter().all(|&d| d == 0), "unused member slots are clear");
                    fw.mcg.insert(in_mod, e);
                }
            }
            _ => return Err(BAD_OP),
        }
        Ok(0)
    }

    /// Writes a completion for entry `counter` of `qpn`'s send or receive
    /// queue, and queues an event if its completion queue is armed.
    fn complete(&self, fw: &mut Firmware, qpn: u32, send: bool, counter: u32, len: u32, csum: (u16, u16)) {
        let cqe = Cqe::Ok(if send { 0x0a } else { 1 });
        self.complete_ud(fw, qpn, send, counter, len, csum, (0, 0, 0), cqe);
    }

    /// Like [`complete`](Self::complete), with the sender fields of a
    /// datagram receive: the CQE's third and fourth dwords.
    #[allow(clippy::too_many_arguments)]
    fn complete_ud(
        &self,
        fw: &mut Firmware,
        qpn: u32,
        send: bool,
        counter: u32,
        len: u32,
        csum: (u16, u16),
        sender: (u32, u32, u32),
        cqe: Cqe,
    ) {
        let (status, checksum) = csum;
        let qp = &fw.qps[&qpn];
        let cqn = if send { qp.cqn_send } else { qp.cqn_recv };
        let cq = &fw.cqs[&cqn];
        let n = 1u32 << cq.log_size;
        let ci = rd(cq.db) & 0xff_ffff;
        assert!(cq.pi.wrapping_sub(ci) < n, "completion queue overflow");
        let pa = Self::translate(fw, cq.mtt, (cq.pi % n) as usize * 32);
        wr(pa, qpn);
        wr(pa + 4, sender.2);
        wr(pa + 8, sender.0);
        wr(pa + 12, sender.1);
        wr(pa + 16, (status as u32) << 16);
        wr(pa + 20, len);
        let owner = (cq.pi / n) & 1;
        match cqe {
            Cqe::Ok(opcode) => {
                wr(pa + 24, counter << 16 | checksum as u32);
                wr(pa + 28, owner << 7 | (send as u32) << 6 | opcode);
            }
            // An error completion: the entry, the vendor syndrome and the syndrome.
            Cqe::Err(syndrome) => {
                wr(pa + 24, counter << 16 | syndrome as u32);
                wr(pa + 28, owner << 7 | (send as u32) << 6 | 0x1e);
            }
        }
        // Armed by the queue's arm record (written just before its doorbell)
        // not yet spent on an event.
        let record = rd(cq.db + 4);
        let armed = record >> 24 & 7 == 2 && Some(record) != cq.spent_arm;
        let cq = fw.cqs.get_mut(&cqn).unwrap();
        cq.pi += 1;
        if armed {
            cq.spent_arm = Some(record);
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
            // One doorbell register serves every queue pair, so it names the last to ring it.
            assert!(fw.qps.contains_key(&(self.uar_reg(UAR_PAGE as usize * 4096 + 0x14) >> 8)), "send doorbell");
            let flags = rd(wqe + 8);
            assert_eq!(flags & 0xc, 0xc, "completion");
            assert!(qp.special || flags & 2 != 0, "solicited");
            let (ip_csum, l4_csum) = (flags & 1 << 4 != 0, flags & 1 << 5 != 0);
            let segments = rd(wqe + 4) & 0x3f;
            let (frame, lso, ud, mlx) = match ctrl & 0x1f {
                0x0a if qp.special => {
                    let (size, rlid) = (rd(wqe + 4) & 0x3f, (rd(wqe + 12) >> 16) as u16);
                    // The headers sit in inline segments, none across a 64-byte boundary.
                    let (mut header, mut at) = (Vec::new(), wqe + 16);
                    while rd(at) >> 31 != 0 {
                        let len = (rd(at) & 0x7fff_ffff) as usize;
                        assert!(at % 64 + 4 + len as u64 <= 64, "inline segment crosses a 64-byte boundary");
                        for i in 0..len {
                            // SAFETY: inside the send queue entry, identity-mapped.
                            header.push(unsafe { ((at + 4 + i as u64) as *const u8).read_volatile() });
                        }
                        at = (at + 4 + len as u64).next_multiple_of(16);
                    }
                    let (len, addr) = (rd(at), (rd(at + 8) as u64) << 32 | rd(at + 12) as u64);
                    assert_eq!(Some(rd(at + 4)), fw.lkey, "lkey");
                    assert_eq!(rd(at + 16), 1 << 31 | 4, "inline segment for the checksum");
                    assert_eq!(size as u64 * 16, at + 32 - wqe, "entry size covers exactly the segments");
                    // SAFETY: the driver's transmit buffer, identity-mapped.
                    let payload = unsafe { core::slice::from_raw_parts(addr as *const u8, len as usize) }.to_vec();
                    let mlx = MlxSend {
                        vl15: flags & 1 << 17 != 0,
                        slr: flags & 1 << 16 != 0,
                        sl: (flags >> 8 & 0xf) as u8,
                        rlid,
                        packet: Packet::decode(&header),
                        payload: payload.clone(),
                        size,
                    };
                    (payload, None, None, Some(mlx))
                }
                0x0a if qp.service == 3 => {
                    assert_eq!(segments, 5, "control + datagram + one data segment");
                    let (av, d) = (wqe + 16, wqe + 64);
                    let (slid, route) = (rd(av + 4), rd(av + 12));
                    let mut dgid = [0u8; 16];
                    for i in 0..4 {
                        dgid[4 * i..4 * i + 4].copy_from_slice(&rd(av + 16 + 4 * i as u64).to_be_bytes());
                    }
                    let ud = UdSend {
                        port: (rd(av) >> 24) as u8,
                        pd: rd(av) & 0xff_ffff,
                        dlid: slid as u16,
                        path_bits: (slid >> 16 & 0x7f) as u8,
                        grh: slid >> 23 & 1 != 0,
                        sl: (route >> 28) as u8,
                        sgid_index: (rd(av + 8) >> 16) as u8,
                        hop_limit: rd(av + 8) as u8,
                        traffic_class: (route >> 20) as u8,
                        flow_label: route & 0xf_ffff,
                        dgid,
                        dqpn: rd(av + 32),
                        qkey: rd(av + 36),
                    };
                    let len = rd(d);
                    assert_eq!(Some(rd(d + 4)), fw.lkey, "lkey");
                    let addr = (rd(d + 8) as u64) << 32 | rd(d + 12) as u64;
                    // SAFETY: the driver's transmit buffer, identity-mapped.
                    let frame = unsafe { core::slice::from_raw_parts(addr as *const u8, len as usize) }.to_vec();
                    (frame, None, Some(ud), None)
                }
                0x0a => {
                    assert_eq!(segments, 2, "control + one data segment");
                    let len = rd(wqe + 16);
                    assert_eq!(Some(rd(wqe + 20)), fw.lkey, "lkey");
                    let addr = (rd(wqe + 24) as u64) << 32 | rd(wqe + 28) as u64;
                    // SAFETY: the driver's transmit buffer, identity-mapped.
                    (unsafe { core::slice::from_raw_parts(addr as *const u8, len as usize) }.to_vec(), None, None, None)
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
                    (frame, Some((mss as u16, hdr)), None, None)
                }
                other => panic!("unexpected send opcode {other:#x}"),
            };
            frames.push(Sent { frame, ip_csum, l4_csum, lso, ud, mlx });
            let counter = qp.sq_next & 0xffff;
            fw.qps.get_mut(&qpn).unwrap().sq_next += 1;
            let mut fw = core::mem::take(&mut s.fw);
            self.complete(&mut fw, qpn, true, counter, 0, (0, 0));
            s.fw = fw;
        }
        self.flush_events(&mut s);
        frames
    }

    /// The state of queue pair `qpn`: 1 INIT, 2 RTR, 3 RTS, 6 error.
    pub fn qp_state(&self, qpn: u32) -> u8 {
        self.state.borrow().fw.qps[&qpn].state
    }

    /// Where a reliable connection stands.
    pub fn rc_ctx(&self, qpn: u32) -> RcCtx {
        self.state.borrow().fw.qps[&qpn].rc.clone()
    }

    /// Runs the send engine of reliable connection `qpn` against its peer
    /// (another queue pair of this adapter): executes the entries posted,
    /// as far as the peer allows, and returns how many it finished. A send
    /// to a peer with no receive ready waits there, or fails after the
    /// retries the connection allows.
    pub fn rc_run(&self, qpn: u32) -> usize {
        let mut s = self.state.borrow_mut();
        let mut done = 0;
        loop {
            let mut fw = core::mem::take(&mut s.fw);
            let progressed = self.rc_step(&mut fw, qpn);
            s.fw = fw;
            if !progressed {
                break;
            }
            done += 1;
        }
        self.flush_events(&mut s);
        done
    }

    fn rc_step(&self, fw: &mut Firmware, qpn: u32) -> bool {
        let qp = &fw.qps[&qpn];
        assert_eq!(qp.service, 0, "a reliable connection");
        assert!(qp.state >= 3, "sending from a queue pair not in RTS");
        let (n, stride) = (1u32 << qp.log_sq, 1usize << qp.log_sq_stride);
        let wqe = Self::translate(fw, qp.mtt, (qp.sq_next % n) as usize * stride);
        let ctrl = rd(wqe);
        if ctrl >> 31 != (qp.sq_next / n) & 1 {
            return false;
        }
        let counter = qp.sq_next & 0xffff;
        let advance = |fw: &mut Firmware| fw.qps.get_mut(&qpn).unwrap().sq_next += 1;
        if qp.state == 6 {
            advance(fw);
            self.complete_ud(fw, qpn, true, counter, 0, (0, 0), (0, 0, 0), Cqe::Err(5)); // flushed
            return true;
        }
        let (opcode, size) = (ctrl & 0x1f, rd(wqe + 4) & 0x3f);
        assert_eq!(rd(wqe + 8) & 0xe, 0xe, "completion and solicited");
        let mut at = wqe + 16;
        let remote = (opcode != 0x0a).then(|| {
            let r = ((rd(at) as u64) << 32 | rd(at + 4) as u64, rd(at + 8));
            at += 16;
            r
        });
        let (len, lkey) = (rd(at) as usize, rd(at + 4));
        let local = (rd(at + 8) as u64) << 32 | rd(at + 12) as u64;
        assert_eq!(Some(lkey), fw.lkey, "lkey");
        assert_eq!(size as u64 * 16, at + 16 - wqe, "the entry size covers exactly its segments");

        let me = &qp.rc;
        let peer_qpn = me.remote_qpn;
        let peer = fw.qps.get(&peer_qpn).filter(|p| p.service == 0 && p.state >= 2 && p.rc.remote_qpn == qpn);
        let (rnr_retry, mtu) = (me.rnr_retry, me.mtu_bytes as usize);
        let packets = len.div_ceil(mtu).max(1) as u32;
        let step: Result<Option<u32>, u8> = match peer {
            None => Err(0x15), // nobody answers: retries exceeded
            Some(peer) if peer.state == 6 => Err(0x15),
            Some(peer) => {
                assert_eq!(me.send_psn & 0xff_ffff, peer.rc.recv_psn & 0xff_ffff, "packet sequence numbers agree");
                match opcode {
                    0x0a => {
                        let posted = rd(peer.db) & 0xffff;
                        if peer.rq_next & 0xffff == posted {
                            if rnr_retry == 7 { Ok(None) } else { Err(0x16) }
                        } else {
                            let (rn, rstride) = (1u32 << peer.log_rq, 1usize << peer.log_rq_stride);
                            let sq_len = (1usize << peer.log_sq) << peer.log_sq_stride;
                            let rwqe = Self::translate(fw, peer.mtt, sq_len + (peer.rq_next % rn) as usize * rstride);
                            let room = rd(rwqe) as usize;
                            let raddr = (rd(rwqe + 8) as u64) << 32 | rd(rwqe + 12) as u64;
                            let rcounter = peer.rq_next & 0xffff;
                            if len > room {
                                // The message does not fit: the receiver fails, and so does the sender.
                                let p = fw.qps.get_mut(&peer_qpn).unwrap();
                                (p.rq_next, p.state) = (p.rq_next + 1, 6);
                                self.complete_ud(fw, peer_qpn, false, rcounter, 0, (0, 0), (0, 0, 0), Cqe::Err(1));
                                Err(0x14)
                            } else {
                                // SAFETY: both are driver buffers, identity-mapped.
                                unsafe { core::ptr::copy_nonoverlapping(local as *const u8, raddr as *mut u8, len) };
                                fw.qps.get_mut(&peer_qpn).unwrap().rq_next += 1;
                                self.complete_ud(
                                    fw,
                                    peer_qpn,
                                    false,
                                    rcounter,
                                    len as u32,
                                    (0, 0),
                                    (0, 0, 0),
                                    Cqe::Ok(1),
                                );
                                Ok(Some(0))
                            }
                        }
                    }
                    0x08 | 0x10 => {
                        let (raddr, rkey) = remote.unwrap();
                        let (need, granted) = if opcode == 0x08 { (1 << 13, 2) } else { (1 << 12, 4) };
                        let region = fw.mrs.values().find(|m| m.key == rkey.rotate_right(8));
                        let fits = |m: &Mr| {
                            m.access & need != 0
                                && raddr >= m.start
                                && raddr.checked_add(len as u64).is_some_and(|end| end <= m.start.saturating_add(m.len))
                        };
                        if !region.is_some_and(fits) || peer.rc.access & granted == 0 {
                            Err(0x13) // remote access error
                        } else {
                            let (from, to) = if opcode == 0x08 { (local, raddr) } else { (raddr, local) };
                            // SAFETY: the driver's buffers, identity-mapped, checked against the region.
                            unsafe { core::ptr::copy_nonoverlapping(from as *const u8, to as *mut u8, len) };
                            Ok(Some(if opcode == 0x10 { len as u32 } else { 0 }))
                        }
                    }
                    other => panic!("unexpected reliable connection opcode {other:#x}"),
                }
            }
        };
        match step {
            Ok(None) => return false, // waiting for the peer
            Ok(Some(bytes)) => {
                fw.qps.get_mut(&qpn).unwrap().rc.send_psn += packets;
                fw.qps.get_mut(&peer_qpn).unwrap().rc.recv_psn += packets;
                advance(fw);
                self.complete_ud(fw, qpn, true, counter, bytes, (0, 0), (0, 0, 0), Cqe::Ok(opcode));
            }
            Err(syndrome) => {
                advance(fw);
                fw.qps.get_mut(&qpn).unwrap().state = 6;
                self.complete_ud(fw, qpn, true, counter, 0, (0, 0), (0, 0, 0), Cqe::Err(syndrome));
            }
        }
        true
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

    /// The subnet management agent: answers the Get or Set in `m` (the first
    /// 256 bytes of the input mailbox), and reports state changes through
    /// `events`.
    fn sma(&self, ib: &mut IbState, port: usize, caps: u32, m: &[u32], events: &mut Vec<(u8, bool)>) -> [u32; 64] {
        let (class, method) = ((m[0] >> 16) as u8, m[0] as u8);
        assert_eq!(m[0] >> 24, 1, "base version");
        assert!(matches!(class, 0x01 | 0x81 | 0x04), "management class {class:#x}");
        assert!(matches!(method, 1 | 2 | 7), "Get, Set or TrapRepress");
        let (attr, modifier, set) = ((m[4] >> 16) as u16, m[5], method == 2);
        let mut r = [0u32; 64];
        r.copy_from_slice(&m[..64]);
        r[0] = r[0] & !0xff | 0x81; // GetResp
        r[16..32].fill(0);
        let mut status = 0;
        let (req, data) = (&m[16..32], &mut r[16..32]);
        match attr {
            _ if class == 0x04 => {} // performance management: an empty answer
            0x0011 => {
                data[0] = 1 << 24 | 1 << 16 | 1 << 8 | 2; // versions, channel adapter, two ports
                data[1] = (NODE_GUID >> 32) as u32;
                data[2] = NODE_GUID as u32;
                data[3] = (NODE_GUID >> 32) as u32;
                data[4] = NODE_GUID as u32;
                let guid = ib.guids[0];
                data[5] = (guid >> 32) as u32;
                data[6] = guid as u32;
                data[9] = (port as u32 + 1) << 24;
            }
            0x0014 if modifier == 0 => {
                for (i, g) in ib.guids.iter().enumerate() {
                    data[2 * i] = (g >> 32) as u32;
                    data[2 * i + 1] = *g as u32;
                }
            }
            0x0015 => {
                assert_eq!(modifier, port as u32 + 1, "PortInfo of this port");
                if set {
                    (ib.lid, ib.sm_lid) = ((req[4] >> 16) as u16, req[4] as u16);
                    ib.lmc = (req[8] >> 8 & 7) as u8;
                    ib.sm_sl = (req[9] >> 24 & 0xf) as u8;
                    let before = ib.state;
                    match (ib.state, req[8] >> 24 & 0xf) {
                        (_, 0) => {}
                        (_, 1) => ib.state = 1,
                        (_, 2) => ib.state = 2,
                        (2 | 3, 3) => ib.state = 3,
                        (3 | 4, 4) => ib.state = 4,
                        _ => status = 0x001c, // not a legal transition
                    }
                    if ib.state != before {
                        events.push((port as u8 + 1, ib.state == 4));
                    }
                }
                data[2] = (ib.gid_prefix >> 32) as u32;
                data[3] = ib.gid_prefix as u32;
                data[4] = (ib.lid as u32) << 16 | ib.sm_lid as u32;
                data[5] = caps;
                data[7] = (port as u32 + 1) << 24;
                let physical = if ib.state >= 2 { 5 } else { 2 };
                data[8] = (1 << 4 | ib.state as u32) << 24 | physical << 20 | (ib.lmc as u32) << 8;
                let neighbor = if ib.state >= 3 { 5 } else { 0 };
                data[9] = (neighbor << 4 | ib.sm_sl as u32) << 24 | 4 << 20;
                data[10] = 5 << 16; // the port's MTU capability: 4096
            }
            0x0016 if modifier == 0 => {
                for (i, k) in ib.pkeys.iter().enumerate() {
                    data[i / 2] |= (*k as u32) << if i % 2 == 0 { 16 } else { 0 };
                }
            }
            0x0017 => {
                if set {
                    ib.sl2vl = [req[0].to_be_bytes(), req[1].to_be_bytes()].concat().try_into().unwrap();
                }
                data[0] = u32::from_be_bytes(ib.sl2vl[..4].try_into().unwrap());
                data[1] = u32::from_be_bytes(ib.sl2vl[4..].try_into().unwrap());
            }
            0x0014 | 0x0016 => status = 0x001c,
            _ => status = 0x000c,
        }
        r[1] = status << 16 | (r[1] & 0xffff);
        r
    }

    /// Queue pair 0 or 1 (`gsi`) of port `port`.
    pub fn special_qpn(&self, port: u8, gsi: bool) -> u32 {
        self.state.borrow().fw.special_qp.expect("configured") + if gsi { 2 } else { 0 } + port as u32 - 1
    }

    /// Runs the receive engine for a management datagram arriving at queue
    /// pair 0 or 1 of `port`; false if it was dropped.
    pub fn deliver_mad(
        &self,
        port: u8,
        gsi: bool,
        from: UdFrom,
        grh: Option<[u8; 40]>,
        mad: &[u8; 256],
        pkey_index: u8,
    ) -> bool {
        let qpn = self.special_qpn(port, gsi);
        let mut s = self.state.borrow_mut();
        if !s.fw.port_up[port as usize - 1] {
            return false;
        }
        let mut fw = core::mem::take(&mut s.fw);
        let delivered = self.receive_ud(&mut fw, port, qpn, 0, from, grh, mad, pkey_index, true);
        s.fw = fw;
        self.flush_events(&mut s);
        delivered
    }

    /// What the subnet manager and the link made of InfiniBand port `port`.
    pub fn ib_state(&self, port: u8) -> IbState {
        self.state.borrow().ib[port as usize - 1].clone().expect("an InfiniBand port")
    }

    /// The subnet manager configures InfiniBand port `port`: assigns `lid`
    /// and activates it, which the adapter reports as a port event.
    pub fn sm_configure(&self, port: u8, lid: u16) {
        let mut s = self.state.borrow_mut();
        let p = port as usize - 1;
        s.link[p] = true;
        let ib = s.ib[p].as_mut().expect("an InfiniBand port");
        (ib.lid, ib.sm_lid, ib.state) = (lid, SM_LID, 4);
        let eqn = s.fw.async_eqn.expect("event queue mapped");
        self.post_event(&mut s, eqn, 0x09, 4, 12, (port as u32) << 28);
    }

    /// Runs the receive engine for one datagram arriving at `port` for
    /// queue pair `dqpn`: dropped (false) unless the port is active, the
    /// queue pair exists with key `qkey` and has a receive entry posted.
    /// The buffer gets the 40-byte header slot then `payload`; `grh` (if
    /// any) fills the slot.
    pub fn deliver_ud(
        &self,
        port: u8,
        dqpn: u32,
        qkey: u32,
        from: UdFrom,
        grh: Option<[u8; 40]>,
        payload: &[u8],
    ) -> bool {
        let mut s = self.state.borrow_mut();
        let active = s.ib[port as usize - 1].as_ref().is_some_and(|ib| ib.state == 4);
        let mut fw = core::mem::take(&mut s.fw);
        let delivered = active && self.receive_ud(&mut fw, port, dqpn, qkey, from, grh, payload, 0, false);
        s.fw = fw;
        self.flush_events(&mut s);
        delivered
    }

    /// Delivers a datagram sent to multicast group `mgid` to every member
    /// queue pair on `port`; returns how many took it.
    pub fn deliver_multicast(
        &self,
        port: u8,
        mgid: &[u8; 16],
        qkey: u32,
        from: UdFrom,
        grh: [u8; 40],
        payload: &[u8],
    ) -> usize {
        let mut s = self.state.borrow_mut();
        let active = s.ib[port as usize - 1].as_ref().is_some_and(|ib| ib.state == 4);
        let mut fw = core::mem::take(&mut s.fw);
        let members: Vec<u32> = match fw.mcg.get(&mgid_hash(mgid)) {
            Some(e) if active && e[4..8].iter().flat_map(|d| d.to_be_bytes()).eq(mgid.iter().copied()) => {
                e[8..8 + (e[1] & 0xff_ffff) as usize].to_vec()
            }
            _ => Vec::new(),
        };
        let taken = members
            .into_iter()
            .filter(|&qpn| self.receive_ud(&mut fw, port, qpn, qkey, from, Some(grh), payload, 0, false))
            .count();
        s.fw = fw;
        self.flush_events(&mut s);
        taken
    }

    #[allow(clippy::too_many_arguments)]
    fn receive_ud(
        &self,
        fw: &mut Firmware,
        port: u8,
        qpn: u32,
        qkey: u32,
        from: UdFrom,
        grh: Option<[u8; 40]>,
        payload: &[u8],
        pkey_index: u8,
        special: bool,
    ) -> bool {
        let Some(qp) = fw.qps.get(&qpn).filter(|q| if special { q.special } else { q.service == 3 && q.qkey == qkey })
        else {
            return false;
        };
        assert!(qp.state >= if special { 2 } else { 3 }, "receiving into a QP not ready");
        if qp.sched_queue >> 6 & 1 != port as u32 - 1 {
            return false; // a member of the group, but on the other port
        }
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
        let total = 40 + payload.len();
        if total > room as usize {
            return false;
        }
        // SAFETY: the driver's receive buffer, identity-mapped.
        let dst = unsafe { core::slice::from_raw_parts_mut(addr as *mut u8, total) };
        dst[..40].copy_from_slice(&grh.unwrap_or([0; 40]));
        dst[40..].copy_from_slice(payload);
        let counter = qp.rq_next & 0xffff;
        fw.qps.get_mut(&qpn).unwrap().rq_next += 1;
        let source = (grh.is_some() as u32) << 31 | (from.path_bits as u32 & 0x7f) << 24 | from.qpn & 0xff_ffff;
        let route = (from.sl as u32) << 28 | from.lid as u32;
        let sender = (source, route, pkey_index as u32);
        self.complete_ud(fw, qpn, false, counter, total as u32, (0, 0), sender, Cqe::Ok(1));
        true
    }

    /// Lets `ns` nanoseconds of the adapter's clock go by.
    pub fn advance(&self, ns: u64) {
        self.state.borrow_mut().now += ns;
    }

    /// Keeps the flash semaphore taken, as during a firmware update.
    pub fn hold_semaphore(&self) {
        self.state.borrow_mut().semaphore_stuck = true;
        self.set_bar(RESET_SEMAPHORE, 1);
    }

    pub fn qps(&self) -> Vec<u32> {
        self.state.borrow().fw.qps.keys().copied().collect()
    }

    /// A datagram queue pair's partition key index, queue key and the
    /// optional-parameter mask of its RST2INIT.
    pub fn ud_qp(&self, qpn: u32) -> (u32, u32, u32) {
        let s = self.state.borrow();
        let qp = &s.fw.qps[&qpn];
        assert_eq!(qp.service, 3);
        (qp.pkey_index, qp.qkey, qp.init_optpar)
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
