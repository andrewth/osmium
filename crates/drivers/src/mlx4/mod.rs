//! Mellanox ConnectX-2 and ConnectX-3 (mlx4) Ethernet.
//!
//! [`Mlx4`] brings the adapter up from PCI BAR 0 (configuration and the
//! command register) and BAR 2 (the UAR doorbell pages): reset, firmware
//! start in host memory (MAP_FA, RUN_FW), context memory (ICM) carved out
//! and mapped, INIT_HCA, one memory region covering all physical memory, and
//! one event queue for port events. [`Mlx4::open_eth`] then turns a port
//! into an [`EthPort`], a [`NetDevice`](osmium_hal::net::NetDevice) with one
//! completion queue and one raw Ethernet queue pair.
//!
//! The sequence follows the PRM as iPXE's `hermon` driver uses it, with
//! Linux's `mlx4_core` for the reset and the Ethernet queue pair settings.
//! By default everything is polled and the driver needs no interrupt line.
//! [`Mlx4::enable_msix`] switches to MSI-X: vector 0 for the asynchronous
//! event queue (link changes), vector 1 for a second event queue that
//! carries completion events, which the interrupt handler
//! ([`Mlx4::handle_interrupt`]) turns into a set of ports with work to do.
//! Polling keeps working alongside, and is the fallback when the function
//! has no MSI-X capability or fewer than two vectors. Each port
//! receives promiscuously (every unicast and multicast frame on the wire)
//! because the steering tables are left empty. VLAN tags stay in the frame.
//!
//! The firmware area and each ICM region are single physically contiguous
//! allocations, several megabytes for the firmware, so the [`DmaAllocator`]
//! must be able to hand those out.
//!
//! If the device stops answering commands, or refuses to give a queue back
//! during teardown, the driver leaks the memory involved rather than free
//! memory the device may still write.
//!
//! An [`EthPort`] also offers IPv4/TCP/UDP checksum offload in both
//! directions and TCP segmentation offload (large send) through its
//! [`transmit_offload`](EthPort::transmit_offload) and
//! [`receive_checked`](EthPort::receive_checked) methods. The shared
//! [`NetDevice`](osmium_hal::net::NetDevice) trait has no way to express
//! offloads, so these are inherent methods; [`EthPort::offloads`] reports
//! what the port can do. The offload and MSI-X paths follow the PRM and
//! Linux's `mlx4_en` but have only run against the simulated HCA.
//!
//! Not yet supported: receive-side scaling, one completion vector per CPU,
//! MAC/VLAN steering, VLAN tag offload, tunnel offloads, and InfiniBand.

mod cmd;
mod eth;

#[cfg(test)]
mod fake;

use core::cell::Cell;
use core::mem::ManuallyDrop;

use osmium_hal::dma::{DmaAllocator, DmaBuffer, OwnedDma};
use osmium_hal::mmio::IoMem;
use osmium_hal::pci::{ConfigAccess, Function, cap};
use osmium_hal::pci::{MsiError, MsiMessage, MsixTable};
use osmium_hal::timer::Clock;

use cmd::{Ctx, Hcr, Input, MTTS_PER_WRITE, op};
pub use eth::{EthPort, Offloads, RxChecksum, TSO_MAX_HEADER, Tso, TxError, TxOffload};

/// Mellanox's PCI vendor ID.
pub const VENDOR_ID: u16 = 0x15b3;

/// PCI device IDs of the physical functions this driver handles:
/// ConnectX (MT25408 family), ConnectX-2 and ConnectX-3 (Pro).
pub const DEVICE_IDS: &[u16] = &[
    0x6340, 0x634a, 0x6732, 0x673c, 0x6368, 0x6750, 0x6372, 0x675a, 0x6764, 0x6746, 0x676e,
    0x6778, // ConnectX, -2
    0x1003, 0x1005, 0x1006, 0x1007, 0x1008, 0x1009, 0x100a, // ConnectX-3, -3 Pro
];

/// Returns true if this driver handles PCI function `vendor:device`.
pub fn supports(vendor: u16, device: u16) -> bool {
    vendor == VENDOR_ID && DEVICE_IDS.contains(&device)
}

/// BAR holding the configuration registers and the HCR.
pub const CONFIG_BAR: u8 = 0;
/// Bytes of BAR 0 the driver uses.
pub const CONFIG_LEN: usize = 0x10_0000;
/// BAR holding the UAR (doorbell) pages.
pub const UAR_BAR: u8 = 2;
/// Bytes of BAR 2 the driver uses: the event queue doorbell pages and
/// the send doorbell page (128).
pub const UAR_LEN: usize = (UAR_PAGE as usize + 1) * PAGE;

const PAGE: usize = 4096;

// Reset, in BAR 0.
const RESET: usize = 0xf0010;
const RESET_SEMAPHORE: usize = 0xf03fc;
const RESET_WAIT_NS: u64 = 1_000_000_000;
const RESET_TIMEOUT_NS: u64 = 2_000_000_000;
const SEMAPHORE_TIMEOUT_NS: u64 = 10_000_000_000;
const SENSE_TIMEOUT_NS: u64 = 500_000_000;

/// UAR page for send doorbells; pages 0–127 are for event queues only.
const UAR_PAGE: u32 = 128;

/// Ports per adapter, at most.
pub const MAX_PORTS: u8 = 2;

// Resources set aside beyond the firmware's reserved ones. These are
// policy: one queue pair, completion queue and MTT range per port.
const NUM_SPECIAL_QPS: u32 = 8;
const MAX_QPS: u32 = 8;
const MAX_CQS: u32 = 8;
const MAX_EQS: u32 = 8;
const LOG_NUM_MCGS: u32 = 7;
const MCG_ENTRY_LEN: u64 = 64;
/// MTT entries per port: one page of completion queue, two of work queues.
const PORT_MTTS: u32 = 3;
/// The asynchronous and completion event queues' MTT entries come first,
/// then each port's.
const MAX_MTTS: u32 = EQ_MTTS + PORT_MTTS * MAX_PORTS as u32;
const EQ_MTTS: u32 = 2;

const NUM_EQES: u32 = 8;
const EQE_LEN: usize = 32;
const EVENT_PORT_CHANGE: u32 = 0x09;
const PORT_CHANGE_ACTIVE: u32 = 0x04;
const EVENT_COMPLETION: u32 = 0x00;
/// Event queue consumer index doorbell bit asking for the next event to
/// raise an interrupt.
const EQ_ARM: u32 = 1 << 31;
/// Event queue states in the context: armed (will interrupt) and fired.
const EQ_STATE_ARMED: u32 = 0x9;
const EQ_STATE_FIRED: u32 = 0xa;

/// MSI-X vector (table entry) of the asynchronous event queue.
pub const VECTOR_ASYNC: u16 = 0;
/// MSI-X vector of the completion event queue.
pub const VECTOR_COMPLETION: u16 = 1;

/// The protection domain of every queue and memory region.
const PD: u32 = 0x12_3456;
const MKEY_PREFIX: u32 = 0x7700_0000;

/// Why bringing up the adapter or a port failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mlx4Error {
    /// A BAR window is smaller than [`CONFIG_LEN`] or [`UAR_LEN`].
    BadRegisters,
    /// The device did not return from reset, or reported nonsense.
    BadDevice,
    /// The flash semaphore stayed taken (a firmware update in progress?).
    Busy,
    /// A command did not complete; the device is abandoned.
    Timeout,
    /// The firmware rejected a command.
    Command {
        /// The command's opcode.
        opcode: u16,
        /// The PRM status code.
        status: u8,
    },
    /// Not enough DMA memory.
    NoMemory,
    /// No such port, or it is already open.
    BadPort,
    /// The port is in InfiniBand mode.
    NotEthernet,
    /// The DMA allocator returned memory that is not 4 KiB aligned.
    MisalignedDma,
    /// MSI-X could not be set up: the function lacks the capability or has
    /// fewer than two vectors, the table does not fit its BAR, or MSI-X is
    /// already enabled.
    Msix(MsiError),
}

/// Limits from QUERY_DEV_CAP.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Caps {
    reserved_qps: u32,
    reserved_srqs: u32,
    reserved_cqs: u32,
    reserved_eqs: u32,
    reserved_mtts: u32,
    reserved_mrws: u32,
    reserved_uars: u32,
    qpc_entry: u64,
    altc_entry: u64,
    auxc_entry: u64,
    srqc_entry: u64,
    cqc_entry: u64,
    eqc_entry: u64,
    cmpt_entry: u64,
    dmpt_entry: u64,
    mtt_entry: u64,
    num_ports: u8,
    dpdp: bool,
    /// Largest LSO frame, or 0 if the device cannot segment.
    max_gso: u32,
}

impl Caps {
    fn parse(c: &Ctx) -> Option<Self> {
        let caps = Self {
            reserved_qps: 1 << c.get(4, 8, 4),
            reserved_srqs: 1 << c.get(5, 28, 4),
            reserved_cqs: 1 << c.get(6, 8, 4),
            // Older firmware reports only the log2.
            reserved_eqs: match c.get(6, 24, 8) {
                0 => 1 << c.get(7, 8, 4),
                n => n,
            },
            reserved_mtts: 1 << c.get(8, 28, 4),
            reserved_mrws: 1 << c.get(8, 8, 4),
            reserved_uars: c.get(18, 28, 4),
            qpc_entry: c.get(32, 0, 16) as u64,
            altc_entry: c.get(33, 0, 16) as u64,
            auxc_entry: c.get(33, 16, 16) as u64,
            cqc_entry: c.get(34, 0, 16) as u64,
            eqc_entry: c.get(34, 16, 16) as u64,
            cmpt_entry: c.get(35, 0, 16) as u64,
            srqc_entry: c.get(35, 16, 16) as u64,
            dmpt_entry: c.get(36, 0, 16) as u64,
            mtt_entry: c.get(36, 16, 16) as u64,
            num_ports: (c.get(13, 0, 4) as u8).min(MAX_PORTS),
            dpdp: c.get(17, 12, 1) != 0,
            max_gso: if c.get(11, 21, 1) != 0 { 1 << c.get(11, 16, 5) } else { 0 },
        };
        let sizes = [
            caps.qpc_entry,
            caps.altc_entry,
            caps.auxc_entry,
            caps.srqc_entry,
            caps.cqc_entry,
            caps.eqc_entry,
            caps.cmpt_entry,
            caps.dmpt_entry,
            caps.mtt_entry,
        ];
        (caps.num_ports > 0 && sizes.iter().all(|s| s.is_power_of_two())).then_some(caps)
    }

    /// The event queue number: past the reserved ones, and in a UAR page
    /// the firmware does not reserve.
    fn eqn(&self) -> u32 {
        (4 * self.reserved_uars).max(self.reserved_eqs)
    }

    /// The completion event queue, next to the asynchronous one.
    fn comp_eqn(&self) -> u32 {
        self.eqn() + 1
    }
}

/// `ceil(log2(n))` for `n >= 1`.
fn log2_ceil(n: u32) -> u32 {
    32 - (n - 1).leading_zeros()
}

/// One stretch of ICM: its address in the device's ICM space and length.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct IcmRegion {
    va: u64,
    len: usize,
}

/// Where each context table lives in ICM, and the INIT_HCA parameters
/// describing it. The four cMPT tables come first, each in its own sparse
/// 2^24-entry window; the other tables follow packed, each aligned to its
/// own (power-of-two) size.
struct IcmPlan {
    regions: [IcmRegion; 5],
    /// Total ICM address space, for SET_ICM_SIZE.
    size: u64,
    init_hca: Ctx,
}

fn plan_icm(caps: &Caps) -> IcmPlan {
    let log_qps = log2_ceil(caps.reserved_qps + 2 * NUM_SPECIAL_QPS - 1 + MAX_QPS);
    let log_srqs = log2_ceil(caps.reserved_srqs);
    let log_cqs = log2_ceil(caps.reserved_cqs + MAX_CQS);
    let log_eqs = log2_ceil((caps.reserved_eqs + MAX_EQS).max(caps.comp_eqn() + 1));
    let log_mtts = log2_ceil(caps.reserved_mtts + MAX_MTTS);
    let log_mpts = log2_ceil(caps.reserved_mrws + 1);
    let page_up = |n: u64| n.next_multiple_of(PAGE as u64) as usize;

    let mut regions = [IcmRegion::default(); 5];
    let cmpt_window = caps.cmpt_entry << 24;
    for (i, log) in [log_qps, log_srqs, log_cqs, log_eqs].into_iter().enumerate() {
        regions[i] = IcmRegion { va: i as u64 * cmpt_window, len: page_up(caps.cmpt_entry << log) };
    }

    let mut c = Ctx::new();
    let start = 4 * cmpt_window;
    let mut at = start;
    let mut table = |entry: u64, log: u32| {
        let len = entry << log;
        let base = at.next_multiple_of(len);
        at = base + len;
        base
    };
    // Base addresses whose low bits share a dword with the table's log2 size.
    c.set_addr(12, table(caps.qpc_entry, log_qps)).set(13, 0, 5, log_qps);
    c.set_addr(24, table(caps.altc_entry, log_qps));
    c.set_addr(28, table(caps.auxc_entry, log_qps));
    c.set_addr(18, table(caps.srqc_entry, log_srqs)).set(19, 0, 5, log_srqs);
    c.set_addr(20, table(caps.cqc_entry, log_cqs)).set(21, 0, 5, log_cqs);
    c.set_addr(32, table(caps.eqc_entry, log_eqs)).set(33, 0, 5, log_eqs);
    c.set_addr(64, table(caps.mtt_entry, log_mtts));
    c.set_addr(60, table(caps.dmpt_entry, log_mpts)).set(62, 0, 6, log_mpts);
    c.set_addr(48, table(MCG_ENTRY_LEN, LOG_NUM_MCGS));
    c.set(52, 0, 5, MCG_ENTRY_LEN.trailing_zeros()).set(53, 0, 5, LOG_NUM_MCGS).set(54, 0, 5, LOG_NUM_MCGS);
    regions[4] = IcmRegion { va: start, len: page_up(at - start) };

    c.set(0, 24, 8, 2); // version, "must be 2"
    c.set(5, 0, 1, 1); // udp
    c.set(74, 8, 4, 8); // log2 of the number of UARs: 256
    IcmPlan { regions, size: start + regions[4].len as u64, init_hca: c }
}

/// Splits `[pa, pa + len)` at ICM address `va` into naturally aligned
/// power-of-two blocks, as MAP_FA, MAP_ICM and MAP_ICM_AUX take them.
fn map_blocks(
    mut va: u64,
    mut pa: u64,
    len: usize,
    mut f: impl FnMut(u64, u64, u32) -> Result<(), Mlx4Error>,
) -> Result<(), Mlx4Error> {
    // The device maps whole pages; a block below 4 KiB has no encoding.
    if !(va | pa).is_multiple_of(PAGE as u64) {
        return Err(Mlx4Error::MisalignedDma);
    }
    let mut left = len.next_multiple_of(PAGE) as u64;
    while left > 0 {
        let align = (va | pa).trailing_zeros().min(63);
        let log = align.min(63 - left.leading_zeros());
        f(va, pa, log)?;
        va += 1 << log;
        pa += 1 << log;
        left -= 1 << log;
    }
    Ok(())
}

/// Memory the device reads and writes until teardown.
struct Memory<'d, D: DmaAllocator + ?Sized> {
    firmware: Option<OwnedDma<'d, D>>,
    icm_aux: Option<OwnedDma<'d, D>>,
    icm: [Option<OwnedDma<'d, D>>; 5],
    eq: Option<OwnedDma<'d, D>>,
    comp_eq: Option<OwnedDma<'d, D>>,
}

/// How far bring-up got, so teardown undoes exactly that.
#[derive(Default)]
struct Stage {
    fa_mapped: bool,
    aux_mapped: bool,
    /// Bytes of each ICM region mapped so far.
    icm_mapped: [usize; 5],
    hca_up: bool,
    eq_hw: bool,
    eq_mapped: bool,
    comp_eq_hw: bool,
}

/// A ConnectX adapter with its firmware running. Dropping it closes the HCA
/// and returns the firmware's memory; open ports borrow it, so they close
/// first.
pub struct Mlx4<'d, D: DmaAllocator + ?Sized> {
    hcr: Hcr<'d, D>,
    uar: IoMem,
    dma: &'d D,
    clock: &'d dyn Clock,
    caps: Caps,
    fw_version: (u16, u16, u16),
    mem: ManuallyDrop<Memory<'d, D>>,
    icm_regions: [IcmRegion; 5],
    stage: Stage,
    lkey: u32,
    qpn_base: u32,
    eq_ci: Cell<u32>,
    comp_eq_ci: Cell<u32>,
    /// Set by [`Mlx4::enable_msix`]: the table, to mask on drop.
    msix: Option<MsixTable>,
    /// The completion event queue, once MSI-X is enabled.
    comp_eqn: Option<u32>,
    /// Per completion queue: events seen so far, which the arm doorbell
    /// carries so the device can tell a fresh request from a stale one.
    arm_sn: [Cell<u8>; MAX_PORTS as usize],
    /// Bit `n` set: port `n + 1` is open / its link is up.
    open: Cell<u8>,
    link: Cell<u8>,
}

impl<'d, D: DmaAllocator + ?Sized> Mlx4<'d, D> {
    /// Resets the adapter at `func` and starts it: `config` and `uar` map
    /// BARs [`CONFIG_BAR`] and [`UAR_BAR`] (at least [`CONFIG_LEN`] and
    /// [`UAR_LEN`] bytes). Memory comes from `dma`, timeouts from `clock`.
    ///
    /// The reset takes a little over a second.
    pub fn new<C: ConfigAccess + ?Sized>(
        func: &Function<'_, C>,
        config: IoMem,
        uar: IoMem,
        dma: &'d D,
        clock: &'d dyn Clock,
    ) -> Result<Self, Mlx4Error> {
        if config.len() < CONFIG_LEN || uar.len() < UAR_LEN {
            return Err(Mlx4Error::BadRegisters);
        }
        func.enable_memory_and_dma();
        reset(func, &config, clock)?;
        func.enable_memory_and_dma();

        let mut hca = Self {
            hcr: Hcr::new(config, dma, clock)?,
            uar,
            dma,
            clock,
            caps: Caps::default(),
            fw_version: (0, 0, 0),
            mem: ManuallyDrop::new(Memory {
                firmware: None,
                icm_aux: None,
                icm: Default::default(),
                eq: None,
                comp_eq: None,
            }),
            icm_regions: Default::default(),
            stage: Stage::default(),
            lkey: 0,
            qpn_base: 0,
            eq_ci: Cell::new(0),
            comp_eq_ci: Cell::new(0),
            msix: None,
            comp_eqn: None,
            arm_sn: Default::default(),
            open: Cell::new(0),
            link: Cell::new(0),
        };
        hca.start_firmware()?;
        hca.caps = hca.query_caps()?;
        hca.map_icm()?;
        hca.setup_mpt()?;
        hca.create_eq()?;

        // The special QP block must be aligned to its size.
        let special = hca.caps.reserved_qps.next_multiple_of(NUM_SPECIAL_QPS);
        hca.hcr.exec(op::CONF_SPECIAL_QP, 0, special, Input::None)?;
        hca.qpn_base = special + NUM_SPECIAL_QPS;
        Ok(hca)
    }

    /// Number of ports.
    pub fn num_ports(&self) -> u8 {
        self.caps.num_ports
    }

    /// Firmware version (major, minor, subminor).
    pub fn firmware_version(&self) -> (u16, u16, u16) {
        self.fw_version
    }

    fn start_firmware(&mut self) -> Result<(), Mlx4Error> {
        let mut fw = Ctx::new();
        self.hcr.exec_out(op::QUERY_FW, 0, 0, Input::None, &mut fw, 256)?;
        self.fw_version = (fw.get(0, 0, 16) as u16, fw.get(1, 16, 16) as u16, fw.get(1, 0, 16) as u16);
        let pages = fw.get(0, 16, 16) as usize;
        if pages == 0 {
            return Err(Mlx4Error::BadDevice);
        }
        let area = OwnedDma::new(self.dma, pages * PAGE).ok_or(Mlx4Error::NoMemory)?;
        let pa = area.device_addr().as_u64();
        self.mem.firmware = Some(area);
        self.stage.fa_mapped = true;
        self.map(op::MAP_FA, 0, pa, pages * PAGE, &mut 0)?;
        self.hcr.exec(op::RUN_FW, 0, 0, Input::None)?;
        Ok(())
    }

    /// Issues `opcode` (a MAP_* command) for each block of the mapping,
    /// counting the bytes mapped in `done`.
    fn map(&self, opcode: u16, va: u64, pa: u64, len: usize, done: &mut usize) -> Result<(), Mlx4Error> {
        map_blocks(va, pa, len, |va, pa, log| {
            let mut m = Ctx::new();
            m.set(0, 0, 32, (va >> 32) as u32).set(1, 0, 32, va as u32 & !0xfff);
            m.set_addr(2, pa & !0xfff).set(3, 0, 6, log - 12);
            self.hcr.exec(opcode, 0, 1, Input::Mailbox(&m, 16))?;
            *done += 1 << log;
            Ok(())
        })
    }

    fn query_caps(&self) -> Result<Caps, Mlx4Error> {
        let mut c = Ctx::new();
        self.hcr.exec_out(op::QUERY_DEV_CAP, 0, 0, Input::None, &mut c, 256)?;
        let caps = Caps::parse(&c).ok_or(Mlx4Error::BadDevice)?;
        // The event queues' doorbells must be below the send doorbell page.
        if caps.comp_eqn() / 4 >= UAR_PAGE {
            return Err(Mlx4Error::BadDevice);
        }
        Ok(caps)
    }

    fn map_icm(&mut self) -> Result<(), Mlx4Error> {
        let plan = plan_icm(&self.caps);
        let aux_pages = self.hcr.exec(op::SET_ICM_SIZE, 0, 0, Input::Imm(plan.size))? as u32;
        let alloc = |len: usize| OwnedDma::new(self.dma, len.max(PAGE)).ok_or(Mlx4Error::NoMemory);

        if aux_pages > 0 {
            let aux = alloc(aux_pages as usize * PAGE)?;
            let pa = aux.device_addr().as_u64();
            self.mem.icm_aux = Some(aux);
            self.stage.aux_mapped = true;
            self.map(op::MAP_ICM_AUX, 0, pa, aux_pages as usize * PAGE, &mut 0)?;
        }
        self.icm_regions = plan.regions;
        for (i, r) in plan.regions.iter().enumerate() {
            let buf = alloc(r.len)?;
            let pa = buf.device_addr().as_u64();
            self.mem.icm[i] = Some(buf);
            let mut done = 0;
            let mapped = self.map(op::MAP_ICM, r.va, pa, r.len, &mut done);
            self.stage.icm_mapped[i] = done;
            mapped?;
        }
        self.hcr.exec(op::INIT_HCA, 0, 0, Input::Mailbox(&plan.init_hca, 512))?;
        self.stage.hca_up = true;
        Ok(())
    }

    /// One physical-address memory region over everything, so work queue
    /// entries can carry bus addresses directly.
    fn setup_mpt(&mut self) -> Result<(), Mlx4Error> {
        let key = self.caps.reserved_mrws | MKEY_PREFIX;
        self.lkey = key.rotate_left(8);
        let mut mpt = Ctx::new();
        // Region, physical addressing, local and remote read/write, atomic.
        mpt.set(0, 8, 7, 0x7f);
        mpt.set(2, 0, 32, key).set(3, 0, 24, PD).set(10, 22, 1, 1); // len64: the whole space
        self.hcr.exec(op::SW2HW_MPT, 0, self.caps.reserved_mrws, Input::Mailbox(&mpt, 64)).map(drop)
    }

    /// Byte address of MTT entry `index` (counted past the reserved ones).
    fn mtt_addr(&self, index: u32) -> u64 {
        (self.caps.reserved_mtts + index) as u64 * self.caps.mtt_entry
    }

    /// Points MTT entries `index..` at the pages of `buf`.
    fn write_mtt(&self, index: u32, buf: &DmaBuffer) -> Result<(), Mlx4Error> {
        let pages = buf.len().div_ceil(PAGE);
        let base = buf.device_addr().as_u64();
        let mut done = 0;
        while done < pages {
            let n = (pages - done).min(MTTS_PER_WRITE);
            let fill = |m: &DmaBuffer| {
                m.store(0, self.mtt_addr(index + done as u32).to_be());
                m.store(8, 0u64);
                for i in 0..n {
                    m.store(16 + 8 * i, ((base + ((done + i) * PAGE) as u64) | 1).to_be()); // present
                }
            };
            self.hcr.exec(op::WRITE_MTT, 0, n as u32, Input::Raw(&fill))?;
            done += n;
        }
        Ok(())
    }

    fn eq_doorbell(&self, eqn: u32) -> usize {
        let eqn = eqn as usize;
        0x800 + PAGE * (eqn / 4) + 8 * (eqn % 4)
    }

    /// Initializes `ring` and hands it to the device as event queue `eqn`,
    /// its MTT entry at `mtt`. If `armed` the queue raises MSI-X vector
    /// `intr` on its next event; otherwise it is "fired" and never
    /// interrupts, and is only polled.
    fn sw2hw_eq(&self, eqn: u32, ring: &OwnedDma<'d, D>, mtt: u32, intr: u16, armed: bool) -> Result<(), Mlx4Error> {
        for i in 0..NUM_EQES as usize {
            put32(ring, i * EQE_LEN + 28, 0x80); // owned by hardware
        }
        self.write_mtt(mtt, ring)?;
        let mut eqc = Ctx::new();
        // Overruns are ignored.
        eqc.set(0, 8, 4, if armed { EQ_STATE_ARMED } else { EQ_STATE_FIRED }).set(0, 17, 1, 1);
        eqc.set(3, 24, 5, log2_ceil(NUM_EQES));
        eqc.set(5, 0, 8, intr as u32);
        eqc.set_addr(6, self.mtt_addr(mtt));
        self.hcr.exec(op::SW2HW_EQ, 0, eqn, Input::Mailbox(&eqc, 64)).map(drop)
    }

    fn create_eq(&mut self) -> Result<(), Mlx4Error> {
        let ring = OwnedDma::new(self.dma, NUM_EQES as usize * EQE_LEN).ok_or(Mlx4Error::NoMemory)?;
        let created = self.sw2hw_eq(self.caps.eqn(), &ring, 0, VECTOR_ASYNC, false);
        self.mem.eq = Some(ring);
        created?;
        self.stage.eq_hw = true;
        self.hcr.exec(op::MAP_EQ, 0, self.caps.eqn(), Input::Imm(!0))?; // every event type
        self.stage.eq_mapped = true;
        Ok(())
    }

    /// Switches the adapter to MSI-X interrupts.
    ///
    /// `table_bar` maps the whole BAR that the function's MSI-X capability
    /// names ([`Msix::table_bir`](osmium_hal::pci::Msix::table_bir)),
    /// and `messages` are the address/data pairs for [`VECTOR_ASYNC`] and
    /// [`VECTOR_COMPLETION`], as the interrupt controller allocated them.
    /// Call it before opening ports; ports opened afterwards complete
    /// through the completion event queue and re-arm their completion queue
    /// as they reap it. The function needs at least two table entries; on
    /// any error the adapter stays in polled mode (a second event queue may
    /// remain created, unused, until drop).
    ///
    /// After an interrupt, call [`handle_interrupt`](Self::handle_interrupt)
    /// with the vector that fired. `Mlx4` is not `Sync`: the caller must
    /// keep the handler and the port operations from running concurrently
    /// (for instance by disabling interrupts around them).
    pub fn enable_msix<C: ConfigAccess + ?Sized>(
        &mut self,
        func: &Function<'_, C>,
        table_bar: &IoMem,
        messages: [MsiMessage; 2],
    ) -> Result<(), Mlx4Error> {
        if self.msix.is_some() {
            return Err(Mlx4Error::Msix(MsiError::Unsupported));
        }
        let msix = func.msix().map_err(Mlx4Error::Msix)?;
        if msix.table_size() <= VECTOR_COMPLETION {
            return Err(Mlx4Error::Msix(MsiError::Unsupported));
        }
        let table = msix.table(table_bar).map_err(Mlx4Error::Msix)?;
        for (vector, msg) in [VECTOR_ASYNC, VECTOR_COMPLETION].into_iter().zip(messages) {
            table.set_masked(vector, true).map_err(Mlx4Error::Msix)?;
            table.set_message(vector, msg).map_err(Mlx4Error::Msix)?;
        }

        let eqn = self.caps.comp_eqn();
        let ring = OwnedDma::new(self.dma, NUM_EQES as usize * EQE_LEN).ok_or(Mlx4Error::NoMemory)?;
        let created = self.sw2hw_eq(eqn, &ring, 1, VECTOR_COMPLETION, true);
        self.mem.comp_eq = Some(ring);
        created?;
        self.stage.comp_eq_hw = true;

        // Arm the asynchronous queue (the completion queue starts armed),
        // then let the function send.
        let _ = self.uar.write(self.eq_doorbell(self.caps.eqn()), (self.eq_ci.get() & 0xff_ffff | EQ_ARM).to_be());
        msix.enable(func);
        for vector in [VECTOR_ASYNC, VECTOR_COMPLETION] {
            table.set_masked(vector, false).map_err(Mlx4Error::Msix)?;
        }
        self.msix = Some(table);
        self.comp_eqn = Some(eqn);
        Ok(())
    }

    /// True once [`enable_msix`](Self::enable_msix) has succeeded.
    pub fn msix_enabled(&self) -> bool {
        self.comp_eqn.is_some()
    }

    /// Services MSI-X vector `vector` ([`VECTOR_ASYNC`] or
    /// [`VECTOR_COMPLETION`]) and re-arms its event queue.
    ///
    /// Returns a bit set of ports (bit `n` for port `n + 1`) whose
    /// completion queue signalled: the caller wakes whatever waits on those
    /// ports. Completions themselves are reaped by the port's own
    /// `receive` and `transmit` calls, which also re-arm the port's
    /// completion queue (until then it raises no further events). The async vector returns 0
    /// (it updates [`link_up`](Self::link_up)).
    pub fn handle_interrupt(&self, vector: u16) -> u8 {
        match vector {
            VECTOR_ASYNC => {
                self.poll_events();
                0
            }
            VECTOR_COMPLETION => self.poll_completion_events(),
            _ => 0,
        }
    }

    /// Consumes the events in `ring` from consumer index `ci`, calling
    /// `handle(event type, ring, byte offset of the entry)` for each, and
    /// rings the doorbell (re-arming the queue if `arm`).
    fn drain_eq(&self, eqn: u32, ring: &DmaBuffer, ci: &Cell<u32>, arm: bool, mut handle: impl FnMut(u32, usize)) {
        let mut at = ci.get();
        loop {
            let off = (at % NUM_EQES) as usize * EQE_LEN;
            let owner = get32(ring, off + 28) >> 7 & 1;
            if owner != (at / NUM_EQES) & 1 {
                break;
            }
            osmium_arch::barrier::dma_rmb();
            handle(get32(ring, off) >> 16 & 0xff, off);
            at = at.wrapping_add(1);
            let _ = self.uar.write(self.eq_doorbell(eqn), (at & 0xff_ffff).to_be());
        }
        ci.set(at);
        if arm {
            let _ = self.uar.write(self.eq_doorbell(eqn), (at & 0xff_ffff | EQ_ARM).to_be());
        }
    }

    /// Handles pending port events (link changes).
    pub fn poll_events(&self) {
        let Some(ring) = &self.mem.eq else { return };
        let arm = self.comp_eqn.is_some();
        self.drain_eq(self.caps.eqn(), ring, &self.eq_ci, arm, |kind, off| {
            if kind == EVENT_PORT_CHANGE {
                let head = get32(ring, off);
                let port = (get32(ring, off + 12) >> 28 & 3) as u8;
                if (1..=MAX_PORTS).contains(&port) {
                    self.set_link(port, head & PORT_CHANGE_ACTIVE != 0);
                }
            }
        });
    }

    /// Consumes completion events; returns the ports whose queue signalled.
    fn poll_completion_events(&self) -> u8 {
        let (Some(ring), Some(eqn)) = (&self.mem.comp_eq, self.comp_eqn) else { return 0 };
        let mut signalled = 0u8;
        self.drain_eq(eqn, ring, &self.comp_eq_ci, true, |kind, off| {
            if kind == EVENT_COMPLETION {
                let index = (get32(ring, off + 4) & 0xff_ffff).wrapping_sub(self.caps.reserved_cqs);
                if let Some(sn) = self.arm_sn.get(index as usize) {
                    sn.set(sn.get().wrapping_add(1));
                    signalled |= 1 << index;
                }
            }
        });
        signalled
    }

    /// Returns true if port `port`'s link is up, as last reported.
    pub fn link_up(&self, port: u8) -> bool {
        self.poll_events();
        (1..=MAX_PORTS).contains(&port) && self.link.get() & 1 << (port - 1) != 0
    }

    fn set_link(&self, port: u8, up: bool) {
        let bit = 1 << (port - 1);
        self.link.set(if up { self.link.get() | bit } else { self.link.get() & !bit });
    }

    /// Opens port `port` (1-based) for Ethernet.
    pub fn open_eth(&self, port: u8) -> Result<EthPort<'_, 'd, D>, Mlx4Error> {
        if !(1..=self.caps.num_ports).contains(&port) || self.open.get() & 1 << (port - 1) != 0 {
            return Err(Mlx4Error::BadPort);
        }
        EthPort::open(self, port)
    }

    /// Waits up to [`SENSE_TIMEOUT_NS`] for a dual-protocol port to tell
    /// which network its cable is on. Returns true unless it is InfiniBand.
    fn sense_ethernet(&self, port: u8) -> Result<bool, Mlx4Error> {
        let deadline = self.clock.now_ns().saturating_add(SENSE_TIMEOUT_NS);
        loop {
            match self.hcr.exec(op::SENSE_PORT, 0, port as u32, Input::None)? & 3 {
                1 => return Ok(false),
                2 => return Ok(true),
                // Nothing sensed yet: no cable, or still negotiating.
                _ if self.clock.now_ns() > deadline => return Ok(true),
                _ => {}
            }
        }
    }

    fn teardown(&mut self) {
        let leak = |hcr: &Hcr<'d, D>, r: Result<u64, Mlx4Error>| {
            if r.is_err() {
                hcr.wedge();
            }
        };
        let eqn = self.caps.eqn();
        if let Some(table) = &self.msix {
            for vector in [VECTOR_ASYNC, VECTOR_COMPLETION] {
                let _ = table.set_masked(vector, true);
            }
        }
        if self.stage.comp_eq_hw {
            let mut eqc = Ctx::new();
            let r = self.hcr.exec_out(op::HW2SW_EQ, 1, self.caps.comp_eqn(), Input::None, &mut eqc, 64).map(|_| 0);
            leak(&self.hcr, r);
        }
        if self.stage.eq_mapped {
            // Failing to unmap is harmless once the queue is gone.
            let _ = self.hcr.exec(op::MAP_EQ, 0, 1 << 31 | eqn, Input::Imm(!0));
        }
        if self.stage.eq_hw {
            let mut eqc = Ctx::new();
            let r = self.hcr.exec_out(op::HW2SW_EQ, 1, eqn, Input::None, &mut eqc, 64).map(|_| 0);
            leak(&self.hcr, r);
        }
        if self.stage.hca_up {
            leak(&self.hcr, self.hcr.exec(op::CLOSE_HCA, 0, 0, Input::None));
        }
        for (r, &len) in self.icm_regions.iter().zip(&self.stage.icm_mapped).rev() {
            if len > 0 {
                leak(&self.hcr, self.hcr.exec(op::UNMAP_ICM, 0, (len / PAGE) as u32, Input::Imm(r.va)));
            }
        }
        if self.stage.aux_mapped {
            leak(&self.hcr, self.hcr.exec(op::UNMAP_ICM_AUX, 0, 0, Input::None));
        }
        if self.stage.fa_mapped {
            leak(&self.hcr, self.hcr.exec(op::UNMAP_FA, 0, 0, Input::None));
        }
    }
}

impl<D: DmaAllocator + ?Sized> Drop for Mlx4<'_, D> {
    fn drop(&mut self) {
        self.teardown();
        if !self.hcr.is_wedged() {
            // SAFETY: dropped once, here; the device no longer uses it.
            unsafe { ManuallyDrop::drop(&mut self.mem) }
        }
    }
}

/// Resets the adapter, preserving its PCI configuration header (as Linux's
/// `mlx4_reset` does).
fn reset<C: ConfigAccess + ?Sized>(func: &Function<'_, C>, config: &IoMem, clock: &dyn Clock) -> Result<(), Mlx4Error> {
    // Dwords 22 and 23 (0x58, 0x5c) are a vendor window, not state.
    let mut header = [0u32; 64];
    for (i, d) in header.iter_mut().enumerate() {
        if i != 22 && i != 23 {
            *d = func.read32(4 * i as u16);
        }
    }
    // Restored from `header` below, so it must lie inside the 256 bytes saved.
    let pcie = func.find_capability(cap::PCI_EXPRESS).filter(|&at| at as usize + 0x14 <= 4 * header.len());

    // Hold off flash updates.
    let deadline = clock.now_ns().saturating_add(SEMAPHORE_TIMEOUT_NS);
    while config.read::<u32>(RESET_SEMAPHORE).map_err(|_| Mlx4Error::BadRegisters)? != 0 {
        if clock.now_ns() > deadline {
            return Err(Mlx4Error::Busy);
        }
    }
    let _ = config.write(RESET, 1u32.to_be());

    // The device must not be touched for a second after reset.
    let start = clock.now_ns();
    while clock.now_ns() < start.saturating_add(RESET_WAIT_NS) {
        core::hint::spin_loop();
    }
    let deadline = clock.now_ns().saturating_add(RESET_TIMEOUT_NS);
    while func.vendor_id() == 0xffff {
        if clock.now_ns() > deadline {
            return Err(Mlx4Error::BadDevice);
        }
    }

    // Device and link control (with their status halves, whose
    // write-1-to-clear bits just get cleared), then the type 0 header,
    // command register last.
    if let Some(at) = pcie {
        for reg in [at + 8, at + 0x10] {
            func.write32(reg, header[reg as usize / 4]);
        }
    }
    for (i, &d) in header[..16].iter().enumerate() {
        if i != 1 {
            func.write32(4 * i as u16, d);
        }
    }
    func.write32(4, header[1]);
    Ok(())
}

/// Stores a big-endian dword into DMA memory.
fn put32(buf: &DmaBuffer, offset: usize, value: u32) {
    buf.store(offset, value.to_be());
}

/// Loads a big-endian dword from DMA memory.
fn get32(buf: &DmaBuffer, offset: usize) -> u32 {
    u32::from_be(buf.load(offset))
}

#[cfg(test)]
mod tests {
    use std::vec;
    use std::vec::Vec;

    use osmium_hal::net::{MacAddress, NetDevice, NetError};

    use super::fake::{self, FakeHca, PortKind};
    use super::*;
    use crate::virtio::testing::HostDma;

    const ETH: [Option<PortKind>; 2] = [Some(PortKind::Ethernet), Some(PortKind::Ethernet)];

    fn bring_up<'d>(hca: &'d FakeHca, dma: &'d HostDma) -> Result<Mlx4<'d, HostDma>, Mlx4Error> {
        let func = Function::new(hca, fake::ADDR).unwrap();
        Mlx4::new(&func, hca.config_io(), hca.uar_io(), dma, hca)
    }

    #[test]
    fn supported_ids() {
        assert!(supports(0x15b3, 0x1003) && supports(0x15b3, 0x1007) && supports(0x15b3, 0x6750));
        assert!(!supports(0x15b3, 0x1013), "ConnectX-4 is mlx5");
        assert!(!supports(0x8086, 0x1003));
    }

    #[test]
    fn map_blocks_are_aligned() {
        let mut blocks = Vec::new();
        map_blocks(0x10_0000_7000, 0x7000, 0x1_9000, |va, pa, log| {
            blocks.push((va, pa, log));
            Ok(())
        })
        .unwrap();
        // pa 0x7000: one page to reach 32 KiB alignment, then as large as
        // the remaining length allows.
        assert_eq!(
            blocks,
            [(0x10_0000_7000, 0x7000, 12), (0x10_0000_8000, 0x8000, 15), (0x10_0001_0000, 0x1_0000, 16)]
        );
        // Block size is limited by both addresses' alignment.
        let mut n = 0;
        map_blocks(0x1000, 0x10_0000, 0x4000, |_, _, log| {
            assert_eq!(log, 12);
            n += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(n, 4);
        let total: u64 = blocks.iter().map(|b| 1u64 << b.2).sum();
        assert_eq!(total, 0x1_9000);
        for (i, &(va, pa, log)) in blocks.iter().enumerate() {
            assert_eq!((va | pa) % (1 << log), 0, "block {i} misaligned");
            if i > 0 {
                assert_eq!(va, blocks[i - 1].0 + (1 << blocks[i - 1].2), "contiguous");
            }
        }
    }

    #[test]
    fn map_blocks_rejects_unaligned_memory() {
        for (va, pa) in [(0x1000, 0x10_0800), (0x1800, 0x10_0000)] {
            let r = map_blocks(va, pa, 0x2000, |_, _, _| panic!("no block for unaligned memory"));
            assert_eq!(r, Err(Mlx4Error::MisalignedDma));
        }
    }

    #[test]
    fn icm_tables_are_aligned_and_disjoint() {
        let caps = Caps {
            reserved_qps: 64,
            reserved_srqs: 64,
            reserved_cqs: 128,
            reserved_eqs: 32,
            reserved_mtts: 16,
            reserved_mrws: 16,
            reserved_uars: 8,
            qpc_entry: 256,
            altc_entry: 64,
            auxc_entry: 128,
            srqc_entry: 64,
            cqc_entry: 64,
            eqc_entry: 64,
            cmpt_entry: 64,
            dmpt_entry: 64,
            mtt_entry: 8,
            num_ports: 2,
            dpdp: false,
            max_gso: 0,
        };
        let plan = plan_icm(&caps);
        let c = &plan.init_hca;
        let base = |dw: usize, low_mask: u32| (c.dword(dw) as u64) << 32 | (c.dword(dw + 1) & low_mask) as u64;
        // (base, entries, entry size) of every packed table.
        let tables = [
            (base(12, !0x1f), 1u64 << c.get(13, 0, 5), 256),
            (base(24, !0), 1 << c.get(13, 0, 5), 64),
            (base(28, !0), 1 << c.get(13, 0, 5), 128),
            (base(18, !0x1f), 1 << c.get(19, 0, 5), 64),
            (base(20, !0x1f), 1 << c.get(21, 0, 5), 64),
            (base(32, !0x1f), 1 << c.get(33, 0, 5), 64),
            (base(64, !0), 32, 8), // log2(16 reserved + 7) rounded up
            (base(60, !0), 1 << c.get(62, 0, 6), 64),
            (base(48, !0), 128, 64),
        ];
        assert!(1 << c.get(13, 0, 5) >= 64 + 15 + MAX_QPS as u64);
        assert!(1 << c.get(33, 0, 5) > caps.comp_eqn() as u64);
        let other = plan.regions[4];
        for (i, &(b, n, e)) in tables.iter().enumerate() {
            let len = n * e;
            assert_eq!(b % len, 0, "table {i} aligned to its size");
            assert!(b >= other.va && b + len <= other.va + other.len as u64, "table {i} inside the region");
            for &(b2, n2, e2) in &tables[i + 1..] {
                assert!(b + len <= b2 || b2 + n2 * e2 <= b, "tables overlap");
            }
        }
        // The cMPT windows: one per object type, each 2^24 entries apart.
        for (i, r) in plan.regions[..4].iter().enumerate() {
            assert_eq!(r.va, i as u64 * (64 << 24));
            assert_eq!(r.len % PAGE, 0);
        }
        assert_eq!(plan.size, other.va + other.len as u64);
    }

    #[test]
    fn bring_up_and_tear_down() {
        let hca = FakeHca::new(ETH);
        let dma = HostDma::default();
        let mlx = bring_up(&hca, &dma).unwrap();
        assert_eq!(mlx.num_ports(), 2);
        assert_eq!(mlx.firmware_version(), (2, 42, 5000));
        {
            let s = hca.state.borrow();
            assert_eq!(s.resets, 1);
            assert!(s.fw.running && s.fw.hca_up && s.fw.eq_mapped);
            assert_eq!(s.fw.aux_pages, fake::AUX_PAGES);
            assert_eq!(s.fw.special_qp, Some(64), "special QPs after the 64 reserved");
            assert_eq!(s.fw.lkey, Some(mlx.lkey));
            let first = |o| s.log.iter().position(|&x| x == o).unwrap();
            let order = [op::QUERY_FW, op::MAP_FA, op::RUN_FW, op::QUERY_DEV_CAP, op::SET_ICM_SIZE, op::INIT_HCA];
            assert!(order.windows(2).all(|w| first(w[0]) < first(w[1])), "{:x?}", s.log);
        }
        // The reset kept the PCI header, BARs and device control.
        assert_eq!(hca.config(4), fake::BAR0);
        assert_eq!(hca.config(6), fake::BAR2);
        assert_eq!(hca.config(fake::PCIE_CAP / 4 + 2), fake::DEVCTL);
        assert_eq!(hca.config(1) & 6, 6, "memory and bus master on");

        drop(mlx);
        let s = hca.state.borrow();
        assert!(!s.fw.running && !s.fw.hca_up && s.fw.icm.is_empty() && s.fw.aux_pages == 0);
        assert_eq!(dma.live.get(), 0, "everything freed");
    }

    #[test]
    fn failed_bring_up_unwinds() {
        let cases =
            [(op::RUN_FW, "firmware"), (op::MAP_ICM, "ICM"), (op::INIT_HCA, "init"), (op::MAP_EQ, "event queue")];
        for (opcode, stage) in cases {
            let hca = FakeHca::new(ETH);
            hca.state.borrow_mut().fail = Some((opcode, 0x10));
            let dma = HostDma::default();
            assert_eq!(bring_up(&hca, &dma).err(), Some(Mlx4Error::Command { opcode, status: 0x10 }), "{stage}");
            let s = hca.state.borrow();
            assert!(!s.fw.running && !s.fw.hca_up && s.fw.icm.is_empty() && s.fw.eqs.is_empty(), "{stage}");
            assert_eq!(dma.live.get(), 0, "{stage}: nothing leaked");
        }
    }

    #[test]
    fn hung_command_leaks_instead_of_freeing() {
        let hca = FakeHca::new(ETH);
        hca.state.borrow_mut().hang = Some(op::INIT_HCA);
        let dma = HostDma::default();
        assert_eq!(bring_up(&hca, &dma).err(), Some(Mlx4Error::Timeout));
        assert!(dma.live.get() > 0, "the device may still own that memory");
    }

    #[test]
    fn reset_preconditions() {
        let hca = FakeHca::new(ETH);
        let dma = HostDma::default();
        let func = Function::new(&hca, fake::ADDR).unwrap();
        let small = hca.config_io().slice(0, CONFIG_LEN / 2).unwrap();
        assert_eq!(Mlx4::new(&func, small, hca.uar_io(), &dma, &hca).err(), Some(Mlx4Error::BadRegisters));
        hca.hold_semaphore();
        assert_eq!(bring_up(&hca, &dma).err(), Some(Mlx4Error::Busy));
        assert_eq!(hca.state.borrow().resets, 0);
        assert_eq!(dma.live.get(), 0);
    }

    #[test]
    fn ethernet_traffic() {
        let hca = FakeHca::new(ETH);
        let dma = HostDma::default();
        let mlx = bring_up(&hca, &dma).unwrap();
        let mut eth = mlx.open_eth(1).unwrap();
        assert_eq!(eth.mac_address(), MacAddress(fake::MAC));
        assert!(eth.link_up());
        let qpn = 64 + 8; // past the reserved and special QPs
        assert_eq!(hca.qps(), [qpn]);
        assert_eq!(hca.cqs(), [128], "first CQ past the reserved ones");
        assert_eq!(hca.state.borrow().fw.port_mtu[0], 1522);
        assert!(hca.state.borrow().fw.port_up[0]);

        // Transmit until the ring is full, then let the device catch up.
        assert!(eth.can_transmit());
        for i in 0..eth::TX_SLOTS as u8 {
            eth.transmit(&[i; 60]).unwrap();
        }
        assert!(!eth.can_transmit());
        assert_eq!(eth.transmit(&[0; 60]), Err(NetError::WouldBlock));
        assert_eq!(eth.transmit(&[0; 1519]), Err(NetError::TooLarge));
        let sent = hca.sent(qpn);
        assert_eq!(sent.len(), eth::TX_SLOTS as usize);
        assert!(sent.iter().enumerate().all(|(i, f)| f == &vec![i as u8; 60]));
        assert!(eth.can_transmit());

        // Several laps of every ring, receive and transmit interleaved.
        let mut buf = [0u8; 2048];
        assert_eq!(eth.receive(&mut buf), Err(NetError::WouldBlock));
        for n in 0..100u32 {
            let frame: Vec<u8> = (0..64 + n % 1400).map(|b| (b + n) as u8).collect();
            assert!(hca.deliver(1, &frame));
            eth.transmit(&frame[..60]).unwrap();
            assert!(eth.can_receive());
            assert_eq!(eth.receive(&mut buf), Ok(frame.len()), "frame {n}");
            assert_eq!(&buf[..frame.len()], &frame[..]);
            assert_eq!(hca.sent(qpn), [frame[..60].to_vec()]);
        }

        // A burst fills every posted receive entry; the rest are dropped.
        for n in 0..eth::RX_SLOTS + 2 {
            assert_eq!(hca.deliver(1, &[n as u8; 100]), n < eth::RX_SLOTS);
        }
        assert_eq!(eth.receive(&mut buf[..50]), Err(NetError::TooLarge));
        for n in 1..eth::RX_SLOTS {
            assert_eq!(eth.receive(&mut buf), Ok(100));
            assert_eq!(buf[0], n as u8);
        }
        assert!(!eth.can_receive());
        assert!(hca.deliver(1, &[7; 60]), "entries reposted");

        drop(eth);
        assert!(hca.qps().is_empty() && hca.cqs().is_empty());
        assert!(!hca.state.borrow().fw.port_up[0]);
        drop(mlx);
        assert_eq!(dma.live.get(), 0);
    }

    #[test]
    fn link_events() {
        let hca = FakeHca::new(ETH);
        let dma = HostDma::default();
        let mlx = bring_up(&hca, &dma).unwrap();
        let p1 = mlx.open_eth(1).unwrap();
        let p2 = mlx.open_eth(2).unwrap();
        assert!(p1.link_up() && !p2.link_up());
        for i in 0..20 {
            // More events than the queue holds, consumed as they come.
            hca.port_event(1, i % 2 == 1);
            hca.port_event(2, i % 2 == 0);
            assert_eq!((p1.link_up(), p2.link_up()), (i % 2 == 1, i % 2 == 0));
        }
        assert_ne!(p1.mac_address(), MacAddress::BROADCAST);
        assert_eq!(hca.qps().len(), 2);
    }

    #[test]
    fn port_selection() {
        let ports = [Some(PortKind::InfiniBand), Some(PortKind::Vpi { sense_after: 3, sensed: 2 })];
        let hca = FakeHca::new(ports);
        hca.state.borrow_mut().dpdp = true;
        let dma = HostDma::default();
        let mlx = bring_up(&hca, &dma).unwrap();
        assert_eq!(mlx.open_eth(0).err(), Some(Mlx4Error::BadPort));
        assert_eq!(mlx.open_eth(3).err(), Some(Mlx4Error::BadPort));
        assert_eq!(mlx.open_eth(1).err(), Some(Mlx4Error::NotEthernet));
        let p2 = mlx.open_eth(2).unwrap();
        assert_eq!(mlx.open_eth(2).err(), Some(Mlx4Error::BadPort), "already open");
        drop(p2);
        drop(mlx.open_eth(2).unwrap());

        let ib = FakeHca::new([None, Some(PortKind::Vpi { sense_after: 0, sensed: 1 })]);
        ib.state.borrow_mut().dpdp = true;
        let mlx = bring_up(&ib, &dma).unwrap();
        assert_eq!(mlx.open_eth(2).err(), Some(Mlx4Error::NotEthernet), "cable on an InfiniBand fabric");
    }

    #[test]
    fn failed_open_unwinds() {
        let hca = FakeHca::new(ETH);
        let dma = HostDma::default();
        let mlx = bring_up(&hca, &dma).unwrap();
        let before = dma.live.get();
        hca.state.borrow_mut().fail = Some((op::INIT_PORT, 0x10));
        assert_eq!(mlx.open_eth(1).err(), Some(Mlx4Error::Command { opcode: op::INIT_PORT, status: 0x10 }));
        assert!(hca.qps().is_empty() && hca.cqs().is_empty());
        assert_eq!(dma.live.get(), before);
        hca.state.borrow_mut().fail = None;
        drop(mlx.open_eth(1).unwrap());
    }

    fn msix_messages() -> [MsiMessage; 2] {
        [MsiMessage { address: 0xfee0_0000, data: 0x40 }, MsiMessage { address: 0xfee0_1000, data: 0x41 }]
    }

    #[test]
    fn msix_interrupts() {
        let hca = FakeHca::new(ETH);
        let dma = HostDma::default();
        let func = Function::new(&hca, fake::ADDR).unwrap();
        let table = hca.msix_io();
        let mut mlx = Mlx4::new(&func, hca.config_io(), hca.uar_io(), &dma, &hca).unwrap();
        assert!(!mlx.msix_enabled());
        mlx.enable_msix(&func, &table, msix_messages()).unwrap();
        assert!(mlx.msix_enabled());
        assert_eq!(mlx.enable_msix(&func, &table, msix_messages()), Err(Mlx4Error::Msix(MsiError::Unsupported)));
        assert_eq!(hca.config(fake::MSIX_CAP / 4) >> 31, 1, "MSI-X enabled");
        assert_eq!((hca.msix_message(0), hca.msix_message(1)), (msix_messages()[0], msix_messages()[1]));
        assert_eq!(hca.state.borrow().fw.eqs.len(), 2, "asynchronous and completion queues");

        let mut eth = mlx.open_eth(1).unwrap();
        let qpn = 64 + 8;
        let mut buf = [0u8; 2048];
        assert!(hca.take_interrupts().is_empty());

        // The first frame interrupts; the completion queue then stays
        // disarmed until the port reaps it, so the second does not.
        assert!(hca.deliver(1, &[1; 100]) && hca.deliver(1, &[2; 100]));
        assert_eq!(hca.take_interrupts(), [VECTOR_COMPLETION]);
        assert_eq!(mlx.handle_interrupt(VECTOR_COMPLETION), 0b1, "port 1 signalled");
        assert_eq!(eth.receive(&mut buf), Ok(100));
        assert_eq!(buf[0], 1);
        assert_eq!(eth.receive(&mut buf), Ok(100));
        assert_eq!(buf[0], 2);

        // Reaping re-armed it: the next frame, and a transmit completion, interrupt again.
        assert!(hca.deliver(1, &[3; 100]));
        assert_eq!(hca.take_interrupts(), [VECTOR_COMPLETION]);
        assert_eq!(mlx.handle_interrupt(VECTOR_COMPLETION), 0b1);
        assert_eq!(eth.receive(&mut buf), Ok(100));
        eth.transmit(&[9; 60]).unwrap();
        assert_eq!(hca.sent(qpn).len(), 1);
        assert_eq!(hca.take_interrupts(), [VECTOR_COMPLETION], "send completion");
        assert_eq!(mlx.handle_interrupt(VECTOR_COMPLETION), 0b1);
        assert!(eth.can_transmit());
        // `can_*` only look; the next `receive` or `transmit` re-arms.
        assert_eq!(eth.receive(&mut buf), Err(NetError::WouldBlock));
        for n in 0..50u8 {
            // The arm count wraps through its two bits many times.
            assert!(hca.deliver(1, &[n; 64]));
            assert_eq!(hca.take_interrupts(), [VECTOR_COMPLETION], "frame {n}");
            assert_eq!(mlx.handle_interrupt(VECTOR_COMPLETION), 0b1);
            assert_eq!(eth.receive(&mut buf), Ok(64));
        }

        // Link changes arrive on the other vector, and are rearmed too.
        for up in [false, true, false] {
            hca.port_event(1, up);
            assert_eq!(hca.take_interrupts(), [VECTOR_ASYNC]);
            assert_eq!(mlx.handle_interrupt(VECTOR_ASYNC), 0);
            assert_eq!(eth.link_up(), up);
        }
        assert_eq!(mlx.handle_interrupt(7), 0, "unknown vector");

        // A second port signals its own bit.
        let mut p2 = mlx.open_eth(2).unwrap();
        assert!(hca.deliver(2, &[5; 64]));
        assert_eq!(mlx.handle_interrupt(VECTOR_COMPLETION), 0b10);
        assert_eq!(p2.receive(&mut buf), Ok(64));

        drop((eth, p2));
        drop(mlx);
        assert!(hca.state.borrow().fw.eqs.is_empty());
        assert_eq!(dma.live.get(), 0);
    }

    #[test]
    fn drop_masks_vectors() {
        let hca = FakeHca::new(ETH);
        let dma = HostDma::default();
        let func = Function::new(&hca, fake::ADDR).unwrap();
        let table = hca.msix_io();
        let mut mlx = Mlx4::new(&func, hca.config_io(), hca.uar_io(), &dma, &hca).unwrap();
        mlx.enable_msix(&func, &table, msix_messages()).unwrap();
        let masked = |v: usize| table.read::<u32>(v * 16 + 12).unwrap() & 1;
        assert_eq!((masked(0), masked(1)), (0, 0), "unmasked once enabled");
        drop(mlx);
        assert_eq!((masked(0), masked(1)), (1, 1));
    }

    #[test]
    fn msix_falls_back_to_polling() {
        let dma = HostDma::default();
        let hca = FakeHca::new(ETH);
        hca.remove_msix();
        let func = Function::new(&hca, fake::ADDR).unwrap();
        let mut mlx = Mlx4::new(&func, hca.config_io(), hca.uar_io(), &dma, &hca).unwrap();
        assert_eq!(mlx.enable_msix(&func, &hca.msix_io(), msix_messages()), Err(Mlx4Error::Msix(MsiError::NotPresent)));
        assert!(!mlx.msix_enabled());

        // A BAR too small for the table is reported, not panicked on.
        let small = hca.msix_io().slice(0, 16).unwrap();
        let hca2 = FakeHca::new(ETH);
        let func2 = Function::new(&hca2, fake::ADDR).unwrap();
        let mut mlx2 = Mlx4::new(&func2, hca2.config_io(), hca2.uar_io(), &dma, &hca2).unwrap();
        assert_eq!(mlx2.enable_msix(&func2, &small, msix_messages()), Err(Mlx4Error::Msix(MsiError::OutOfBar)));
        assert_eq!(hca2.config(fake::MSIX_CAP / 4) >> 31, 0, "left disabled");
        assert!(!mlx2.msix_enabled());

        // Polling still works.
        let mut eth = mlx.open_eth(1).unwrap();
        assert!(hca.deliver(1, &[4; 80]));
        assert!(hca.take_interrupts().is_empty(), "polled queues never interrupt");
        let mut buf = [0u8; 2048];
        assert_eq!(eth.receive(&mut buf), Ok(80));
    }

    #[test]
    fn checksum_offload() {
        let hca = FakeHca::new(ETH);
        let dma = HostDma::default();
        let mlx = bring_up(&hca, &dma).unwrap();
        let mut eth = mlx.open_eth(1).unwrap();
        let qpn = 64 + 8;
        assert!(eth.offloads().tx_checksum && eth.offloads().rx_checksum);
        assert_eq!(eth.offloads().tso_max_frame, 0, "the fake does not segment by default");

        eth.transmit(&[1; 60]).unwrap();
        eth.transmit_offload(&[2; 60], TxOffload { checksum: true, tso: None }).unwrap();
        let sent = hca.sent_ex(qpn);
        assert_eq!((sent[0].ip_csum, sent[0].l4_csum), (false, false));
        assert_eq!((sent[1].ip_csum, sent[1].l4_csum), (true, true));
        assert_eq!(sent[1].frame, [2; 60]);
        let checksum = TxOffload { checksum: true, tso: None };
        assert_eq!(eth.transmit_offload(&[0; 1519], checksum), Err(NetError::TooLarge.into()));

        const L4_OK: u16 = 1 << 10 | 1 << 12; // TCP, IP header ok
        let mut buf = [0u8; 2048];
        for (status, sum, want) in [
            (L4_OK, 0xffff, RxChecksum::Verified),
            (1 << 11 | 1 << 12, 0xffff, RxChecksum::Verified), // UDP
            (L4_OK, 0x1234, RxChecksum::Unverified),           // bad TCP sum
            (1 << 10, 0xffff, RxChecksum::Unverified),         // bad IP header
            (1 << 12, 0xffff, RxChecksum::Unverified),         // neither TCP nor UDP
            (0, 0, RxChecksum::Unverified),
        ] {
            assert!(hca.deliver_with(1, &[7; 70], status, sum));
            assert_eq!(eth.receive_checked(&mut buf), Ok((70, want)), "status {status:#x} sum {sum:#x}");
        }
        assert!(hca.deliver_with(1, &[7; 70], L4_OK, 0xffff));
        assert_eq!(eth.receive(&mut buf), Ok(70), "plain receive ignores the verdict");
    }

    #[test]
    fn segmentation_offload() {
        let hca = FakeHca::new(ETH);
        hca.state.borrow_mut().max_gso = 65536;
        let dma = HostDma::default();
        let mlx = bring_up(&hca, &dma).unwrap();
        let mut eth = mlx.open_eth(1).unwrap();
        let qpn = 64 + 8;
        assert_eq!(eth.offloads().tso_max_frame, 16 * 1024, "bounded by the staging buffer");

        let frame: Vec<u8> = (0..9000u32).map(|i| (i * 7) as u8).collect();
        let tso = |mss, header_len| TxOffload { checksum: false, tso: Some(Tso { mss, header_len }) };
        eth.transmit_offload(&frame, tso(1448, 54)).unwrap();
        let sent = hca.sent_ex(qpn);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].frame, frame, "header inline, payload from the staging buffer");
        assert_eq!(sent[0].lso, Some((1448, 54)));
        assert!(sent[0].ip_csum && sent[0].l4_csum, "segmentation implies checksum offload");

        // The largest header, and an odd one that needs padding.
        for h in [eth::TSO_MAX_HEADER as u16, 55] {
            eth.transmit_offload(&frame[..3000], tso(1000, h)).unwrap();
            assert_eq!(hca.sent_ex(qpn)[0].lso, Some((1000, h as usize)));
        }

        // Only one segmentation frame is in flight; the buffer frees on completion.
        eth.transmit_offload(&frame[..4000], tso(1000, 54)).unwrap();
        assert_eq!(eth.transmit_offload(&frame[..4000], tso(1000, 54)), Err(NetError::WouldBlock.into()));
        eth.transmit(&[0; 60]).unwrap(); // ordinary frames still go
        assert_eq!(hca.sent_ex(qpn).len(), 2);
        eth.transmit_offload(&frame[..4000], tso(1000, 54)).unwrap();
        assert_eq!(hca.sent_ex(qpn).len(), 1);

        let mut bad = |mss, h, len: usize| eth.transmit_offload(&frame[..len], tso(mss, h));
        assert_eq!(bad(0, 54, 3000), Err(TxError::BadSegmentation));
        assert_eq!(bad(1000, 0, 3000), Err(TxError::BadSegmentation));
        assert_eq!(bad(1000, eth::TSO_MAX_HEADER as u16 + 1, 3000), Err(TxError::BadSegmentation));
        assert_eq!(bad(1000, 54, 54), Err(TxError::BadSegmentation), "no payload");
        assert_eq!(bad(1500, 54, 3000), Err(NetError::TooLarge.into()), "segments over the MTU");
        let big = vec![0u8; 16 * 1024 + 1];
        assert_eq!(eth.transmit_offload(&big, tso(1000, 54)), Err(NetError::TooLarge.into()));
        assert!(hca.sent_ex(qpn).is_empty(), "nothing was posted");
        drop(eth);
        drop(mlx);
        assert_eq!(dma.live.get(), 0);
    }

    #[test]
    fn segmentation_needs_device_support() {
        let hca = FakeHca::new(ETH);
        let dma = HostDma::default();
        let mlx = bring_up(&hca, &dma).unwrap();
        let mut eth = mlx.open_eth(1).unwrap();
        let t = TxOffload { checksum: true, tso: Some(Tso { mss: 1000, header_len: 54 }) };
        assert_eq!(eth.transmit_offload(&[0; 3000], t), Err(TxError::Unsupported));
    }
}
