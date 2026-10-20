//! A software NVMe controller for host tests.
//!
//! [`Fake::serve`] runs on its own thread and plays the controller over
//! plain memory: it watches CC for enable, disable and shutdown, reads the
//! doorbells the driver writes, fetches commands from the submission
//! queues in DMA memory, follows their PRPs over RAM-disk namespaces, and
//! posts completions with phase tags. It checks what the driver programs
//! as it goes (and panics, failing the test, on anything wrong).
//!
//! It is also the driver's [`Clock`]: real time, plus whatever the fake
//! skips ahead to play a controller that takes seconds without the test
//! waiting for them.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::boxed::Box;
use std::sync::Mutex;
use std::time::Instant;
use std::vec;
use std::vec::Vec;

use osmium_hal::mmio::IoMem;
use osmium_hal::timer::Clock;

use super::{ACQ, AQA, ASQ, CAP, CC, CSTS, DOORBELLS, IrqSignal, PAGE, VS, op};

/// Bytes of register window.
pub const REGS_LEN: usize = 0x2000;

pub const MODEL: &str = "QEMU NVMe Ctrl";
pub const SERIAL: &str = "osmium0";
pub const FIRMWARE: &str = "9.1.0";

/// Status values (SCT << 8 | SC).
pub const INVALID_OPCODE: u16 = 0x001;
pub const INTERNAL_ERROR: u16 = 0x006;
pub const INVALID_NAMESPACE: u16 = 0x00b;
pub const LBA_OUT_OF_RANGE: u16 = 0x080;
pub const UNRECOVERED_READ: u16 = 0x281;
pub const INVALID_QUEUE: u16 = 0x101;

/// A namespace: a RAM disk of `data.len() >> lbads` blocks.
pub struct Ns {
    pub nsid: u32,
    pub lbads: u8,
    /// Metadata bytes per block, which the driver must refuse.
    pub ms: u16,
    pub data: Vec<u8>,
}

impl Ns {
    pub fn new(nsid: u32, lbads: u8, blocks: usize) -> Self {
        let data = (0..blocks << lbads).map(|i| (i as u8).wrapping_mul(13).wrapping_add(nsid as u8)).collect();
        Self { nsid, lbads, ms: 0, data }
    }
}

pub struct Config {
    pub mqes: u16,
    pub dstrd: u8,
    pub to: u8,
    pub css_nvm: bool,
    pub mpsmin: u8,
    pub version: u32,
    pub mdts: u8,
    pub vwc: bool,
    /// Never sets CSTS.RDY (and time flies while the driver waits).
    pub never_ready: bool,
    /// Starts enabled but not yet ready, as firmware might leave it, and
    /// becomes ready 20 ms later; clearing EN before then is an error.
    pub enabling: bool,
    /// Sets CSTS.CFS instead of RDY.
    pub fatal: bool,
    /// Transfers touching blocks at or past this fail as unrecovered.
    pub bad_from: u64,
    pub reject_flush: bool,
    /// Posts a completion with a wrong command identifier before each
    /// I/O completion.
    pub stray: bool,
    /// Never completes I/O commands (and an hour passes).
    pub ignore_io: bool,
    /// Sets CSTS.CFS instead of completing I/O commands.
    pub fatal_io: bool,
    /// Nanoseconds each I/O command takes.
    pub io_delay_ns: u64,
    /// Sets More in every completion's status, and Do Not Retry in failed
    /// ones.
    pub status_flags: bool,
    /// Posts the completions found in one doorbell scan in reverse order.
    pub reorder: bool,
    pub namespaces: Vec<Ns>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mqes: 2047,
            dstrd: 0,
            to: 1,
            css_nvm: true,
            mpsmin: 0,
            version: 0x0001_0400,
            mdts: 7,
            vwc: true,
            never_ready: false,
            enabling: false,
            fatal: false,
            bad_from: u64::MAX,
            reject_flush: false,
            stray: false,
            ignore_io: false,
            fatal_io: false,
            io_delay_ns: 0,
            status_flags: false,
            reorder: false,
            namespaces: vec![Ns::new(1, 9, 1024)],
        }
    }
}

/// One command the controller ran.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cmd {
    pub qid: u16,
    pub opcode: u8,
    pub nsid: u32,
    pub cdw10: u32,
    pub cdw11: u32,
    pub cdw12: u32,
    /// Entries of the PRP list it used (0 without one).
    pub list: usize,
}

impl Cmd {
    pub fn io(opcode: u8, nsid: u32, lba: u64, blocks: u32, list: usize) -> Self {
        let cdw12 = if opcode == op::FLUSH { 0 } else { blocks - 1 };
        Self { qid: 1, opcode, nsid, cdw10: lba as u32, cdw11: (lba >> 32) as u32, cdw12, list }
    }
}

#[derive(Clone, Copy)]
struct Sq {
    base: u64,
    size: u16,
    head: u16,
    cqid: u16,
}

#[derive(Clone, Copy)]
struct Cq {
    base: u64,
    size: u16,
    tail: u16,
    phase: bool,
    /// Raises the fake's MSI-X signal for each completion.
    ien: bool,
}

pub struct Fake {
    regs: Box<[AtomicU32]>,
    pub cfg: Config,
    pub namespaces: Mutex<Vec<Ns>>,
    pub log: Mutex<Vec<Cmd>>,
    stop: AtomicBool,
    pub shutdowns: AtomicU32,
    /// Times the controller went from enabled to disabled.
    pub disables: AtomicU32,
    start: Instant,
    /// Nanoseconds skipped ahead.
    skipped: AtomicU64,
    /// Clock readings so far, so a slow command can wait for the driver to
    /// see the time it took.
    readings: AtomicU64,
    /// Raised for each completion posted to a queue with interrupts on.
    pub signal: IrqSignal,
    /// The most commands the controller found waiting at once on an I/O queue.
    pub max_inflight: AtomicU32,
    /// Dword 11 of the last Create I/O Completion Queue.
    pub cq_flags: AtomicU32,
}

// The driver's buffers are identity-mapped host memory.
fn rd32(addr: u64) -> u32 {
    // SAFETY: an address in test DMA memory the driver handed over.
    unsafe { (addr as *const u32).read_volatile() }
}

fn wr32(addr: u64, v: u32) {
    // SAFETY: as for `rd32`.
    unsafe { (addr as *mut u32).write_volatile(v) }
}

fn rd64(addr: u64) -> u64 {
    rd32(addr) as u64 | (rd32(addr + 4) as u64) << 32
}

fn bytes(addr: u64, len: usize) -> &'static mut [u8] {
    // SAFETY: as for `rd32`.
    unsafe { core::slice::from_raw_parts_mut(addr as *mut u8, len) }
}

/// The pages (address, length) that PRPs `prp1`, `prp2` describe for
/// `len` bytes, and how many list entries that took.
fn prp_segments(prp1: u64, prp2: u64, len: usize) -> (Vec<(u64, usize)>, usize) {
    let page = PAGE as u64;
    assert_eq!(prp1 % 4, 0, "PRP1 is dword-aligned");
    let first = len.min(PAGE - (prp1 % page) as usize);
    let mut segs = vec![(prp1, first)];
    let mut rest = len - first;
    if rest == 0 {
        return (segs, 0);
    }
    if rest <= PAGE {
        assert_eq!(prp2 % page, 0, "PRP2 is a page");
        segs.push((prp2, rest));
        return (segs, 0);
    }
    assert_eq!(prp2 % 8, 0, "the PRP list is qword-aligned");
    let n = rest.div_ceil(PAGE);
    assert!((prp2 % page) as usize + n * 8 <= PAGE, "no list chaining needed");
    for i in 0..n {
        let entry = rd64(prp2 + 8 * i as u64);
        assert_eq!(entry % page, 0, "list entries are pages");
        segs.push((entry, rest.min(PAGE)));
        rest -= rest.min(PAGE);
    }
    (segs, n)
}

impl Fake {
    pub fn new(mut cfg: Config) -> Self {
        let regs: Box<[AtomicU32]> = (0..REGS_LEN / 4).map(|_| AtomicU32::new(0)).collect();
        let cap = cfg.mqes as u64
            | 1 << 16 // CQR
            | (cfg.to as u64) << 24
            | (cfg.dstrd as u64) << 32
            | (cfg.css_nvm as u64) << 37
            | (cfg.mpsmin as u64) << 48
            | 4 << 52; // MPSMAX
        regs[CAP / 4].store(cap as u32, Ordering::Relaxed);
        regs[CAP / 4 + 1].store((cap >> 32) as u32, Ordering::Relaxed);
        regs[VS / 4].store(cfg.version, Ordering::Relaxed);
        // As firmware might leave it: enabled.
        regs[CC / 4].store(1, Ordering::Relaxed);
        regs[CSTS / 4].store(!cfg.enabling as u32, Ordering::Relaxed);
        let namespaces = Mutex::new(core::mem::take(&mut cfg.namespaces));
        Self {
            regs,
            cfg,
            namespaces,
            log: Mutex::new(Vec::new()),
            stop: AtomicBool::new(false),
            shutdowns: AtomicU32::new(0),
            disables: AtomicU32::new(0),
            start: Instant::now(),
            skipped: AtomicU64::new(0),
            readings: AtomicU64::new(0),
            signal: IrqSignal::new(),
            max_inflight: AtomicU32::new(0),
            cq_flags: AtomicU32::new(0),
        }
    }

    /// Moves the clock `ns` ahead.
    pub fn skip(&self, ns: u64) {
        self.skipped.fetch_add(ns, Ordering::AcqRel);
    }

    /// Moves the clock `ns` ahead and waits until the driver has read it
    /// twice, so it decides on its deadline before the completion appears
    /// (a real controller completes only after the time has passed).
    fn take_time(&self, ns: u64) {
        self.skip(ns);
        let seen = self.readings.load(Ordering::Acquire);
        let start = Instant::now();
        while self.readings.load(Ordering::Acquire) < seen + 2 && start.elapsed().as_secs() < 5 {
            std::thread::yield_now();
        }
    }

    pub fn io(&self) -> IoMem {
        // SAFETY: the registers are atomics, which tolerate the driver's
        // volatile accesses from another thread; they outlive the driver.
        unsafe { IoMem::new(self.regs.as_ptr() as *mut u8, REGS_LEN) }
    }

    pub fn reg(&self, off: usize) -> u32 {
        self.regs[off / 4].load(Ordering::Acquire)
    }

    fn set_reg(&self, off: usize, v: u32) {
        self.regs[off / 4].store(v, Ordering::Release)
    }

    fn doorbell(&self, qid: u16, completion: bool) -> u16 {
        self.reg(DOORBELLS + (2 * qid as usize + completion as usize) * (4 << self.cfg.dstrd)) as u16
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::Release);
    }

    pub fn commands(&self) -> Vec<Cmd> {
        self.log.lock().unwrap().clone()
    }

    pub fn io_commands(&self) -> Vec<Cmd> {
        self.commands().into_iter().filter(|c| c.qid == 1).collect()
    }

    /// Plays the controller until [`stop`](Self::stop).
    pub fn serve(&self) {
        let mut sqs: [Option<Sq>; 2] = [None; 2];
        let mut cqs: [Option<Cq>; 2] = [None; 2];
        let mut enabled = false;
        let mut ready_at = self.cfg.enabling.then(|| self.now_ns() + 20_000_000);
        while !self.stop.load(Ordering::Acquire) {
            let cc = self.reg(CC);
            if let Some(at) = ready_at {
                assert_eq!(cc & 1, 1, "EN cleared while the controller is still enabling");
                if self.now_ns() >= at {
                    ready_at = None;
                    enabled = true;
                    self.set_reg(CSTS, 1);
                }
                std::thread::yield_now();
                continue;
            }
            if cc & 1 == 0 {
                if enabled {
                    self.disables.fetch_add(1, Ordering::Relaxed);
                }
                enabled = false;
                sqs = [None; 2];
                cqs = [None; 2];
                self.set_reg(CSTS, 0);
            } else if !enabled && self.reg(CSTS) == 0 {
                if self.cfg.fatal {
                    self.set_reg(CSTS, 2);
                } else if self.cfg.never_ready {
                    self.skip(100_000_000);
                } else {
                    assert_eq!(cc, 0x0046_0001, "IOCQES 4, IOSQES 6, MPS 0, CSS 0");
                    let aqa = self.reg(AQA);
                    let (asq, acq) = (self.reg(ASQ) as u64, self.reg(ACQ) as u64);
                    let (asq, acq) = (asq | (self.reg(ASQ + 4) as u64) << 32, acq | (self.reg(ACQ + 4) as u64) << 32);
                    assert_eq!((asq % PAGE as u64, acq % PAGE as u64), (0, 0));
                    sqs[0] = Some(Sq { base: asq, size: (aqa & 0xfff) as u16 + 1, head: 0, cqid: 0 });
                    cqs[0] =
                        Some(Cq { base: acq, size: (aqa >> 16 & 0xfff) as u16 + 1, tail: 0, phase: true, ien: false });
                    enabled = true;
                    self.set_reg(CSTS, 1);
                }
            }
            if enabled && cc >> 14 & 3 == 1 && self.reg(CSTS) & 0xc == 0 {
                self.shutdowns.fetch_add(1, Ordering::Relaxed);
                self.set_reg(CSTS, self.reg(CSTS) | 0x8);
            }
            let mut busy = false;
            for qid in 0..2u16 {
                let Some(mut sq) = sqs[qid as usize] else { continue };
                let tail = self.doorbell(qid, false);
                assert!(tail < sq.size, "SQ {qid} tail {tail} within {}", sq.size);
                if qid == 1 {
                    let waiting = (tail + sq.size - sq.head) % sq.size;
                    self.max_inflight.fetch_max(waiting as u32, Ordering::Relaxed);
                }
                let mut deferred = Vec::new();
                while sq.head != tail {
                    busy = true;
                    let sqe: [u32; 16] = core::array::from_fn(|i| rd32(sq.base + sq.head as u64 * 64 + 4 * i as u64));
                    sq.head = (sq.head + 1) % sq.size;
                    sqs[qid as usize] = Some(sq);
                    let (result, status) = if qid == 0 {
                        self.admin(&sqe, &mut sqs, &mut cqs)
                    } else {
                        if self.cfg.ignore_io || self.cfg.fatal_io {
                            self.record(1, &sqe, 0);
                            match self.cfg.fatal_io {
                                true => self.set_reg(CSTS, self.reg(CSTS) | 2),
                                // Once is enough to time the driver out. Later jumps would race with its
                                // shutdown and push that past its own deadline.
                                false if self.skipped.load(Ordering::Acquire) == 0 => self.skip(3_600_000_000_000),
                                false => {}
                            }
                            continue;
                        }
                        if self.cfg.io_delay_ns != 0 {
                            self.take_time(self.cfg.io_delay_ns);
                        }
                        self.nvm(&sqe)
                    };
                    let cid = (sqe[0] >> 16) as u16;
                    let Some(cq) = cqs[sq.cqid as usize].as_mut() else { continue };
                    if qid == 1 && self.cfg.stray {
                        self.post(cq, sq.cqid, cid ^ 0x8000, qid, sq.head, 0, 0);
                    }
                    if qid == 1 && self.cfg.reorder {
                        deferred.push((sq.cqid, cid, sq.head, result, status));
                        continue;
                    }
                    self.post(cq, sq.cqid, cid, qid, sq.head, result, status);
                }
                for (cqid, cid, head, result, status) in deferred.into_iter().rev() {
                    let cq = cqs[cqid as usize].as_mut().expect("completion queue exists");
                    self.post(cq, cqid, cid, qid, head, result, status);
                }
            }
            if !busy {
                std::thread::yield_now();
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn post(&self, cq: &mut Cq, cqid: u16, cid: u16, sqid: u16, sqhd: u16, result: u32, mut status: u16) {
        if self.cfg.status_flags {
            // More, and Do Not Retry.
            status |= 1 << 13 | ((status != 0) as u16) << 14;
        }
        // Wait for room: the queue is full when the tail would meet the head.
        loop {
            let head = self.doorbell(cqid, true);
            assert!(head < cq.size, "CQ {cqid} head {head} within {}", cq.size);
            if (cq.tail + 1) % cq.size != head || self.stop.load(Ordering::Acquire) {
                break;
            }
            std::thread::yield_now();
        }
        let at = cq.base + cq.tail as u64 * 16;
        wr32(at, result);
        wr32(at + 4, 0);
        wr32(at + 8, sqhd as u32 | (sqid as u32) << 16);
        core::sync::atomic::fence(Ordering::Release);
        wr32(at + 12, cid as u32 | (cq.phase as u32) << 16 | (status as u32) << 17);
        if cq.ien {
            self.signal.notify();
        }
        cq.tail += 1;
        if cq.tail == cq.size {
            cq.tail = 0;
            cq.phase = !cq.phase;
        }
    }

    fn record(&self, qid: u16, sqe: &[u32; 16], list: usize) {
        let opcode = sqe[0] as u8;
        let cmd = Cmd { qid, opcode, nsid: sqe[1], cdw10: sqe[10], cdw11: sqe[11], cdw12: sqe[12], list };
        self.log.lock().unwrap().push(cmd);
    }

    fn prps(sqe: &[u32; 16]) -> (u64, u64) {
        (sqe[6] as u64 | (sqe[7] as u64) << 32, sqe[8] as u64 | (sqe[9] as u64) << 32)
    }

    /// Writes `src` to the buffer the command's PRPs describe.
    fn fill(sqe: &[u32; 16], src: &[u8]) {
        let (prp1, prp2) = Self::prps(sqe);
        let mut off = 0;
        for (addr, len) in prp_segments(prp1, prp2, src.len()).0 {
            bytes(addr, len).copy_from_slice(&src[off..off + len]);
            off += len;
        }
    }

    fn admin(&self, sqe: &[u32; 16], sqs: &mut [Option<Sq>; 2], cqs: &mut [Option<Cq>; 2]) -> (u32, u16) {
        self.record(0, sqe, 0);
        let (prp1, _) = Self::prps(sqe);
        let qid = sqe[10] as u16;
        let size = (sqe[10] >> 16) as u16 + 1;
        match sqe[0] as u8 {
            op::IDENTIFY => {
                let mut page = vec![0u8; PAGE];
                let nss = self.namespaces.lock().unwrap();
                match sqe[10] & 0xff {
                    1 => {
                        page[0..2].copy_from_slice(&0x1b36u16.to_le_bytes());
                        let mut put = |off: usize, len: usize, s: &str| {
                            page[off..off + len].fill(b' ');
                            page[off..off + s.len()].copy_from_slice(s.as_bytes());
                        };
                        put(4, 20, SERIAL);
                        put(24, 40, MODEL);
                        put(64, 8, FIRMWARE);
                        page[77] = self.cfg.mdts;
                        page[80..84].copy_from_slice(&self.cfg.version.to_le_bytes());
                        let nn = nss.iter().map(|n| n.nsid).max().unwrap_or(0);
                        page[516..520].copy_from_slice(&nn.to_le_bytes());
                        page[525] = self.cfg.vwc as u8;
                    }
                    0 => {
                        if let Some(ns) = nss.iter().find(|n| n.nsid == sqe[1]) {
                            let blocks = (ns.data.len() >> ns.lbads) as u64;
                            for off in [0, 8, 16] {
                                page[off..off + 8].copy_from_slice(&blocks.to_le_bytes());
                            }
                            // Two formats: a decoy, and the one in use.
                            page[25] = 1;
                            page[26] = 1;
                            page[128..132].copy_from_slice(&(9u32 << 16).to_le_bytes());
                            let lbaf = (ns.lbads as u32) << 16 | ns.ms as u32;
                            page[132..136].copy_from_slice(&lbaf.to_le_bytes());
                        }
                    }
                    2 => {
                        let mut ids: Vec<u32> = nss.iter().map(|n| n.nsid).filter(|&id| id > sqe[1]).collect();
                        ids.sort();
                        for (i, id) in ids.iter().enumerate() {
                            page[4 * i..4 * i + 4].copy_from_slice(&id.to_le_bytes());
                        }
                    }
                    _ => return (0, INVALID_OPCODE),
                }
                drop(nss);
                Self::fill(sqe, &page);
                (0, 0)
            }
            op::SET_FEATURES => {
                assert_eq!((sqe[10], sqe[11]), (0x07, 0), "one queue pair");
                (0, 0)
            }
            op::CREATE_CQ => {
                assert_eq!(qid, 1);
                assert!(sqe[11] & 0xffff == 1 || sqe[11] & 0xffff == 3, "contiguous, interrupts on or off");
                self.cq_flags.store(sqe[11], Ordering::Relaxed);
                assert!(size >= 2 && size <= self.cfg.mqes + 1, "CQ size {size}");
                assert_eq!(prp1 % PAGE as u64, 0);
                cqs[1] = Some(Cq { base: prp1, size, tail: 0, phase: true, ien: sqe[11] & 2 != 0 });
                (0, 0)
            }
            op::CREATE_SQ => {
                assert_eq!((qid, sqe[11]), (1, 1 << 16 | 1), "qid 1 on CQ 1, contiguous");
                assert!(size >= 2 && size <= self.cfg.mqes + 1, "SQ size {size}");
                assert_eq!(prp1 % PAGE as u64, 0);
                if cqs[1].is_none() {
                    return (0, INVALID_QUEUE);
                }
                sqs[1] = Some(Sq { base: prp1, size, head: 0, cqid: 1 });
                (0, 0)
            }
            op::DELETE_SQ => {
                assert_eq!(qid, 1);
                sqs[1] = None;
                (0, 0)
            }
            op::DELETE_CQ => {
                assert_eq!(qid, 1);
                assert!(sqs[1].is_none(), "the SQ goes first");
                cqs[1] = None;
                (0, 0)
            }
            _ => (0, INVALID_OPCODE),
        }
    }

    fn nvm(&self, sqe: &[u32; 16]) -> (u32, u16) {
        let opcode = sqe[0] as u8;
        let mut nss = self.namespaces.lock().unwrap();
        let Some(ns) = nss.iter_mut().find(|n| n.nsid == sqe[1]) else {
            self.record(1, sqe, 0);
            return (0, INVALID_NAMESPACE);
        };
        if opcode == op::FLUSH {
            self.record(1, sqe, 0);
            return (0, if self.cfg.reject_flush { INTERNAL_ERROR } else { 0 });
        }
        let lba = sqe[10] as u64 | (sqe[11] as u64) << 32;
        let blocks = (sqe[12] & 0xffff) as u64 + 1;
        let len = (blocks as usize) << ns.lbads;
        let (prp1, prp2) = Self::prps(sqe);
        let (segs, list) = prp_segments(prp1, prp2, len);
        self.record(1, sqe, list);
        if self.cfg.mdts != 0 {
            assert!(len <= PAGE << self.cfg.mdts, "{len} bytes exceeds MDTS");
        }
        if lba + blocks > (ns.data.len() >> ns.lbads) as u64 {
            return (0, LBA_OUT_OF_RANGE);
        }
        if lba + blocks > self.cfg.bad_from {
            return (0, UNRECOVERED_READ);
        }
        let mut off = (lba as usize) << ns.lbads;
        for (addr, n) in segs {
            match opcode {
                op::READ => bytes(addr, n).copy_from_slice(&ns.data[off..off + n]),
                op::WRITE => ns.data[off..off + n].copy_from_slice(bytes(addr, n)),
                _ => return (0, INVALID_OPCODE),
            }
            off += n;
        }
        (0, 0)
    }
}

impl Clock for Fake {
    fn now_ns(&self) -> u64 {
        self.readings.fetch_add(1, Ordering::AcqRel);
        self.start.elapsed().as_nanos() as u64 + self.skipped.load(Ordering::Acquire)
    }
}
