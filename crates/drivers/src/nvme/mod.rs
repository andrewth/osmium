//! NVM Express (NVMe) storage controllers.
//!
//! [`Nvme`] brings a controller up from its registers (PCI BAR 0, class
//! 01/08/02): disable, one admin queue pair, enable, IDENTIFY, one I/O
//! queue pair, and the first active namespace, which it then serves as a
//! [`BlockDevice`]. Requests are synchronous, but a transfer larger than one
//! command carries (over [`DATA_LEN`], or the controller's maximum, MDTS) is
//! split and the pieces are kept in flight together, up to [`SLOTS`] at a
//! time (fewer if the controller's queues are shorter), each with its own
//! bounce buffer of [`DATA_LEN`] bytes described by PRP entries; completions
//! may arrive in any order.
//!
//! By default the driver polls its completion queue ([`Nvme::new`]). With
//! [`Nvme::with_interrupts`] the I/O completion queue is created with an
//! MSI-X vector instead, and the driver sleeps through an [`Interrupts::idle`]
//! hook between completions; the caller programs the MSI-X table and the
//! interrupt handler, which calls [`IrqSignal::notify`]. Admin commands are
//! always polled. The interrupt mask registers (INTMS) are written only when
//! polling; the spec forbids touching them with MSI-X.
//!
//! Every wait is bounded by a [`Clock`]: CAP.TO for the controller to
//! change state, [`COMMAND_TIMEOUT_NS`] for a command ([`FLUSH_TIMEOUT_NS`]
//! for a flush). If a command never completes, or the controller reports a
//! fatal error while it runs, the driver stops using the controller (later
//! requests fail) rather than reuse memory the controller may still write;
//! if the controller then refuses to disable, dropping the driver leaks its
//! DMA memory for the same reason.
//!
//! The [`DmaAllocator`] must hand out page-aligned memory, as frame
//! allocators do. Namespaces with metadata, or with blocks larger than
//! 4 KiB, are not supported.
//!
//! Not yet supported: several I/O queues (one per CPU), pin-based or
//! single-vector MSI interrupts, and controllers whose smallest page
//! exceeds 4 KiB.

mod queue;

#[cfg(test)]
mod fake;

use core::mem::ManuallyDrop;
use core::ops::Range;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::ioext::IoMemExt;
use osmium_arch::barrier;
use osmium_hal::block::{BlockDevice, BlockError};
use osmium_hal::dma::{DmaAllocator, OwnedDma};
use osmium_hal::mmio::IoMem;
use osmium_hal::timer::Clock;

use queue::{Queue, Sqe};

/// The BAR holding the controller's registers (64-bit memory).
pub const BAR: u8 = 0;

/// Bytes of DMA bounce buffer per slot, and so the most one command transfers.
pub const DATA_LEN: usize = 64 * 1024;

/// Bounce buffers, and so the most I/O commands in flight at once.
pub const SLOTS: usize = 4;

/// Entries in the admin queues.
pub const ADMIN_DEPTH: u16 = 16;

/// Entries in the I/O queues, at most (the controller may allow fewer).
pub const IO_DEPTH: u16 = 16;

/// The memory page size the driver programs (CC.MPS = 0).
const PAGE: usize = 4096;

/// Create I/O completion queue: interrupts enabled.
const QUEUE_IEN: u32 = 1 << 1;

// The PRP list is one page, never chained.
const _: () = assert!(DATA_LEN / PAGE <= PAGE / 8);

// Controller registers.
const CAP: usize = 0x00;
const VS: usize = 0x08;
const INTMS: usize = 0x0c;
const CC: usize = 0x14;
const CSTS: usize = 0x1c;
const AQA: usize = 0x24;
const ASQ: usize = 0x28;
const ACQ: usize = 0x30;
const DOORBELLS: usize = 0x1000;

const CC_EN: u32 = 1 << 0;
const CC_SHN_MASK: u32 = 3 << 14;
const CC_SHN_NORMAL: u32 = 1 << 14;
const CC_IOSQES: u32 = 6 << 16;
const CC_IOCQES: u32 = 4 << 20;
const CSTS_RDY: u32 = 1 << 0;
const CSTS_CFS: u32 = 1 << 1;
const CSTS_SHST_MASK: u32 = 3 << 2;
const CSTS_SHST_COMPLETE: u32 = 2 << 2;
/// CAP.CSS bit for the NVM command set.
const CAP_CSS_NVM: u64 = 1 << 37;

/// VS of NVMe 1.1, the first with the active namespace list.
const VERSION_1_1: u32 = 0x0001_0100;

/// Nanoseconds per CAP.TO unit.
const TIMEOUT_UNIT_NS: u64 = 500_000_000;

/// How long a command may take before it counts as lost.
pub const COMMAND_TIMEOUT_NS: u64 = 30_000_000_000;

/// How long a flush may take: writing back a large cache can take a while.
pub const FLUSH_TIMEOUT_NS: u64 = 120_000_000_000;

/// Command identifiers run 0..=MAX_CID (0xffff is reserved).
const MAX_CID: u16 = 0xfffe;

/// Opcodes.
mod op {
    pub const DELETE_SQ: u8 = 0x00;
    pub const CREATE_SQ: u8 = 0x01;
    pub const DELETE_CQ: u8 = 0x04;
    pub const CREATE_CQ: u8 = 0x05;
    pub const IDENTIFY: u8 = 0x06;
    pub const SET_FEATURES: u8 = 0x09;
    pub const FLUSH: u8 = 0x00;
    pub const WRITE: u8 = 0x01;
    pub const READ: u8 = 0x02;
}

// IDENTIFY's CNS values.
const CNS_NAMESPACE: u32 = 0;
const CNS_CONTROLLER: u32 = 1;
const CNS_ACTIVE_NAMESPACES: u32 = 2;

const FEATURE_NUM_QUEUES: u32 = 0x07;
/// Create I/O queue: physically contiguous.
const QUEUE_PC: u32 = 1 << 0;

/// The I/O queue pair's identifier.
const IO_QID: u16 = 1;

/// Why bringing up the controller, or an admin operation, failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NvmeError {
    /// The register window is too small or nothing answers in it.
    BadRegisters,
    /// The controller lacks the NVM command set or 4 KiB pages, or the
    /// namespace's format has metadata or blocks over 4 KiB.
    Unsupported,
    /// The controller did not become ready, or a command did not complete.
    Timeout,
    /// The controller reported a fatal status (CSTS.CFS).
    Fatal,
    /// The controller failed an admin command.
    Command {
        /// The command's opcode.
        opcode: u8,
        /// Status code type.
        sct: u8,
        /// Status code.
        sc: u8,
    },
    /// No such namespace, or no active one.
    NoNamespace,
    /// DMA memory could not be allocated.
    NoMemory,
    /// The allocator returned memory that is not page-aligned.
    MisalignedDma,
}

/// How one command failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    Timeout,
    Fatal,
    Status(u16),
}

/// Allocates `len` zeroed bytes of page-aligned DMA memory.
fn alloc<D: DmaAllocator + ?Sized>(dma: &D, len: usize) -> Result<OwnedDma<'_, D>, NvmeError> {
    let buf = OwnedDma::new(dma, len).ok_or(NvmeError::NoMemory)?;
    match buf.device_addr().is_aligned(PAGE as u64) {
        true => Ok(buf),
        false => Err(NvmeError::MisalignedDma),
    }
}

/// A command with `cdw10..=cdw12`; the identifier and PRPs come later.
fn command(opcode: u8, nsid: u32, cdw10: u32, cdw11: u32, cdw12: u32) -> Sqe {
    let mut sqe = [0; 16];
    sqe[0] = opcode as u32;
    sqe[1] = nsid;
    sqe[10] = cdw10;
    sqe[11] = cdw11;
    sqe[12] = cdw12;
    sqe
}

fn set_prps(sqe: &mut Sqe, prp1: u64, prp2: u64) {
    sqe[6] = prp1 as u32;
    sqe[7] = (prp1 >> 32) as u32;
    sqe[8] = prp2 as u32;
    sqe[9] = (prp2 >> 32) as u32;
}

/// An identify string: ASCII, space-padded.
fn ident_string<const N: usize>(page: &[u8], offset: usize) -> [u8; N] {
    core::array::from_fn(|i| match page.get(offset.saturating_add(i)) {
        Some(&b @ 0x20..=0x7e) => b,
        _ => b' ',
    })
}

fn trimmed(s: &[u8]) -> &str {
    // Only printable ASCII is stored.
    core::str::from_utf8(s).unwrap_or("").trim_end()
}

/// The register window and doorbell stride.
struct Regs {
    io: IoMem,
    stride: usize,
}

impl Regs {
    fn read(&self, off: usize) -> u32 {
        self.io.rd(off)
    }

    fn write(&self, off: usize, v: u32) {
        self.io.wr(off, v)
    }

    // 64-bit registers are accessed as two dwords, low first, which every
    // controller accepts.
    fn write64(&self, off: usize, v: u64) {
        self.write(off, v as u32);
        self.write(off + 4, (v >> 32) as u32);
    }

    /// Writes queue `qid`'s submission tail or completion head doorbell.
    fn doorbell(&self, qid: u16, completion: bool, value: u16) {
        self.write(DOORBELLS + (2 * qid as usize + completion as usize) * self.stride, value as u32);
    }
}

/// A count of completion interrupts, shared between the interrupt handler
/// and the driver (a `static` will do).
pub struct IrqSignal(AtomicU32);

impl IrqSignal {
    /// A signal nothing has raised.
    pub const fn new() -> Self {
        Self(AtomicU32::new(0))
    }

    /// Records an interrupt; call it from the MSI-X handler.
    pub fn notify(&self) {
        self.0.fetch_add(1, Ordering::Release);
    }

    /// Interrupts recorded so far (wrapping).
    pub fn count(&self) -> u32 {
        self.0.load(Ordering::Acquire)
    }
}

impl Default for IrqSignal {
    fn default() -> Self {
        Self::new()
    }
}

/// How an interrupt-driven [`Nvme`] is signalled and waits.
#[derive(Clone, Copy)]
pub struct Interrupts<'d> {
    /// The MSI-X table entry the I/O completion queue raises. The caller
    /// has programmed and unmasked it, and enabled MSI-X.
    pub vector: u16,
    /// Raised by the handler of that vector.
    pub signal: &'d IrqSignal,
    /// Called to sleep until an interrupt may have arrived (for example
    /// `sti; hlt`). It may return early or spuriously, and must return
    /// eventually (a timer tick suffices), since the driver enforces its
    /// command timeouts between calls.
    pub idle: &'d dyn Fn(),
}

/// Sleeps in `irq`'s idle hook if no interrupt has arrived since `seen`
/// (read before the completion queue was checked), else just spins once.
fn idle(irq: Option<Interrupts<'_>>, seen: u32) {
    match irq {
        Some(i) if i.signal.count() == seen => (i.idle)(),
        _ => osmium_arch::cpu::spin_hint(),
    }
}

/// Copies a range of a request to or from the bounce buffer at a DMA offset.
type Copier<'d, 'f, D> = dyn FnMut(&OwnedDma<'d, D>, usize, Range<usize>) + 'f;

/// Everything the controller may access by DMA.
struct Memory<'d, D: DmaAllocator + ?Sized> {
    admin: Queue<'d, D>,
    io: Queue<'d, D>,
    /// [`SLOTS`] bounce buffers of [`DATA_LEN`] bytes.
    data: OwnedDma<'d, D>,
    /// [`SLOTS`] pages of PRP list, one per bounce buffer.
    prp_list: OwnedDma<'d, D>,
}

/// An NVMe controller and the namespace it serves. Dropping it disables
/// the controller and frees its memory.
pub struct Nvme<'d, D: DmaAllocator + ?Sized> {
    regs: Regs,
    /// Freed in `drop` only once the controller is disabled.
    mem: ManuallyDrop<Memory<'d, D>>,
    clock: &'d dyn Clock,
    /// CAP.TO: how long the controller may take to enable or disable.
    ready_timeout_ns: u64,
    next_cid: u16,
    irq: Option<Interrupts<'d>>,
    /// Why a command was lost (it timed out, or the controller failed);
    /// the controller may still write its buffer.
    broken: Option<Failure>,
    io_queues: bool,
    version: u32,
    model: [u8; 40],
    serial: [u8; 20],
    firmware: [u8; 8],
    max_transfer: usize,
    has_flush: bool,
    nsid: u32,
    block_shift: u32,
    blocks: u64,
}

impl<'d, D: DmaAllocator + ?Sized> Nvme<'d, D> {
    /// Resets the controller whose registers are `io` (all of BAR 0) and
    /// starts it with DMA memory from `dma`, serving its first active
    /// namespace; `clock` times its waits. The PCI function must already
    /// decode memory and be allowed to master the bus.
    ///
    /// Completions are polled; see [`with_interrupts`](Self::with_interrupts).
    pub fn new(io: IoMem, dma: &'d D, clock: &'d dyn Clock) -> Result<Self, NvmeError> {
        Self::start(io, dma, clock, None)
    }

    /// Like [`new`](Self::new), but the I/O completion queue raises MSI-X
    /// vector `irq.vector` and the driver waits with `irq.idle` instead of
    /// spinning. The caller must have set up the vector (and enabled MSI-X
    /// on the PCI function) before this call; if it cannot, use
    /// [`new`](Self::new), which works without any interrupts.
    pub fn with_interrupts(
        io: IoMem,
        dma: &'d D,
        clock: &'d dyn Clock,
        irq: Interrupts<'d>,
    ) -> Result<Self, NvmeError> {
        Self::start(io, dma, clock, Some(irq))
    }

    fn start(io: IoMem, dma: &'d D, clock: &'d dyn Clock, irq: Option<Interrupts<'d>>) -> Result<Self, NvmeError> {
        let r = |off: usize| io.read::<u32>(off).map_err(|_| NvmeError::BadRegisters);
        let cap = r(CAP)? as u64 | (r(CAP + 4)? as u64) << 32;
        let version = r(VS)?;
        let mqes = cap as u16;
        let timeout = (cap >> 24 & 0xff).max(1);
        let stride = 4usize << (cap >> 32 & 0xf);
        let mpsmin = cap >> 48 & 0xf;
        // All ones is what a bus returns when nothing decodes the address.
        if cap == u64::MAX || mqes == 0 || io.len() < DOORBELLS + 2 * (IO_QID as usize + 1) * stride {
            return Err(NvmeError::BadRegisters);
        }
        if cap & CAP_CSS_NVM == 0 || mpsmin != 0 {
            return Err(NvmeError::Unsupported);
        }

        let mem = Memory {
            admin: Queue::new(dma, 0, ADMIN_DEPTH)?,
            io: Queue::new(dma, IO_QID, (mqes.saturating_add(1)).min(IO_DEPTH))?,
            data: alloc(dma, SLOTS * DATA_LEN)?,
            prp_list: alloc(dma, SLOTS * PAGE)?,
        };
        // From here on, dropping `nvme` on an error disables the controller
        // before the memory goes.
        let mut nvme = Self {
            regs: Regs { io, stride },
            mem: ManuallyDrop::new(mem),
            clock,
            ready_timeout_ns: timeout * TIMEOUT_UNIT_NS,
            next_cid: 0,
            irq,
            broken: None,
            io_queues: false,
            version,
            model: [b' '; 40],
            serial: [b' '; 20],
            firmware: [b' '; 8],
            max_transfer: DATA_LEN,
            has_flush: false,
            nsid: 0,
            block_shift: 9,
            blocks: 0,
        };
        nvme.disable()?;
        nvme.enable()?;
        nvme.identify_controller()?;
        nvme.create_io_queues()?;
        let nsid = nvme.first_namespace()?;
        nvme.select_namespace(nsid)?;
        Ok(nvme)
    }

    /// The NVMe version the controller implements, as VS encodes it:
    /// major in bits 31:16, minor in 15:8, tertiary in 7:0.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// The model number, without trailing spaces.
    pub fn model(&self) -> &str {
        trimmed(&self.model)
    }

    /// The serial number, without trailing spaces.
    pub fn serial(&self) -> &str {
        trimmed(&self.serial)
    }

    /// The firmware revision, without trailing spaces.
    pub fn firmware(&self) -> &str {
        trimmed(&self.firmware)
    }

    /// The namespace being served.
    pub fn namespace(&self) -> u32 {
        self.nsid
    }

    /// The most bytes one command transfers: [`DATA_LEN`], or less if the
    /// controller says so.
    pub fn max_transfer(&self) -> usize {
        self.max_transfer
    }

    /// The most I/O commands this driver keeps in flight: [`SLOTS`], or
    /// fewer if the controller's I/O queue is shorter.
    pub fn queue_depth(&self) -> usize {
        SLOTS.min(self.mem.io.depth() as usize - 1)
    }

    /// True if completions arrive by interrupt rather than polling.
    pub fn interrupt_driven(&self) -> bool {
        self.irq.is_some()
    }

    /// True if the controller has a volatile write cache, which
    /// [`BlockDevice::flush`] writes back.
    pub fn has_write_cache(&self) -> bool {
        self.has_flush
    }

    /// Copies the identifiers of active namespaces, in ascending order,
    /// into `out`; returns how many it copied (the first 1024 at most).
    /// Controllers older than NVMe 1.1 list none.
    pub fn active_namespaces(&mut self, out: &mut [u32]) -> Result<usize, NvmeError> {
        if self.version < VERSION_1_1 {
            return Ok(0);
        }
        self.admin(command(op::IDENTIFY, 0, CNS_ACTIVE_NAMESPACES, 0, 0), PAGE)?;
        let mut n = 0;
        for slot in out.iter_mut().take(PAGE / 4) {
            let nsid = u32::from_le(self.mem.data.load(n * 4));
            if nsid == 0 {
                break;
            }
            *slot = nsid;
            n += 1;
        }
        Ok(n)
    }

    /// Serves namespace `nsid` from now on. On failure the namespace in
    /// use stays selected.
    pub fn select_namespace(&mut self, nsid: u32) -> Result<(), NvmeError> {
        if nsid == 0 || nsid == u32::MAX {
            return Err(NvmeError::NoNamespace);
        }
        match self.admin(command(op::IDENTIFY, nsid, CNS_NAMESPACE, 0, 0), PAGE) {
            // Invalid Namespace or Format.
            Err(NvmeError::Command { sct: 0, sc: 0x0b, .. }) => return Err(NvmeError::NoNamespace),
            r => r?,
        };
        let data = &self.mem.data;
        let nsze = u64::from_le(data.load(0));
        let nlbaf = data.load::<u8>(25);
        let flbas = data.load::<u8>(26);
        // Bits 6:5 extend the format index past 16 formats (NVMe 2.0).
        let index = (flbas & 0xf) | (flbas >> 5 & 3) << 4;
        let lbaf = u32::from_le(data.load(128 + 4 * index as usize));
        let (ms, lbads) = (lbaf & 0xffff, lbaf >> 16 & 0xff);
        // An inactive namespace identifies as all zeros.
        if nsze == 0 {
            return Err(NvmeError::NoNamespace);
        }
        if index > nlbaf || ms != 0 || !(9..=12).contains(&lbads) {
            return Err(NvmeError::Unsupported);
        }
        self.nsid = nsid;
        self.block_shift = lbads;
        self.blocks = nsze;
        Ok(())
    }

    /// Polls CSTS until `done` holds for it, for up to CAP.TO.
    fn wait(&self, done: impl Fn(u32) -> bool) -> Result<u32, NvmeError> {
        let deadline = self.clock.now_ns().saturating_add(self.ready_timeout_ns);
        loop {
            let csts = self.regs.read(CSTS);
            if done(csts) {
                return Ok(csts);
            }
            if self.clock.now_ns() > deadline {
                // One last look, in case the clock moved while this was descheduled.
                let csts = self.regs.read(CSTS);
                return if done(csts) { Ok(csts) } else { Err(NvmeError::Timeout) };
            }
            osmium_arch::cpu::spin_hint();
        }
    }

    /// Clears CC.EN and waits for the controller to stop, which also ends
    /// any DMA and deletes every queue.
    fn disable(&self) -> Result<(), NvmeError> {
        // A controller still enabling (EN = 1, RDY = 0) must become ready,
        // or fail, before EN is cleared. If it does neither in time, clear
        // EN anyway: there is nothing better to try.
        if self.regs.read(CC) & CC_EN != 0 {
            let _ = self.wait(|csts| csts & (CSTS_RDY | CSTS_CFS) != 0);
        }
        self.regs.write(CC, 0);
        self.wait(|csts| csts & CSTS_RDY == 0).map(|_| ())
    }

    fn enable(&self) -> Result<(), NvmeError> {
        let (asq, acq) = self.mem.admin.addrs();
        let depth = ADMIN_DEPTH as u32 - 1;
        self.regs.write(AQA, depth << 16 | depth);
        self.regs.write64(ASQ, asq);
        self.regs.write64(ACQ, acq);
        // NVM command set, 4 KiB pages, round-robin arbitration.
        self.regs.write(CC, CC_IOCQES | CC_IOSQES | CC_EN);
        let csts = self.wait(|csts| csts & (CSTS_RDY | CSTS_CFS) != 0)?;
        if csts & CSTS_CFS != 0 {
            return Err(NvmeError::Fatal);
        }
        // Pin interrupts stay masked when completions are polled. With MSI-X
        // the spec forbids touching INTMS/INTMC.
        if self.irq.is_none() {
            self.regs.write(INTMS, u32::MAX);
        }
        Ok(())
    }

    fn identify_controller(&mut self) -> Result<(), NvmeError> {
        self.admin(command(op::IDENTIFY, 0, CNS_CONTROLLER, 0, 0), PAGE)?;
        let mut page = [0u8; 528];
        self.mem.data.read(0, &mut page);
        self.serial = ident_string(&page, 4);
        self.model = ident_string(&page, 24);
        self.firmware = ident_string(&page, 64);
        // MDTS is a power of two in units of the minimum page; 0 means
        // no limit. Beyond 2^4 pages it exceeds the bounce buffer anyway.
        self.max_transfer = match page[77] {
            0 => DATA_LEN,
            mdts => DATA_LEN.min(PAGE << mdts.min(8)),
        };
        self.has_flush = page[525] & 1 != 0;
        Ok(())
    }

    fn create_io_queues(&mut self) -> Result<(), NvmeError> {
        // Ask for one queue pair; controllers grant at least that, so a
        // refusal (some reject the feature) changes nothing.
        match self.admin(command(op::SET_FEATURES, 0, FEATURE_NUM_QUEUES, 0, 0), 0) {
            Err(NvmeError::Command { .. }) | Ok(_) => {}
            Err(e) => return Err(e),
        }
        let (sq, cq) = self.mem.io.addrs();
        let size = (self.mem.io.depth() as u32 - 1) << 16 | IO_QID as u32;
        // Interrupts stay off (IEN = 0) unless the caller set up a vector.
        let flags = match self.irq {
            Some(i) => QUEUE_PC | QUEUE_IEN | (i.vector as u32) << 16,
            None => QUEUE_PC,
        };
        let mut create_cq = command(op::CREATE_CQ, 0, size, flags, 0);
        set_prps(&mut create_cq, cq, 0);
        self.admin(create_cq, 0)?;
        self.io_queues = true;
        let mut create_sq = command(op::CREATE_SQ, 0, size, (IO_QID as u32) << 16 | QUEUE_PC, 0);
        set_prps(&mut create_sq, sq, 0);
        self.admin(create_sq, 0)?;
        Ok(())
    }

    fn first_namespace(&mut self) -> Result<u32, NvmeError> {
        let mut first = [0];
        match self.version {
            v if v < VERSION_1_1 => Ok(1),
            _ => match self.active_namespaces(&mut first)? {
                0 => Err(NvmeError::NoNamespace),
                _ => Ok(first[0]),
            },
        }
    }

    /// Runs one admin command over the first `len` bytes of the buffer.
    fn admin(&mut self, sqe: Sqe, len: usize) -> Result<u32, NvmeError> {
        let opcode = sqe[0] as u8;
        self.execute(false, sqe, len).map_err(|f| match f {
            Failure::Timeout => NvmeError::Timeout,
            Failure::Fatal => NvmeError::Fatal,
            Failure::Status(s) => NvmeError::Command { opcode, sct: (s >> 8 & 7) as u8, sc: s as u8 },
        })
    }

    /// Reads or writes `len` bytes at `lba` as commands of at most
    /// `max_transfer` bytes, keeping up to [`queue_depth`](Self::queue_depth)
    /// of them in flight. `fill` copies a piece's bytes (a range of the
    /// request) into its bounce buffer before it is submitted, and `drain`
    /// copies them out once it completes; both get the buffer's offset in
    /// the DMA region. If a piece fails, no more are submitted, those in
    /// flight are waited for, and the request fails.
    fn pipeline(
        &mut self,
        opcode: u8,
        lba: u64,
        len: usize,
        fill: &mut Copier<'d, '_, D>,
        drain: &mut Copier<'d, '_, D>,
    ) -> Result<(), BlockError> {
        if self.broken.is_some() {
            return Err(BlockError::Io);
        }
        let chunk = self.max_transfer;
        let pieces = len.div_ceil(chunk);
        let window = self.queue_depth();
        let irq = self.irq;
        let qid = self.mem.io.qid();
        // The command identifier and piece index in each slot.
        let mut slots: [Option<(u16, usize)>; SLOTS] = [None; SLOTS];
        let (mut submitted, mut failed) = (0, false);
        let mut deadline = self.clock.now_ns().saturating_add(COMMAND_TIMEOUT_NS);
        loop {
            let mut tail = None;
            while !failed && submitted < pieces {
                let Some(slot) = slots.iter().take(window).position(Option::is_none) else { break };
                let start = submitted * chunk;
                let range = start..len.min(start + chunk);
                fill(&self.mem.data, slot * DATA_LEN, range.clone());
                let cid = self.next_cid;
                self.next_cid = if cid == MAX_CID { 0 } else { cid + 1 };
                let at = lba + (start >> self.block_shift) as u64;
                let blocks = (range.len() >> self.block_shift) as u32;
                let mut sqe = command(opcode, self.nsid, at as u32, (at >> 32) as u32, blocks.saturating_sub(1));
                sqe[0] |= (cid as u32) << 16;
                self.data_prps(&mut sqe, slot, range.len());
                tail = Some(self.mem.io.push(&sqe));
                if let Some(s) = slots.get_mut(slot) {
                    *s = Some((cid, submitted));
                }
                submitted += 1;
            }
            if let Some(tail) = tail {
                // The entries (and PRP lists) before the doorbell.
                barrier::mb();
                // Read before the doorbell: the controller may take its time from the ring on.
                deadline = self.clock.now_ns().saturating_add(COMMAND_TIMEOUT_NS);
                self.regs.doorbell(qid, false, tail);
            }
            if slots.iter().all(Option::is_none) {
                return if failed { Err(BlockError::Io) } else { Ok(()) };
            }
            // Wait for one completion, whichever it is.
            let lost = loop {
                let seen = irq.map_or(0, |i| i.signal.count());
                let Some(done) = self.mem.io.pop() else {
                    if self.regs.read(CSTS) & CSTS_CFS != 0 {
                        break Some(Failure::Fatal);
                    }
                    if self.clock.now_ns() > deadline {
                        break Some(Failure::Timeout);
                    }
                    idle(irq, seen);
                    continue;
                };
                // The entries are the controller's again once the head moves: finish reading first.
                barrier::mb();
                self.regs.doorbell(qid, true, self.mem.io.head());
                let found = slots.iter().position(|s| matches!(s, Some((cid, _)) if *cid == done.cid));
                // Anything else is stray.
                let Some(slot) = found.filter(|_| done.sqid == qid) else {
                    // A controller that keeps posting stray completions must not stall us forever.
                    if self.clock.now_ns() > deadline {
                        break Some(Failure::Timeout);
                    }
                    continue;
                };
                let Some((_, index)) = slots.get_mut(slot).and_then(Option::take) else { continue };
                match done.status {
                    0 if opcode == op::READ => {
                        let start = index * chunk;
                        drain(&self.mem.data, slot * DATA_LEN, start..len.min(start + chunk));
                    }
                    0 => {}
                    _ => failed = true,
                }
                deadline = self.clock.now_ns().saturating_add(COMMAND_TIMEOUT_NS);
                break None;
            };
            // Only a lost command gets here without a completion.
            if let Some(why) = lost {
                self.broken = Some(why);
                return Err(BlockError::Io);
            }
        }
    }

    /// Submits `sqe` on the admin or I/O queue, pointing its PRPs at the
    /// first `len` bytes of the bounce buffer, and waits for its
    /// completion; returns its dword 0.
    fn execute(&mut self, io_queue: bool, mut sqe: Sqe, len: usize) -> Result<u32, Failure> {
        if let Some(why) = self.broken {
            return Err(why);
        }
        let cid = self.next_cid;
        self.next_cid = if cid == MAX_CID { 0 } else { cid + 1 };
        sqe[0] |= (cid as u32) << 16;
        if len > 0 {
            self.data_prps(&mut sqe, 0, len);
        }
        let irq = self.irq.filter(|_| io_queue);

        let mem = &mut *self.mem;
        let queue = if io_queue { &mut mem.io } else { &mut mem.admin };
        let tail = queue.push(&sqe);
        let timeout = match io_queue && sqe[0] as u8 == op::FLUSH {
            true => FLUSH_TIMEOUT_NS,
            false => COMMAND_TIMEOUT_NS,
        };
        let deadline = self.clock.now_ns().saturating_add(timeout);
        // The entry (and PRP list) before the doorbell.
        barrier::mb();
        self.regs.doorbell(queue.qid(), false, tail);
        let why = loop {
            let seen = irq.map_or(0, |i| i.signal.count());
            let Some(done) = queue.pop() else {
                // A failed controller completes nothing more.
                if self.regs.read(CSTS) & CSTS_CFS != 0 {
                    break Failure::Fatal;
                }
                if self.clock.now_ns() > deadline {
                    break Failure::Timeout;
                }
                idle(irq, seen);
                continue;
            };
            // The entries are the controller's again once the head moves: finish reading first.
            barrier::mb();
            self.regs.doorbell(queue.qid(), true, queue.head());
            // Nothing else is in flight, so anything else is stray.
            if done.cid == cid && done.sqid == queue.qid() {
                return match done.status {
                    0 => Ok(done.result),
                    s => Err(Failure::Status(s)),
                };
            }
            if self.clock.now_ns() > deadline {
                break Failure::Timeout;
            }
        };
        self.broken = Some(why);
        Err(why)
    }

    /// Describes the first `len` bytes of bounce buffer `slot`: PRP1 is its
    /// first page; PRP2 is the second page or, beyond two, a list of the
    /// rest (in the slot's own page of list).
    fn data_prps(&self, sqe: &mut Sqe, slot: usize, len: usize) {
        let base = self.mem.data.device_addr().as_u64() + (slot * DATA_LEN) as u64;
        let list = slot * PAGE;
        let prp2 = match len.div_ceil(PAGE) {
            1 => 0,
            2 => base + PAGE as u64,
            pages => {
                for i in 1..pages {
                    self.mem.prp_list.store(list + (i - 1) * 8, (base + (i * PAGE) as u64).to_le());
                }
                self.mem.prp_list.device_addr().as_u64() + list as u64
            }
        };
        set_prps(sqe, base, prp2);
    }

    /// Shuts the controller down and disables it; returns true once it has
    /// stopped.
    fn shutdown(&self) -> bool {
        let (cc, csts) = (self.regs.read(CC), self.regs.read(CSTS));
        if cc & CC_EN != 0 && csts & (CSTS_RDY | CSTS_CFS) == CSTS_RDY {
            // A normal shutdown lets the controller write back its caches.
            self.regs.write(CC, cc & !CC_SHN_MASK | CC_SHN_NORMAL);
            let _ = self.wait(|csts| csts & CSTS_SHST_MASK == CSTS_SHST_COMPLETE);
        }
        self.disable().is_ok()
    }
}

impl<D: DmaAllocator + ?Sized> BlockDevice for Nvme<'_, D> {
    fn block_size(&self) -> usize {
        1 << self.block_shift
    }

    fn num_blocks(&self) -> u64 {
        self.blocks
    }

    fn read_blocks(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        self.check_range(lba, buf.len())?;
        let len = buf.len();
        let drain = &mut |dma: &OwnedDma<'_, D>, off, range: Range<usize>| {
            if let Some(dst) = buf.get_mut(range) {
                dma.read(off, dst);
            }
        };
        self.pipeline(op::READ, lba, len, &mut |_, _, _| {}, drain)
    }

    fn write_blocks(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        self.check_range(lba, buf.len())?;
        let fill = &mut |dma: &OwnedDma<'_, D>, off, range: Range<usize>| {
            if let Some(src) = buf.get(range) {
                dma.write(off, src);
            }
        };
        self.pipeline(op::WRITE, lba, buf.len(), fill, &mut |_, _, _| {})
    }

    /// Writes back the controller's volatile cache; a no-op for controllers
    /// without one (they write through).
    fn flush(&mut self) -> Result<(), BlockError> {
        if !self.has_flush {
            return Ok(());
        }
        let sqe = command(op::FLUSH, self.nsid, 0, 0, 0);
        self.execute(true, sqe, 0).map(|_| ()).map_err(|_| BlockError::Io)
    }
}

impl<D: DmaAllocator + ?Sized> Drop for Nvme<'_, D> {
    fn drop(&mut self) {
        if self.io_queues {
            // The orderly way out; disabling deletes them anyway.
            let _ = self.admin(command(op::DELETE_SQ, 0, IO_QID as u32, 0, 0), 0);
            let _ = self.admin(command(op::DELETE_CQ, 0, IO_QID as u32, 0, 0), 0);
        }
        // Stop the controller before the queues and buffers are freed; if
        // it will not stop, leak them rather than let it write freed memory.
        if self.shutdown() {
            // SAFETY: `mem` is not used again.
            unsafe { ManuallyDrop::drop(&mut self.mem) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::{Cmd, Config, FIRMWARE, Fake, MODEL, Ns, SERIAL};
    use super::*;
    use crate::virtio::testing::HostDma;
    use core::sync::atomic::Ordering::Relaxed;
    use std::vec;
    use std::vec::Vec;

    /// Runs `body` while a controller thread serves `fake`.
    fn run<R>(fake: &Fake, body: impl FnOnce() -> R) -> R {
        struct Stop<'dev>(&'dev Fake);
        impl Drop for Stop<'_> {
            fn drop(&mut self) {
                self.0.stop();
            }
        }
        std::thread::scope(|s| {
            s.spawn(|| fake.serve());
            let _stop = Stop(fake);
            body()
        })
    }

    fn pattern(len: usize, seed: u8) -> Vec<u8> {
        (0..len).map(|i| (i as u8).wrapping_mul(7).wrapping_add(seed)).collect()
    }

    fn admin_ops(fake: &Fake) -> Vec<u8> {
        fake.commands().iter().filter(|c| c.qid == 0).map(|c| c.opcode).collect()
    }

    fn disk(fake: &Fake, i: usize) -> Vec<u8> {
        fake.namespaces.lock().unwrap()[i].data.clone()
    }

    #[test]
    fn init_identifies_controller_and_namespaces() {
        let cfg = Config { namespaces: vec![Ns::new(5, 12, 64), Ns::new(2, 9, 300)], ..Config::default() };
        let fake = Fake::new(cfg);
        let dma = HostDma::default();
        run(&fake, || {
            let mut nv = Nvme::new(fake.io(), &dma, &fake).unwrap();
            assert_eq!((nv.model(), nv.serial(), nv.firmware()), (MODEL, SERIAL, FIRMWARE));
            assert_eq!(nv.version(), 0x0001_0400);
            assert_eq!(nv.namespace(), 2, "the lowest active namespace");
            assert_eq!((nv.block_size(), nv.num_blocks()), (512, 300));
            assert_eq!(nv.max_transfer(), DATA_LEN, "MDTS of 512 KiB is past the buffer");
            assert!(nv.has_write_cache());
            assert_eq!(fake.reg(INTMS), u32::MAX, "interrupts masked");
            assert_eq!(dma.live.get(), 6);

            let mut ids = [0; 4];
            assert_eq!(nv.active_namespaces(&mut ids), Ok(2));
            assert_eq!(ids[..2], [2, 5]);
            assert_eq!(nv.active_namespaces(&mut ids[..1]), Ok(1));
            nv.select_namespace(5).unwrap();
            assert_eq!((nv.namespace(), nv.block_size(), nv.num_blocks()), (5, 4096, 64));
            assert_eq!(nv.select_namespace(3), Err(NvmeError::NoNamespace));
            assert_eq!(nv.select_namespace(0), Err(NvmeError::NoNamespace));
            assert_eq!(nv.namespace(), 5, "a failed selection changes nothing");
            let mut buf = [0u8; 4096];
            nv.read_blocks(63, &mut buf).unwrap();
            assert_eq!(buf[..], disk(&fake, 0)[63 * 4096..]);
            drop(nv);
            // Nothing runs on a disabled controller.
            assert_eq!(fake.reg(CC) & CC_EN, 0);
        });
        assert_eq!(dma.live.get(), 0);
        assert_eq!(fake.shutdowns.load(Relaxed), 1, "shut down normally");
        assert_eq!(fake.disables.load(Relaxed), 1);
        let ops = admin_ops(&fake);
        let setup = [op::IDENTIFY, op::SET_FEATURES, op::CREATE_CQ, op::CREATE_SQ, op::IDENTIFY, op::IDENTIFY];
        assert_eq!(ops[..6], setup);
        assert_eq!(ops[ops.len() - 2..], [op::DELETE_SQ, op::DELETE_CQ]);
        assert_eq!(fake.io_commands(), [Cmd::io(op::READ, 5, 63, 1, 0)]);
    }

    /// Brings up a controller configured by `tweak`; returns the namespace
    /// it serves, after checking that nothing leaked.
    fn probe(tweak: impl FnOnce(&mut Config)) -> Result<u32, NvmeError> {
        let mut cfg = Config::default();
        tweak(&mut cfg);
        let fake = Fake::new(cfg);
        let dma = HostDma::default();
        let r = run(&fake, || Nvme::new(fake.io(), &dma, &fake).map(|nv| nv.namespace()));
        assert_eq!(dma.live.get(), 0, "nothing leaks");
        if fake.disables.load(Relaxed) > 0 || matches!(r, Err(NvmeError::Timeout | NvmeError::Fatal)) {
            assert_eq!(fake.reg(CC) & CC_EN, 0, "left disabled");
        }
        r
    }

    #[test]
    fn init_failures() {
        assert_eq!(probe(|_| {}), Ok(1));
        assert_eq!(probe(|c| c.mqes = 0), Err(NvmeError::BadRegisters));
        assert_eq!(probe(|c| c.dstrd = 10), Err(NvmeError::BadRegisters), "doorbells past the window");
        assert_eq!(probe(|c| c.mpsmin = 1), Err(NvmeError::Unsupported));
        assert_eq!(probe(|c| c.css_nvm = false), Err(NvmeError::Unsupported));
        assert_eq!(probe(|c| c.never_ready = true), Err(NvmeError::Timeout));
        // Left enabling by firmware: it gets to finish before EN is cleared.
        assert_eq!(probe(|c| c.enabling = true), Ok(1));
        assert_eq!(probe(|c| c.fatal = true), Err(NvmeError::Fatal));
        assert_eq!(probe(|c| c.namespaces.clear()), Err(NvmeError::NoNamespace));
        assert_eq!(probe(|c| c.namespaces[0].ms = 8), Err(NvmeError::Unsupported), "metadata");
        assert_eq!(probe(|c| c.namespaces = vec![Ns::new(1, 13, 4)]), Err(NvmeError::Unsupported), "8 KiB blocks");
        // Before NVMe 1.1 there is no active namespace list: namespace 1 it is.
        let old = |c: &mut Config| c.version = 0x0001_0000;
        assert_eq!(probe(|c| (old(c), c.namespaces.push(Ns::new(3, 9, 8))).0), Ok(1));
        assert_eq!(probe(|c| (old(c), c.namespaces[0].nsid = 3).0), Err(NvmeError::NoNamespace));

        let fake = Fake::new(Config::default());
        let dma = HostDma::default();
        let small = fake.io().slice(0, DOORBELLS).unwrap();
        assert_eq!(Nvme::new(small, &dma, &fake).err(), Some(NvmeError::BadRegisters));
    }

    #[test]
    fn read_write_and_flush() {
        for lbads in [9, 12] {
            let bs = 1 << lbads;
            let fake = Fake::new(Config { namespaces: vec![Ns::new(1, lbads, 64)], ..Config::default() });
            let original = disk(&fake, 0);
            let new = pattern(2 * bs, 99);
            let dma = HostDma::default();
            run(&fake, || {
                let mut nv = Nvme::new(fake.io(), &dma, &fake).unwrap();
                assert_eq!(nv.block_size(), bs);
                let mut buf = vec![0u8; 2 * bs];
                nv.read_blocks(10, &mut buf).unwrap();
                assert_eq!(buf[..], original[10 * bs..12 * bs]);
                nv.write_blocks(20, &new).unwrap();
                nv.read_blocks(20, &mut buf).unwrap();
                assert_eq!(buf, new);
                nv.flush().unwrap();
                nv.read_blocks(0, &mut []).unwrap();
            });
            let after = disk(&fake, 0);
            assert_eq!(after[20 * bs..22 * bs], new[..]);
            assert_eq!(after[..20 * bs], original[..20 * bs], "nothing else touched");
            assert_eq!(after[22 * bs..], original[22 * bs..]);
            let expected = [
                Cmd::io(op::READ, 1, 10, 2, 0),
                Cmd::io(op::WRITE, 1, 20, 2, 0),
                Cmd::io(op::READ, 1, 20, 2, 0),
                Cmd::io(op::FLUSH, 1, 0, 0, 0),
            ];
            assert_eq!(fake.io_commands(), expected);
        }
    }

    #[test]
    fn flush_without_write_cache_is_a_no_op() {
        let fake = Fake::new(Config { vwc: false, ..Config::default() });
        let dma = HostDma::default();
        run(&fake, || {
            let mut nv = Nvme::new(fake.io(), &dma, &fake).unwrap();
            assert!(!nv.has_write_cache());
            assert_eq!(nv.flush(), Ok(()));
        });
        assert_eq!(fake.io_commands(), []);
    }

    #[test]
    fn prp_lists_and_split_transfers() {
        for mdts in [0, 1] {
            let fake = Fake::new(Config { mdts, namespaces: vec![Ns::new(1, 12, 64)], ..Config::default() });
            let data = pattern(39 * 4096, 3);
            let dma = HostDma::default();
            run(&fake, || {
                let mut nv = Nvme::new(fake.io(), &dma, &fake).unwrap();
                assert_eq!(nv.max_transfer(), if mdts == 0 { DATA_LEN } else { 8192 });
                // 3 pages, then 16 (a full buffer), then 20 (split).
                nv.write_blocks(0, &data[..3 * 4096]).unwrap();
                nv.write_blocks(3, &data[3 * 4096..19 * 4096]).unwrap();
                nv.write_blocks(19, &data[19 * 4096..]).unwrap();
                let mut back = vec![0u8; data.len()];
                nv.read_blocks(0, &mut back).unwrap();
                assert!(back == data);
            });
            assert!(disk(&fake, 0)[..data.len()] == data[..]);
            let log: Vec<(u8, u64, u32, usize)> =
                fake.io_commands().iter().map(|c| (c.opcode, c.cdw10 as u64, c.cdw12 + 1, c.list)).collect();
            // Each piece is at most the maximum transfer; beyond two pages,
            // PRP2 points to a list of all but the first.
            let max = if mdts == 0 { 16 } else { 2 };
            let split = |opcode, lba: u64, n: u32| {
                (0..n).step_by(max as usize).map(move |i| {
                    let k = max.min(n - i);
                    (opcode, lba + i as u64, k, if k > 2 { k as usize - 1 } else { 0 })
                })
            };
            let (w, r) = (op::WRITE, op::READ);
            let expected: Vec<_> =
                split(w, 0, 3).chain(split(w, 3, 16)).chain(split(w, 19, 20)).chain(split(r, 0, 39)).collect();
            if mdts == 0 {
                assert_eq!(log.iter().map(|c| c.3).collect::<Vec<_>>(), [2, 15, 15, 3, 15, 15, 6]);
            }
            assert_eq!(log, expected);
        }
    }

    /// Writes and reads back 40 blocks of 4 KiB in 8 KiB commands, 20 pieces
    /// each way, and checks the controller saw them several at a time.
    fn pipelined_roundtrip(fake: &Fake, nv: &mut Nvme<'_, HostDma>) -> Vec<u8> {
        let data = pattern(40 * 4096, 11);
        nv.write_blocks(0, &data).unwrap();
        let mut back = vec![0u8; data.len()];
        nv.read_blocks(0, &mut back).unwrap();
        assert!(back == data, "every piece landed in its own place");
        assert!(disk(fake, 0)[..data.len()] == data[..]);
        data
    }

    #[test]
    fn several_commands_in_flight() {
        for (mqes, stray, reorder) in [(2047, false, false), (2047, true, true), (3, false, true), (1, true, true)] {
            let ns = vec![Ns::new(1, 12, 64)];
            let fake = Fake::new(Config { mdts: 1, mqes, stray, reorder, namespaces: ns, ..Config::default() });
            let dma = HostDma::default();
            run(&fake, || {
                let mut nv = Nvme::new(fake.io(), &dma, &fake).unwrap();
                assert!(!nv.interrupt_driven());
                let window = nv.queue_depth();
                // IO_DEPTH 16 entries, or mqes + 1; one entry stays empty.
                assert_eq!(window, SLOTS.min((mqes as usize + 1).min(IO_DEPTH as usize) - 1));
                pipelined_roundtrip(&fake, &mut nv);
                assert_eq!(fake.max_inflight.load(Relaxed) as usize, window, "mqes {mqes}");
                assert_eq!(fake.cq_flags.load(Relaxed), 1, "no interrupts");
                assert_eq!(fake.signal.count(), 0);
            });
            assert_eq!(fake.io_commands().len(), 40);
            assert_eq!(dma.live.get(), 0);
        }
    }

    #[test]
    fn completions_by_interrupt() {
        for reorder in [false, true] {
            let ns = vec![Ns::new(1, 12, 64)];
            let fake = Fake::new(Config { mdts: 1, reorder, namespaces: ns, ..Config::default() });
            let dma = HostDma::default();
            let idles = AtomicU32::new(0);
            let idle = || {
                idles.fetch_add(1, Relaxed);
                std::thread::yield_now();
            };
            let irq = Interrupts { vector: 5, signal: &fake.signal, idle: &idle };
            run(&fake, || {
                let mut nv = Nvme::with_interrupts(fake.io(), &dma, &fake, irq).unwrap();
                assert!(nv.interrupt_driven());
                assert_eq!(fake.cq_flags.load(Relaxed), QUEUE_PC | QUEUE_IEN | 5 << 16, "IEN and vector 5");
                assert_eq!(fake.reg(INTMS), 0, "INTMS is for pin interrupts; MSI-X leaves it alone");
                assert_eq!(fake.signal.count(), 0, "admin completions raise nothing here");
                pipelined_roundtrip(&fake, &mut nv);
                assert_eq!(fake.max_inflight.load(Relaxed) as usize, SLOTS);
                nv.flush().unwrap();
            });
            assert_eq!(fake.signal.count() as usize, fake.io_commands().len(), "one interrupt per completion");
            assert_eq!(dma.live.get(), 0);
        }
    }

    #[test]
    fn a_failed_piece_drains_the_rest() {
        let fake =
            Fake::new(Config { mdts: 1, bad_from: 6, namespaces: vec![Ns::new(1, 12, 64)], ..Config::default() });
        let dma = HostDma::default();
        run(&fake, || {
            let mut nv = Nvme::new(fake.io(), &dma, &fake).unwrap();
            let mut buf = vec![0u8; 20 * 4096];
            assert_eq!(nv.read_blocks(0, &mut buf), Err(BlockError::Io));
            // Nothing is left in flight: the next request starts clean.
            let mut small = vec![0u8; 4 * 4096];
            nv.read_blocks(0, &mut small).unwrap();
            assert!(small[..] == disk(&fake, 0)[..4 * 4096]);
            assert_eq!(nv.write_blocks(0, &buf), Err(BlockError::Io));
        });
        let sent = fake.io_commands().len();
        assert!(sent < 3 * 10 + 2, "submission stopped after the failure: {sent} commands");
        assert_eq!(dma.live.get(), 0);
    }

    #[test]
    fn a_lost_piece_stops_the_driver() {
        let fake = Fake::new(Config { mdts: 1, ignore_io: true, ..Config::default() });
        let dma = HostDma::default();
        run(&fake, || {
            let mut nv = Nvme::new(fake.io(), &dma, &fake).unwrap();
            let mut buf = vec![0u8; 8 * 8192];
            assert_eq!(nv.read_blocks(0, &mut buf), Err(BlockError::Io));
            assert_eq!(nv.read_blocks(0, &mut buf), Err(BlockError::Io));
        });
        // A full window went out at once, but the driver may give up (the clock jumps an hour at the first
        // command) before the controller has looked at all of it. Nothing is submitted after.
        assert!((1..=SLOTS).contains(&fake.io_commands().len()));
        assert_eq!(fake.reg(CC) & CC_EN, 0);
        assert_eq!(dma.live.get(), 0);
    }

    #[test]
    fn queues_wrap_around() {
        for stray in [false, true] {
            // Four-entry I/O queues, and 16-byte doorbell spacing.
            let fake = Fake::new(Config { mqes: 3, dstrd: 2, stray, ..Config::default() });
            let dma = HostDma::default();
            run(&fake, || {
                let mut nv = Nvme::new(fake.io(), &dma, &fake).unwrap();
                assert_eq!(nv.mem.io.depth(), 4);
                for i in 0..50u64 {
                    let block = pattern(512, i as u8);
                    nv.write_blocks(i, &block).unwrap();
                    let mut back = [0u8; 512];
                    nv.read_blocks(i, &mut back).unwrap();
                    assert_eq!(back[..], block[..], "block {i}");
                }
                // The admin queue wraps too.
                for _ in 0..3 * ADMIN_DEPTH {
                    let mut ids = [0; 2];
                    assert_eq!(nv.active_namespaces(&mut ids), Ok(1));
                }
            });
            assert_eq!(fake.io_commands().len(), 100);
            assert_eq!(dma.live.get(), 0);
        }
    }

    #[test]
    fn device_errors_and_range_checks() {
        let cfg = Config { bad_from: 6, reject_flush: true, namespaces: vec![Ns::new(1, 9, 8)], ..Config::default() };
        let fake = Fake::new(cfg);
        let dma = HostDma::default();
        run(&fake, || {
            let mut nv = Nvme::new(fake.io(), &dma, &fake).unwrap();
            let mut buf = [0u8; 512];
            assert_eq!(nv.read_blocks(6, &mut buf), Err(BlockError::Io));
            assert_eq!(nv.write_blocks(7, &buf), Err(BlockError::Io));
            assert_eq!(nv.flush(), Err(BlockError::Io));
            // The driver recovers: later commands still work.
            assert_eq!(nv.read_blocks(5, &mut buf), Ok(()));
            assert_eq!(buf[..], disk(&fake, 0)[5 * 512..6 * 512]);

            assert_eq!(nv.read_blocks(8, &mut buf), Err(BlockError::OutOfRange));
            assert_eq!(nv.write_blocks(7, &[0; 1024]), Err(BlockError::OutOfRange));
            assert_eq!(nv.read_blocks(u64::MAX, &mut buf), Err(BlockError::OutOfRange));
            assert_eq!(nv.read_blocks(0, &mut [0; 100]), Err(BlockError::BadBuffer));
            // Admin errors carry the status.
            let bad = nv.admin(command(0x7f, 0, 0, 0, 0), 0);
            assert_eq!(bad, Err(NvmeError::Command { opcode: 0x7f, sct: 0, sc: 1 }));
            assert_eq!(nv.read_blocks(0, &mut buf), Ok(()));
        });
        assert_eq!(fake.io_commands().len(), 5, "rejected requests never reach the controller");
    }

    #[test]
    fn a_lost_command_stops_the_driver() {
        let fake = Fake::new(Config { ignore_io: true, ..Config::default() });
        let dma = HostDma::default();
        run(&fake, || {
            let mut nv = Nvme::new(fake.io(), &dma, &fake).unwrap();
            let mut buf = [0u8; 512];
            assert_eq!(nv.read_blocks(0, &mut buf), Err(BlockError::Io));
            assert_eq!(nv.read_blocks(1, &mut buf), Err(BlockError::Io));
            assert_eq!(nv.flush(), Err(BlockError::Io));
            let mut ids = [0];
            assert_eq!(nv.active_namespaces(&mut ids), Err(NvmeError::Timeout));
        });
        assert_eq!(fake.io_commands().len(), 1, "nothing more was submitted");
        assert_eq!(fake.reg(CC) & CC_EN, 0, "the controller is disabled");
        assert_eq!(dma.live.get(), 0, "and once it stopped, its memory is freed");
    }

    #[test]
    fn a_slow_flush_is_not_lost() {
        // A minute: past the command timeout, within the flush timeout.
        let fake = Fake::new(Config { io_delay_ns: 60_000_000_000, ..Config::default() });
        let dma = HostDma::default();
        run(&fake, || {
            let mut nv = Nvme::new(fake.io(), &dma, &fake).unwrap();
            assert_eq!(nv.flush(), Ok(()));
            assert_eq!(nv.flush(), Ok(()));
            // A read that slow is lost, and stops the driver.
            let mut buf = [0u8; 512];
            assert_eq!(nv.read_blocks(0, &mut buf), Err(BlockError::Io));
            assert_eq!(nv.flush(), Err(BlockError::Io));
        });
        assert_eq!(fake.io_commands().len(), 3);
        assert_eq!(dma.live.get(), 0);
    }

    #[test]
    fn a_fatal_controller_fails_commands_at_once() {
        let fake = Fake::new(Config { fatal_io: true, ..Config::default() });
        let dma = HostDma::default();
        run(&fake, || {
            let mut nv = Nvme::new(fake.io(), &dma, &fake).unwrap();
            let start = fake.now_ns();
            let mut buf = [0u8; 512];
            assert_eq!(nv.read_blocks(0, &mut buf), Err(BlockError::Io));
            assert!(fake.now_ns() - start < COMMAND_TIMEOUT_NS, "without waiting for the timeout");
            let mut ids = [0];
            assert_eq!(nv.active_namespaces(&mut ids), Err(NvmeError::Fatal));
        });
        assert_eq!(fake.io_commands().len(), 1, "nothing more was submitted");
        assert_eq!(fake.reg(CC) & CC_EN, 0, "the controller is disabled");
        assert_eq!(dma.live.get(), 0);
    }

    #[test]
    fn more_and_do_not_retry_are_not_failures() {
        let fake = Fake::new(Config { status_flags: true, bad_from: 6, ..Config::default() });
        let dma = HostDma::default();
        run(&fake, || {
            let mut nv = Nvme::new(fake.io(), &dma, &fake).unwrap();
            let mut buf = [0u8; 512];
            nv.read_blocks(5, &mut buf).unwrap();
            assert_eq!(buf[..], disk(&fake, 0)[5 * 512..6 * 512]);
            assert_eq!(nv.read_blocks(6, &mut buf), Err(BlockError::Io));
            let bad = nv.admin(command(0x7f, 0, 0, 0, 0), 0);
            assert_eq!(bad, Err(NvmeError::Command { opcode: 0x7f, sct: 0, sc: 1 }));
            nv.flush().unwrap();
        });
    }
}
