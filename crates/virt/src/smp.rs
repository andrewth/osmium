//! The CPUs of a multi-vCPU guest: start/stop state, IPI and remote-fence
//! lines, and kicks of vCPUs running on other host CPUs.
//!
//! The state numbering matches both SBI HSM `hart_get_status` and PSCI
//! `AFFINITY_INFO` (0 on, 1 off, 2 on pending).

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use osmium_sync::IrqSpinLock;

/// CPU states (SBI HSM and PSCI `AFFINITY_INFO` use the same values).
pub mod status {
    /// Running.
    pub const STARTED: u64 = 0;
    /// Not running; can be started.
    pub const STOPPED: u64 = 1;
    /// A start was requested and the CPU has not run yet.
    pub const START_PENDING: u64 = 2;
}

struct Slot {
    state: AtomicU64,
    start: IrqSpinLock<Option<(u64, u64)>>,
    ipi: Arc<AtomicBool>,
    /// A remote fence (SBI RFENCE) is due before the hart runs again.
    fence: Arc<AtomicBool>,
    /// Host CPU the hart's vCPU is running guest code on, or `usize::MAX`.
    running: Arc<AtomicUsize>,
}

/// How long a remote fence waits for a running hart to take it.
const FENCE_SPINS: u32 = 50_000_000;

/// Not in the guest.
pub(crate) const NOT_RUNNING: usize = usize::MAX;

type Kick = Box<dyn Fn(usize) + Send + Sync>;

/// Why a CPU could not be started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartError {
    /// There is no such CPU.
    NoSuchCpu,
    /// It is running.
    AlreadyOn,
    /// A start was already requested and has not happened yet.
    Pending,
}

/// Shared state for a guest's CPUs. Each vCPU's host task takes start
/// requests with [`take_start`](Self::take_start) and connects its vCPU
/// (`attach` on RISC-V, [`attach_arm`](Self::attach_arm) on AArch64); the
/// guest's firmware calls (`riscv::sbi::handle_smp`,
/// `aarch64::psci::handle_smp`) start, stop, query and signal CPUs through
/// it.
pub struct GuestCpus {
    slots: Vec<Slot>,
    kick: Option<Kick>,
}

impl GuestCpus {
    /// `n` harts, all stopped.
    pub fn new(n: usize) -> Arc<Self> {
        Arc::new(Self::build(n, None))
    }

    /// Like [`new`](Self::new), with a way to interrupt host CPU `cpu`
    /// (usually a host IPI). An IPI to a hart whose vCPU is running guest
    /// code on another host CPU then kicks that CPU, so the vCPU exits and
    /// sees the interrupt at once instead of at its next exit.
    pub fn with_kick(n: usize, kick: impl Fn(usize) + Send + Sync + 'static) -> Arc<Self> {
        Arc::new(Self::build(n, Some(Box::new(kick))))
    }

    fn build(n: usize, kick: Option<Kick>) -> Self {
        let slots = (0..n)
            .map(|_| Slot {
                state: AtomicU64::new(status::STOPPED),
                start: IrqSpinLock::new(None),
                ipi: Arc::new(AtomicBool::new(false)),
                fence: Arc::new(AtomicBool::new(false)),
                running: Arc::new(AtomicUsize::new(NOT_RUNNING)),
            })
            .collect();
        Self { slots, kick }
    }

    /// Connects a RISC-V vCPU as hart `hart`: its IPI line, its remote-fence
    /// line, and the record of which host CPU it runs on (for kicks).
    /// Does nothing if there is no such hart.
    pub fn attach(&self, hart: usize, vcpu: &mut crate::riscv::RiscvVcpu) {
        let Some(slot) = self.slots.get(hart) else { return };
        vcpu.connect_ipi(slot.ipi.clone());
        vcpu.running = Some(slot.running.clone());
        vcpu.fence = Some(slot.fence.clone());
    }

    /// Number of harts.
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// Whether there are no harts.
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Asks a stopped CPU to start at `entry` with `opaque` as its
    /// argument (SBI `hart_start`, PSCI `CPU_ON`).
    pub fn request_start(&self, cpu: usize, entry: u64, opaque: u64) -> Result<(), StartError> {
        let slot = self.slots.get(cpu).ok_or(StartError::NoSuchCpu)?;
        slot.state
            .compare_exchange(status::STOPPED, status::START_PENDING, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|s| if s == status::START_PENDING { StartError::Pending } else { StartError::AlreadyOn })?;
        *slot.start.lock() = Some((entry, opaque));
        Ok(())
    }

    /// Kicks the host CPU that `cpu`'s vCPU is running guest code on, if
    /// any (and not this one), so it exits and looks at its lines.
    pub fn kick(&self, cpu: usize) {
        let Some(s) = self.slots.get(cpu) else { return };
        let host = s.running.load(Ordering::Acquire);
        if let Some(kick) = &self.kick
            && host != NOT_RUNNING
            && host != osmium_arch::cpu::current_id()
        {
            kick(host);
        }
    }

    /// Connects an AArch64 vCPU as CPU `cpu`, so kicks find it.
    pub fn attach_arm(&self, cpu: usize, vcpu: &mut crate::aarch64::Aarch64Vcpu) {
        if let Some(slot) = self.slots.get(cpu) {
            vcpu.running = Some(slot.running.clone());
        }
    }

    /// Connects an SVM vCPU as CPU `cpu`, so kicks find it.
    pub fn attach_svm(&self, cpu: usize, vcpu: &mut crate::x86::svm::SvmVcpu) {
        if let Some(slot) = self.slots.get(cpu) {
            vcpu.running = Some(slot.running.clone());
        }
    }

    /// Connects a VMX vCPU as CPU `cpu`, so kicks find it.
    pub fn attach_vmx(&self, cpu: usize, vcpu: &mut crate::x86::vmx::VmxVcpu) {
        if let Some(slot) = self.slots.get(cpu) {
            vcpu.running = Some(slot.running.clone());
        }
    }

    /// Takes hart `hart`'s pending start request (entry, opaque), marking it
    /// started; `None` if there is none.
    pub fn take_start(&self, hart: usize) -> Option<(u64, u64)> {
        let slot = self.slots.get(hart)?;
        let req = slot.start.lock().take()?;
        slot.state.store(status::STARTED, Ordering::Release);
        Some(req)
    }

    /// Marks `hart` stopped (after SBI `hart_stop`).
    pub fn stopped(&self, hart: usize) {
        if let Some(s) = self.slots.get(hart) {
            s.state.store(status::STOPPED, Ordering::Release);
        }
    }

    /// The HSM status of `hart`.
    pub fn status(&self, hart: usize) -> Option<u64> {
        self.slots.get(hart).map(|s| s.state.load(Ordering::Acquire))
    }

    /// `hart`'s software-interrupt line, for its vCPU (a detached line if
    /// there is no such hart).
    pub fn ipi_line(&self, hart: usize) -> Arc<AtomicBool> {
        self.slots.get(hart).map_or_else(|| Arc::new(AtomicBool::new(false)), |s| s.ipi.clone())
    }

    /// Raises the software interrupt of every hart in `mask` (bit `i` =
    /// hart `base + i`; `base` = `u64::MAX` means all harts).
    pub fn send_ipi(&self, mask: u64, base: u64) -> Result<(), i64> {
        self.each(mask, base, |s| s.ipi.store(true, Ordering::Release));
        Ok(())
    }

    /// Makes every hart in `mask` execute `fence.i` and flush its guest
    /// TLB (`hfence.vvma` for the VM) before it next runs guest code: SBI
    /// RFENCE `remote_fence_i` and `remote_sfence_vma[_asid]`, done
    /// conservatively for the whole address space.
    ///
    /// Returns once every target running guest code has taken the request
    /// (it leaves the guest through the kick and flushes before re-entering),
    /// as SBI requires the fence to be done on return. A target outside the
    /// guest flushes before it next enters, so it is not waited for. The wait
    /// is bounded, for a target that cannot be kicked.
    pub fn remote_fence(&self, mask: u64, base: u64) -> Result<(), i64> {
        self.each(mask, base, |s| s.fence.store(true, Ordering::SeqCst));
        // Pairs with the vCPU storing `running` and then taking the flag.
        core::sync::atomic::fence(Ordering::SeqCst);
        let me = osmium_arch::cpu::current_id();
        for (i, s) in self.slots.iter().enumerate() {
            if !self.selected(i, mask, base) {
                continue;
            }
            let mut spins = 0u32;
            while s.fence.load(Ordering::Acquire) {
                let host = s.running.load(Ordering::SeqCst);
                if host == NOT_RUNNING || host == me || spins >= FENCE_SPINS {
                    break;
                }
                if spins % 1024 == 0 {
                    self.kick(i);
                }
                spins += 1;
                core::hint::spin_loop();
            }
        }
        Ok(())
    }

    fn selected(&self, i: usize, mask: u64, base: u64) -> bool {
        base == u64::MAX || (i as u64).checked_sub(base).is_some_and(|b| b < 64 && mask & (1 << b) != 0)
    }

    /// Applies `f` to the harts selected by `mask`/`base`, kicking those
    /// running on another host CPU so they notice now.
    fn each(&self, mask: u64, base: u64, f: impl Fn(&Slot)) {
        for (i, s) in self.slots.iter().enumerate() {
            if self.selected(i, mask, base) {
                f(s);
                self.kick(i);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_stop_ipi() {
        let h = GuestCpus::new(3);
        assert_eq!(h.status(1), Some(status::STOPPED));
        assert_eq!(h.take_start(1), None);
        h.request_start(1, 0x8000_0000, 7).unwrap();
        assert_eq!(h.status(1), Some(status::START_PENDING));
        assert_eq!(h.request_start(1, 0, 0), Err(StartError::Pending));
        assert_eq!(h.take_start(1), Some((0x8000_0000, 7)));
        assert_eq!(h.status(1), Some(status::STARTED));
        assert_eq!(h.request_start(1, 0, 0), Err(StartError::AlreadyOn));
        h.stopped(1);
        assert_eq!(h.status(1), Some(status::STOPPED));
        assert_eq!(h.request_start(5, 0, 0), Err(StartError::NoSuchCpu));

        h.send_ipi(0b10, 1).unwrap();
        assert!(!h.ipi_line(0).load(Ordering::SeqCst));
        assert!(!h.ipi_line(1).load(Ordering::SeqCst));
        assert!(h.ipi_line(2).load(Ordering::SeqCst));
        h.send_ipi(0, u64::MAX).unwrap();
        assert!(h.ipi_line(0).load(Ordering::SeqCst));
    }

    #[test]
    fn kicks_running_harts_only() {
        let kicked = Arc::new(AtomicUsize::new(NOT_RUNNING));
        let k = kicked.clone();
        let h = GuestCpus::with_kick(2, move |cpu| k.store(cpu, Ordering::SeqCst));
        h.send_ipi(0b10, 0).unwrap();
        assert_eq!(kicked.load(Ordering::SeqCst), NOT_RUNNING, "hart 1 is not in the guest");
        h.slots[1].running.store(3, Ordering::SeqCst);
        h.send_ipi(0b10, 0).unwrap();
        assert_eq!(kicked.load(Ordering::SeqCst), 3);
        kicked.store(NOT_RUNNING, Ordering::SeqCst);
        h.remote_fence(0b10, 0).unwrap();
        assert_eq!(kicked.load(Ordering::SeqCst), 3, "fences kick too");
        assert!(h.slots[1].fence.load(Ordering::SeqCst));
        assert!(!h.slots[0].fence.load(Ordering::SeqCst));
    }

    #[test]
    fn remote_fence_waits_for_a_running_hart() {
        let h = GuestCpus::new(2);
        // Not in the guest: returns at once, the request stays for the next entry.
        h.remote_fence(0b10, 0).unwrap();
        assert!(h.slots[1].fence.load(Ordering::SeqCst));
        h.slots[1].fence.store(false, Ordering::SeqCst);

        // Running on another host CPU: waits until it takes the request.
        h.slots[1].running.store(usize::MAX - 1, Ordering::SeqCst);
        let fence = h.slots[1].fence.clone();
        let taken = Arc::new(AtomicBool::new(false));
        let t = taken.clone();
        let th = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            t.store(true, Ordering::SeqCst);
            fence.store(false, Ordering::SeqCst);
        });
        h.remote_fence(0b10, 0).unwrap();
        assert!(taken.load(Ordering::SeqCst), "returned before the hart took the fence");
        th.join().unwrap();
    }
}
