//! PSCI for guests: version, features and power off, and with
//! [`GuestCpus`] the SMP calls (`CPU_ON`, `CPU_OFF`, `AFFINITY_INFO`).

use super::Aarch64Vcpu;
use crate::smp::{GuestCpus, StartError};
use crate::vcpu::{Vcpu, VmExit};

/// `PSCI_VERSION`.
pub const VERSION: u64 = 0x8400_0000;
/// `CPU_ON` (SMC64).
pub const CPU_ON: u64 = 0xc400_0003;
/// `SYSTEM_OFF`.
pub const SYSTEM_OFF: u64 = 0x8400_0008;
/// `SYSTEM_RESET`.
pub const SYSTEM_RESET: u64 = 0x8400_0009;
/// `PSCI_FEATURES`.
pub const FEATURES: u64 = 0x8400_000a;
/// `CPU_OFF`.
pub const CPU_OFF: u64 = 0x8400_0002;
/// `AFFINITY_INFO` (SMC64).
pub const AFFINITY_INFO: u64 = 0xc400_0004;
/// PSCI `INVALID_PARAMETERS`.
pub const INVALID_PARAMETERS: i64 = -2;
/// PSCI `ALREADY_ON`.
pub const ALREADY_ON: i64 = -4;

/// PSCI `NOT_SUPPORTED`.
pub const NOT_SUPPORTED: i64 = -1;

/// What the caller should do after [`handle`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The call was answered; keep running the guest.
    Continue,
    /// The guest asked to power off or reset.
    Shutdown,
    /// This CPU turned itself off (`CPU_OFF`): stop running its vCPU until
    /// [`GuestCpus::take_start`] yields a new start request.
    Stop,
}

/// Answers the PSCI (or other SMCCC) call in `exit`. Unknown functions
/// return `NOT_SUPPORTED`. Returns `None` for other exits.
pub fn handle(vcpu: &mut Aarch64Vcpu, exit: VmExit) -> Option<Outcome> {
    handle_smp(vcpu, exit, None)
}

/// Like [`handle`], and with `cpus` = (the guest's CPUs, this vCPU's
/// index) also answers `CPU_ON` (target by MPIDR affinity 0, which this
/// takes to be the CPU index), `CPU_OFF` and `AFFINITY_INFO`.
pub fn handle_smp(vcpu: &mut Aarch64Vcpu, exit: VmExit, cpus: Option<(&GuestCpus, usize)>) -> Option<Outcome> {
    let VmExit::Hypercall { nr, args } = exit else { return None };
    let ret = match nr & 0xffff_ffff {
        CPU_ON if let Some((c, _)) = cpus => match c.request_start((args[0] & 0xff) as usize, args[1], args[2]) {
            Ok(()) => 0,
            Err(StartError::NoSuchCpu) => INVALID_PARAMETERS as u64,
            Err(StartError::AlreadyOn) => ALREADY_ON as u64,
        },
        CPU_OFF if let Some((c, me)) = cpus => {
            c.stopped(me);
            return Some(Outcome::Stop);
        }
        AFFINITY_INFO if let Some((c, _)) = cpus => {
            c.status((args[0] & 0xff) as usize).unwrap_or(INVALID_PARAMETERS as u64)
        }
        VERSION => 0x1_0001, // 1.1
        SYSTEM_OFF | SYSTEM_RESET => return Some(Outcome::Shutdown),
        FEATURES => match args[0] {
            VERSION | SYSTEM_OFF | SYSTEM_RESET | FEATURES => 0,
            CPU_ON | CPU_OFF | AFFINITY_INFO if cpus.is_some() => 0,
            _ => NOT_SUPPORTED as u64,
        },
        _ => NOT_SUPPORTED as u64,
    };
    vcpu.complete_hypercall(ret);
    Some(Outcome::Continue)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::GuestPhysAddr;

    #[test]
    fn calls() {
        let mut v = Aarch64Vcpu::new(GuestPhysAddr(0), 0, 0);
        let call = |v: &mut Aarch64Vcpu, nr, a0| handle(v, VmExit::Hypercall { nr, args: [a0, 0, 0, 0, 0, 0] });
        assert_eq!(call(&mut v, VERSION, 0), Some(Outcome::Continue));
        assert_eq!(v.state.x[0], 0x1_0001);
        call(&mut v, FEATURES, SYSTEM_OFF);
        assert_eq!(v.state.x[0], 0);
        call(&mut v, FEATURES, CPU_ON);
        assert_eq!(v.state.x[0] as i64, NOT_SUPPORTED);
        call(&mut v, CPU_ON, 1);
        assert_eq!(v.state.x[0] as i64, NOT_SUPPORTED);
        assert_eq!(call(&mut v, SYSTEM_OFF, 0), Some(Outcome::Shutdown));
        assert_eq!(handle(&mut v, VmExit::Halt), None);

        // With CPUs: start CPU 1, query it, turn this one off.
        let cpus = GuestCpus::new(2);
        let smp = |v: &mut Aarch64Vcpu, nr, a: [u64; 6]| handle_smp(v, VmExit::Hypercall { nr, args: a }, Some((&cpus, 0)));
        smp(&mut v, CPU_ON, [1, 0x4000_0100, 7, 0, 0, 0]);
        assert_eq!(v.state.x[0], 0);
        smp(&mut v, CPU_ON, [1, 0, 0, 0, 0, 0]);
        assert_eq!(v.state.x[0] as i64, ALREADY_ON);
        smp(&mut v, AFFINITY_INFO, [1, 0, 0, 0, 0, 0]);
        assert_eq!(v.state.x[0], crate::smp::status::START_PENDING);
        assert_eq!(cpus.take_start(1), Some((0x4000_0100, 7)));
        assert_eq!(smp(&mut v, CPU_OFF, [0; 6]), Some(Outcome::Stop));
        assert_eq!(cpus.status(0), Some(crate::smp::status::STOPPED));
    }
}
