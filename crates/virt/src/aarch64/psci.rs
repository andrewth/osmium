//! PSCI for a single-vCPU guest: version, features and power off.

use super::Aarch64Vcpu;
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

/// PSCI `NOT_SUPPORTED`.
pub const NOT_SUPPORTED: i64 = -1;

/// What the caller should do after [`handle`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The call was answered; keep running the guest.
    Continue,
    /// The guest asked to power off or reset.
    Shutdown,
}

/// Answers the PSCI (or other SMCCC) call in `exit`. Unknown functions
/// return `NOT_SUPPORTED`. Returns `None` for other exits.
pub fn handle(vcpu: &mut Aarch64Vcpu, exit: VmExit) -> Option<Outcome> {
    let VmExit::Hypercall { nr, args } = exit else { return None };
    let ret = match nr & 0xffff_ffff {
        VERSION => 0x1_0001, // 1.1
        SYSTEM_OFF | SYSTEM_RESET => return Some(Outcome::Shutdown),
        FEATURES => match args[0] {
            VERSION | SYSTEM_OFF | SYSTEM_RESET | FEATURES => 0,
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
    }
}
