//! A minimal SBI implementation for guests: enough for a console, a timer
//! and shutdown.

use alloc::vec;

use super::RiscvVcpu;
use crate::memory::{GuestMemory, GuestPhysAddr};
use crate::vcpu::VmExit;

/// SBI extension IDs.
pub mod eid {
    /// Legacy `sbi_set_timer`.
    pub const LEGACY_SET_TIMER: u64 = 0x00;
    /// Legacy `sbi_console_putchar`.
    pub const LEGACY_PUTCHAR: u64 = 0x01;
    /// Legacy `sbi_console_getchar`.
    pub const LEGACY_GETCHAR: u64 = 0x02;
    /// Legacy `sbi_shutdown`.
    pub const LEGACY_SHUTDOWN: u64 = 0x08;
    /// Base extension.
    pub const BASE: u64 = 0x10;
    /// Timer extension ("TIME").
    pub const TIME: u64 = 0x5449_4d45;
    /// System reset ("SRST").
    pub const SRST: u64 = 0x5352_5354;
    /// Debug console ("DBCN").
    pub const DBCN: u64 = 0x4442_434e;
}

/// SBI error: the call is not supported.
pub const ERR_NOT_SUPPORTED: i64 = -2;
/// SBI error: an invalid parameter.
pub const ERR_INVALID_PARAM: i64 = -3;

/// SBI implementation ID reported to the guest (0x4f53 = "OS").
pub const IMPL_ID: u64 = 0x4f53;

/// What the caller should do after [`handle`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The call was answered; keep running the guest.
    Continue,
    /// The guest asked to power off or reset.
    Shutdown,
}

/// Answers the SBI call in `exit` (a [`VmExit::Hypercall`] from `vcpu`).
/// Console output goes to `console`. Unknown calls return
/// `SBI_ERR_NOT_SUPPORTED` to the guest. Returns `None` for other exits.
pub fn handle(vcpu: &mut RiscvVcpu, mem: &GuestMemory, exit: VmExit, console: &mut dyn FnMut(&[u8])) -> Option<Outcome> {
    let VmExit::Hypercall { nr, args } = exit else { return None };
    let (eid, fid) = (nr & 0xffff_ffff, nr >> 32);
    // Legacy calls return only a0, so they leave a1 as it was.
    let a1 = vcpu.state.x[11];
    let (error, value) = match (eid, fid) {
        (eid::LEGACY_SET_TIMER, _) | (eid::TIME, 0) => {
            vcpu.csrs.vstimecmp = args[0];
            (0, a1)
        }
        (eid::LEGACY_PUTCHAR, _) => {
            console(&[args[0] as u8]);
            (0, a1)
        }
        (eid::LEGACY_GETCHAR, _) => (-1, a1),
        (eid::LEGACY_SHUTDOWN, _) | (eid::SRST, 0) => return Some(Outcome::Shutdown),
        (eid::BASE, 0) => (0, 2 << 24), // SBI 2.0
        (eid::BASE, 1) => (0, IMPL_ID),
        (eid::BASE, 2) => (0, 1),
        (eid::BASE, 3) => {
            let supported = matches!(
                args[0],
                eid::BASE
                    | eid::TIME
                    | eid::SRST
                    | eid::DBCN
                    | eid::LEGACY_SET_TIMER
                    | eid::LEGACY_PUTCHAR
                    | eid::LEGACY_GETCHAR
                    | eid::LEGACY_SHUTDOWN
            );
            (0, supported as u64)
        }
        (eid::BASE, 4..=6) => (0, 0), // mvendorid, marchid, mimpid
        (eid::DBCN, 0) => {
            // write(num_bytes, base_lo, base_hi): a guest-physical buffer.
            let gpa = GuestPhysAddr(args[1] | args[2] << 32);
            let mut buf = vec![0u8; args[0].min(4096) as usize];
            match mem.read(gpa, &mut buf) {
                Ok(()) => {
                    console(&buf);
                    (0, buf.len() as u64)
                }
                Err(_) => (ERR_INVALID_PARAM, 0),
            }
        }
        (eid::DBCN, 1) => (0, 0), // read: no input
        (eid::DBCN, 2) => {
            console(&[args[0] as u8]);
            (0, 0)
        }
        _ => (ERR_NOT_SUPPORTED, 0),
    };
    vcpu.complete_sbi(error, value);
    Some(Outcome::Continue)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn call(v: &mut RiscvVcpu, mem: &GuestMemory, eid: u64, fid: u64, args: [u64; 6], out: &mut Vec<u8>) -> Option<Outcome> {
        handle(v, mem, VmExit::Hypercall { nr: eid | fid << 32, args }, &mut |b| out.extend_from_slice(b))
    }

    #[test]
    fn console_timer_probe_shutdown() {
        let mut ram = vec![0u8; 0x1000];
        let mut mem = GuestMemory::new();
        // SAFETY: `ram` outlives `mem` and is only used through it.
        unsafe { mem.add_region(GuestPhysAddr(0x8000_0000), ram.as_mut_ptr(), 0x1000) };
        mem.write(GuestPhysAddr(0x8000_0100), b"hello").unwrap();
        let mut v = RiscvVcpu::new(GuestPhysAddr(0x8000_0000), 0, 0, 0);
        let mut out = Vec::new();

        assert_eq!(call(&mut v, &mem, eid::DBCN, 0, [5, 0x8000_0100, 0, 0, 0, 0], &mut out), Some(Outcome::Continue));
        assert_eq!((v.state.x[10], v.state.x[11]), (0, 5));
        call(&mut v, &mem, eid::LEGACY_PUTCHAR, 0, [b'!' as u64, 0, 0, 0, 0, 0], &mut out);
        assert_eq!(out, b"hello!");
        call(&mut v, &mem, eid::DBCN, 0, [4, 0x9000_0000, 0, 0, 0, 0], &mut out);
        assert_eq!(v.state.x[10] as i64, ERR_INVALID_PARAM);

        call(&mut v, &mem, eid::TIME, 0, [12345, 0, 0, 0, 0, 0], &mut out);
        assert_eq!(v.csrs.vstimecmp, 12345);

        call(&mut v, &mem, eid::BASE, 3, [eid::DBCN, 0, 0, 0, 0, 0], &mut out);
        assert_eq!(v.state.x[11], 1);
        call(&mut v, &mem, eid::BASE, 3, [0x48_534d, 0, 0, 0, 0, 0], &mut out);
        assert_eq!(v.state.x[11], 0, "HSM is not offered");
        call(&mut v, &mem, 0x48_534d, 0, [0; 6], &mut out);
        assert_eq!(v.state.x[10] as i64, ERR_NOT_SUPPORTED);

        assert_eq!(call(&mut v, &mem, eid::SRST, 0, [0; 6], &mut out), Some(Outcome::Shutdown));
        assert_eq!(handle(&mut v, &mem, VmExit::Halt, &mut |_| {}), None);
    }
}
