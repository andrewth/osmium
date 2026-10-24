#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::unreachable)]
//! Every system call, thrown hostile argument values. Nothing may panic or
//! hang; the result itself is whatever the call makes of the nonsense.

use super::blocked::become_cpu;
use super::*;
use crate::syscall::NUMBERS;

/// Values a hostile program would try: zero, all ones, signed extremes,
/// 32-bit truncations, misaligned and unmapped addresses, and mapped ones.
const HOSTILE: [u64; 14] = [
    0,
    1,
    u64::MAX,
    u64::MAX / 2,
    u64::MAX / 2 + 1,
    0xffff_ffff,
    0x8000_0000,
    0x1_0000_0000,
    0x1001,
    0xdead_0000,
    DATA,
    DATA + 1,
    DATA + 0x3fff,
    0x7fff_ffff_ffff_f000,
];

/// Calls that wait for something the sweep cannot provide, with arguments
/// that would make them wait: tested with explicit non-blocking arguments in
/// `blocking_calls_with_hostile_arguments`.
fn waits(sys: Sys) -> bool {
    match sys {
        Sys::Futex | Sys::Ppoll | Sys::Pselect6 | Sys::EpollPwait => true,
        #[cfg(target_arch = "x86_64")]
        Sys::Poll | Sys::Select | Sys::EpollWait => true,
        _ => false,
    }
}

/// Runs one call in a fresh process and ignores the outcome.
fn throw(sys: Sys, args: [u64; 6], p: &Process) {
    let _ = dispatch(p, sys.number(), args);
}

#[test]
fn every_call_survives_hostile_arguments() {
    become_cpu();
    // A second baseline: plausible values, so calls get past their first check.
    let sane = [1, DATA + 0x100, 4, 0, DATA + 0x200, 0];
    for &(_, sys) in NUMBERS {
        if waits(sys) {
            continue;
        }
        for &v in &HOSTILE {
            // Every argument the same.
            let (p, _) = process("hostile-all");
            throw(sys, [v; 6], &p);
            for base in [[0; 6], sane] {
                for slot in 0..6 {
                    let (p, _) = process("hostile-one");
                    let mut a = base;
                    a[slot] = v;
                    throw(sys, a, &p);
                }
            }
        }
        // Pairs of hostile values in the first three slots, the usual (fd, ptr, len).
        let (p, _) = process("hostile-pairs");
        for &x in &HOSTILE {
            for &y in &HOSTILE {
                for z in [0, 1, 8, DATA, u64::MAX] {
                    throw(sys, [x, y, z, 0, 0, 0], &p);
                }
            }
        }
    }
}

#[test]
fn unknown_numbers_are_enosys() {
    let (p, _) = process("unknown");
    for nr in [u64::MAX, u64::MAX / 2, 1 << 32, 100_000, 0xffff_ffff] {
        assert_eq!(dispatch(&p, nr, [0; 6]), Outcome::Return(-(Errno::ENOSYS.0 as i64)));
    }
}

#[test]
fn blocking_calls_with_hostile_arguments() {
    become_cpu();
    let (p, _) = process("hostile-blocking");
    // A zero timespec: poll and friends return at once.
    put(&p, DATA + 0x800, &[0; 16]);
    let zero_ts = DATA + 0x800;
    for &v in &HOSTILE {
        for &w in &HOSTILE {
            let _ = dispatch(&p, Sys::Ppoll.number(), [v, w, zero_ts, 0, 0, 0]);
            let _ = dispatch(&p, Sys::Ppoll.number(), [DATA, w.min(64), zero_ts, v, w, 0]);
            let _ = dispatch(&p, Sys::Pselect6.number(), [w.min(2000), v, v, v, zero_ts, 0]);
            let _ = dispatch(&p, Sys::Pselect6.number(), [w, DATA, DATA + 0x80, 0, zero_ts, v]);
            let _ = dispatch(&p, Sys::EpollPwait.number(), [v, v, w, 0, 0, 0]);
            // Non-blocking futex operations: wake, requeue, wake-op, and waits that cannot sleep.
            for op in [1u64, 3, 4, 5, 9, 10, 0x81, 0x87, 0x89, 0x8a, 7, 12, 99] {
                let _ = dispatch(&p, Sys::Futex.number(), [v, op, w, v, w, v]);
                let _ = dispatch(&p, Sys::Futex.number(), [DATA, op, w, zero_ts, DATA + 4, w]);
            }
            // Waits whose value does not match, or whose timeout is already up.
            let _ = dispatch(&p, Sys::Futex.number(), [DATA, 0, 1, zero_ts, 0, 0]);
            let _ = dispatch(&p, Sys::Futex.number(), [v, 0, w, zero_ts, 0, 0]);
        }
    }
    #[cfg(target_arch = "x86_64")]
    for &v in &HOSTILE {
        for &w in &HOSTILE {
            let _ = dispatch(&p, Sys::Poll.number(), [v, w, 0, 0, 0, 0]);
            let _ = dispatch(&p, Sys::Select.number(), [w.min(2000), v, v, v, zero_ts, 0]);
            let _ = dispatch(&p, Sys::EpollWait.number(), [v, v, w, 0, 0, 0]);
        }
    }
}

#[test]
fn pipes_and_socket_pairs_with_hostile_buffers() {
    become_cpu();
    let (p, _) = process("hostile-io");
    // Non-blocking pipe and socket pair, so reads and writes never wait.
    assert_eq!(call(&p, Sys::Pipe2, &[DATA, 0o4000]), 0);
    let fds = get(&p, DATA, 8);
    let rw = [
        u32::from_ne_bytes(fds[..4].try_into().unwrap()) as u64,
        u32::from_ne_bytes(fds[4..].try_into().unwrap()) as u64,
    ];
    assert_eq!(call(&p, Sys::Socketpair, &[1, 1 | 0o4000, 0, DATA + 0x10]), 0);
    let sv = get(&p, DATA + 0x10, 8);
    let socks = [
        u32::from_ne_bytes(sv[..4].try_into().unwrap()) as u64,
        u32::from_ne_bytes(sv[4..].try_into().unwrap()) as u64,
    ];
    for fd in rw.into_iter().chain(socks) {
        for &v in &HOSTILE {
            for &w in &HOSTILE {
                for sys in [Sys::Read, Sys::Write, Sys::Readv, Sys::Writev, Sys::Sendto, Sys::Recvfrom] {
                    let _ = dispatch(&p, sys.number(), [fd, v, w, 0x40, v, w]);
                }
                for sys in [Sys::Sendmsg, Sys::Recvmsg] {
                    let _ = dispatch(&p, sys.number(), [fd, v, 0x40, 0, 0, 0]);
                    let _ = dispatch(&p, sys.number(), [fd, v, w, 0, 0, 0]);
                }
                let _ = dispatch(&p, Sys::Getsockname.number(), [fd, v, w, 0, 0, 0]);
                let _ = dispatch(&p, Sys::Getsockopt.number(), [fd, 1, 4, v, w, 0]);
                let _ = dispatch(&p, Sys::Setsockopt.number(), [fd, 1, 20, v, w, 0]);
                let _ = dispatch(&p, Sys::Fcntl.number(), [fd, v, w, 0, 0, 0]);
                let _ = dispatch(&p, Sys::Lseek.number(), [fd, v, w, 0, 0, 0]);
            }
        }
    }
    // A msghdr whose every field is hostile.
    for &v in &HOSTILE {
        let hdr: alloc::vec::Vec<u8> = [v; 7].iter().flat_map(|x| x.to_ne_bytes()).collect();
        put(&p, DATA + 0x1000, &hdr);
        for fd in socks {
            for sys in [Sys::Sendmsg, Sys::Recvmsg] {
                let _ = dispatch(&p, sys.number(), [fd, DATA + 0x1000, 0, 0, 0, 0]);
            }
        }
    }
}

#[test]
fn signal_numbers_and_frames_are_checked() {
    let (p, _) = process("hostile-signals");
    for sig in [0u64, 1, 9, 32, 33, 63, 64, 65, 128, 255, 256, u64::MAX] {
        for &w in &[0, 8, 16, DATA, DATA + 0x100, u64::MAX] {
            let _ = dispatch(&p, Sys::RtSigaction.number(), [sig, w, w, 8, 0, 0]);
            let _ = dispatch(&p, Sys::Kill.number(), [0, sig, 0, 0, 0, 0]);
            let _ = dispatch(&p, Sys::Tkill.number(), [p.pid().0 as u64, sig, 0, 0, 0, 0]);
            let _ = dispatch(&p, Sys::Tgkill.number(), [p.pid().0 as u64, p.pid().0 as u64, sig, 0, 0, 0]);
        }
    }
}

#[test]
fn clone_flags_and_thread_arguments_are_checked() {
    become_cpu();
    for &flags in &HOSTILE {
        for &v in &HOSTILE {
            let (p, _) = process("hostile-clone");
            let _ = dispatch(&p, Sys::Clone.number(), [flags, v, v, v, v, 0]);
            let _ = dispatch(&p, Sys::Clone.number(), [flags | 0x1_0f00, v, DATA, DATA + 4, v, 0]);
            let _ =
                dispatch(&p, Sys::Clone.number(), [flags | 0x1_0f00 | 0x8_0000, DATA + 0x2000, DATA, DATA + 4, v, 0]);
        }
    }
}

/// `program()` with the bytes at `at` replaced.
fn patched(at: usize, with: &[u8]) -> alloc::vec::Vec<u8> {
    let mut f = program().to_vec();
    f[at..at + with.len()].copy_from_slice(with);
    f
}

#[test]
fn hostile_elf_headers_are_rejected_not_fatal() {
    platform();
    let plat = crate::exec::platform().unwrap();
    let mut images = alloc::vec::Vec::new();
    // Every program-header field of both segments, and the table fields, hostile.
    for &v in &HOSTILE {
        for at in (64..176).step_by(8) {
            images.push(patched(at, &v.to_le_bytes()));
        }
        for at in [32usize, 24] {
            images.push(patched(at, &v.to_le_bytes()));
        }
        for at in [54usize, 56, 16, 18] {
            images.push(patched(at, &(v as u16).to_le_bytes()));
        }
    }
    // Every byte of the headers flipped to a few extremes.
    for at in 0..0x80 {
        for b in [0u8, 0x7f, 0x80, 0xff] {
            images.push(patched(at, &[b]));
        }
    }
    // Truncations.
    for len in 0..program().len() {
        images.push(program()[..len].to_vec());
    }
    for image in &images {
        let Ok(elf) = osmium_boot::elf::Elf::new(image) else { continue };
        let _ = crate::exec::brk_limit(&elf, plat);
        let _ = crate::exec::phdr_address(image, &elf);
        let s = space(leaked_frames());
        let _ = s.load_elf(&elf);
    }
}
