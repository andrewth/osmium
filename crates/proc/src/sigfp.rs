// SPDX-License-Identifier: GPL-2.0-only
//! The FP/SIMD registers in a signal frame, as Linux lays them out for each
//! architecture, and the checks a frame from user memory must pass before
//! `rt_sigreturn` loads them.
//!
//! - x86_64: `sigcontext.fpstate` points at an FXSAVE area (or an XSAVE area
//!   with `fpx_sw_bytes` in its software-reserved bytes and
//!   `FP_XSTATE_MAGIC2` after it, `uc_flags` `UC_FP_XSTATE`), 64-byte
//!   aligned above the frame. The handler starts with the FP registers reset,
//!   as on Linux. A null `fpstate` on return resets them; an area without
//!   valid `fpx_sw_bytes` restores x87 and SSE only.
//! - AArch64: a `fpsimd_context` record (`FPSIMD_MAGIC`) first in
//!   `sigcontext.__reserved`, then the terminating null record.
//!   `rt_sigreturn` requires the record while FP is on, accepts an
//!   `esr_context` beside it, and refuses any other record.
//! - RISC-V: `sigcontext.__fpstate` holds `f0`..`f31` and `fcsr` (the D
//!   extension's `__riscv_d_ext_state`); the extension header after it must
//!   be the terminating one, as Linux checks.
//!
//! The registers are read from and written to the calling task through
//! [`osmium_sched::current_fp_state`] and
//! [`osmium_sched::set_current_fp_state`], in the layout of
//! [`osmium_arch::fp::FpState::as_bytes`]; with FP off (a soft-float kernel
//! that never called `osmium_arch::fp::enable`) there is nothing to save,
//! and frames carry none. `FpState::set_bytes` refuses what would fault on
//! loading (x86_64's reserved `MXCSR` bits or a bad XSAVE header), which
//! ends the program with `SIGSEGV`, as Linux does.

use osmium_fs::Errno;

use crate::bytes::{put, slice, u32_at, u64_at};
use crate::process::Process;
#[cfg(test)]
use test_regs::{current, reset_current, set_current};

/// Most bytes of a saved FP/SIMD state (an x86_64 XSAVE area).
pub(crate) const IMAGE_MAX: usize = 1024;

/// AArch64 `FPSIMD_MAGIC` and the record's size.
const FPSIMD_MAGIC: u32 = 0x4650_8001;
const FPSIMD_SIZE: usize = 528;
/// AArch64 `ESR_MAGIC`, a record `rt_sigreturn` ignores.
const ESR_MAGIC: u32 = 0x4553_5201;
/// AArch64: `__reserved` within `sigcontext`, and its size.
const AARCH64_RESERVED: usize = 288;
/// RISC-V: `__fpstate` within `sigcontext`, and the extension header
/// (`reserved` word, then `magic` and `size`) after the D state.
const RISCV_FP: usize = 256;
const RISCV_EXT_RESERVED: usize = RISCV_FP + 516;
/// x86_64: `fpstate` within `sigcontext`; `fpx_sw_bytes` within the FXSAVE area.
const X86_FPSTATE_PTR: usize = 184;
const X86_SW_BYTES: usize = 464;
const FP_XSTATE_MAGIC1: u32 = 0x4650_5853;
const FP_XSTATE_MAGIC2: u32 = 0x4650_5845;
/// x86_64 `uc_flags` bit: the frame's FP state is an XSAVE area.
pub(crate) const UC_FP_XSTATE: u64 = 0x1;

/// Where an architecture's signal frame keeps the FP/SIMD state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FpLayout {
    /// Pointed at by `sigcontext.fpstate`, above the frame.
    X86_64,
    /// A record in `sigcontext.__reserved`.
    Aarch64,
    /// `sigcontext.__fpstate`.
    Riscv64,
}

impl FpLayout {
    /// Bytes of the state in [`osmium_arch::fp::FpState::as_bytes`] layout,
    /// for the architectures with one size.
    fn native_len(self) -> Option<usize> {
        match self {
            Self::X86_64 => None,
            Self::Aarch64 => Some(528),
            Self::Riscv64 => Some(264),
        }
    }

    /// Whether `img` is this architecture's layout (a hosted build's
    /// simulated state is not, and is left out of frames).
    fn fits(self, img: &Image) -> bool {
        match self.native_len() {
            Some(n) => img.len == n,
            None => img.len == 512 || (576..=IMAGE_MAX).contains(&img.len) && img.xfeatures != 0,
        }
    }
}

/// A saved FP/SIMD state in [`osmium_arch::fp::FpState::as_bytes`] layout.
#[derive(Clone)]
pub(crate) struct Image {
    bytes: [u8; IMAGE_MAX],
    len: usize,
    /// x86_64: the XSAVE features (`XCR0`) when this is an XSAVE area, else 0.
    xfeatures: u64,
}

impl Image {
    /// An image of `bytes`; `None` if they do not fit.
    pub(crate) fn new(bytes: &[u8], xfeatures: u64) -> Option<Self> {
        let mut img = Self { bytes: [0; IMAGE_MAX], len: bytes.len(), xfeatures };
        img.bytes.get_mut(..bytes.len())?.copy_from_slice(bytes);
        Some(img)
    }

    /// x86_64: whether this is an XSAVE area (rather than an FXSAVE one).
    pub(crate) fn is_xsave(&self) -> bool {
        self.xfeatures != 0
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or(&[])
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.bytes.get_mut(..self.len).unwrap_or(&mut [])
    }
}

/// The calling task's FP/SIMD registers; `None` when FP is off.
#[cfg(not(test))]
pub(crate) fn current() -> Option<Image> {
    if !osmium_arch::fp::enabled() {
        return None;
    }
    let state = osmium_sched::current_fp_state();
    Image::new(state.as_bytes(), osmium_arch::fp::xsave_features())
}

/// Loads `img` into the calling task's FP/SIMD registers; `EINVAL` if
/// loading it could fault.
#[cfg(not(test))]
fn set_current(img: &Image) -> Result<(), Errno> {
    let mut state = osmium_arch::fp::FpState::new();
    state.set_bytes(img.as_slice()).map_err(|_| Errno::EINVAL)?;
    osmium_sched::set_current_fp_state(&state);
    Ok(())
}

/// Resets the calling task's FP/SIMD registers, as a new program has them.
#[cfg(not(test))]
fn reset_current() {
    osmium_sched::reset_current_fp();
}

/// Bytes of the x86_64 FP area that goes above the frame for `img`
/// (`FP_XSTATE_MAGIC2` follows an XSAVE area), or 0 for none.
pub(crate) fn x86_area_len(img: Option<&Image>) -> u64 {
    match img {
        Some(i) if FpLayout::X86_64.fits(i) => i.len as u64 + if i.xfeatures != 0 { 4 } else { 0 },
        _ => 0,
    }
}

/// The calling task's registers, if this layout can carry them.
pub(crate) fn for_frame(layout: FpLayout) -> Option<Image> {
    current().filter(|i| layout.fits(i))
}

/// Writes `img` into the frame's head: `mc` is `uc_mcontext` within it.
/// x86_64's state goes in its own area ([`x86_area`]) instead.
pub(crate) fn save(layout: FpLayout, head: &mut [u8], mc: usize, img: Option<&Image>) -> Result<(), Errno> {
    let Some(img) = img else {
        // The head is zeroed: no state (AArch64: the terminating record alone).
        return Ok(());
    };
    let b = img.as_slice();
    match layout {
        FpLayout::X86_64 => Ok(()),
        FpLayout::Aarch64 => {
            let rec = mc + AARCH64_RESERVED;
            put(head, rec, &FPSIMD_MAGIC.to_ne_bytes())?;
            put(head, rec + 4, &(FPSIMD_SIZE as u32).to_ne_bytes())?;
            // fpsr and fpcr, 32 bits each, then the vector registers.
            put(head, rec + 8, slice(b, 520, 4)?)?;
            put(head, rec + 12, slice(b, 512, 4)?)?;
            put(head, rec + 16, slice(b, 0, 512)?)?;
            // The terminating record after it: magic 0, size 0, as zeroed.
            slice(head, rec + FPSIMD_SIZE, 8).map(|_| ())
        }
        FpLayout::Riscv64 => {
            put(head, mc + RISCV_FP, slice(b, 0, 256)?)?;
            put(head, mc + RISCV_FP + 256, slice(b, 256, 4)?)
        }
    }
}

/// x86_64: `img` as the area `fpstate` points at, `area.len()` being
/// [`x86_area_len`]: the FXSAVE or XSAVE image, with `fpx_sw_bytes` saying
/// which.
pub(crate) fn x86_area(img: &Image, area: &mut [u8]) -> Result<(), Errno> {
    let len = img.len;
    put(area, 0, img.as_slice())?;
    // The software-reserved bytes: zero, or `fpx_sw_bytes` for an XSAVE area.
    put(area, X86_SW_BYTES, &[0; 48])?;
    if img.xfeatures != 0 {
        put(area, X86_SW_BYTES, &FP_XSTATE_MAGIC1.to_ne_bytes())?;
        put(area, X86_SW_BYTES + 4, &(len as u32 + 4).to_ne_bytes())?;
        put(area, X86_SW_BYTES + 8, &img.xfeatures.to_ne_bytes())?;
        put(area, X86_SW_BYTES + 16, &(len as u32).to_ne_bytes())?;
        put(area, len, &FP_XSTATE_MAGIC2.to_ne_bytes())?;
    }
    Ok(())
}

/// x86_64: where `sigcontext.fpstate` is, within `uc_mcontext`.
pub(crate) const X86_FPSTATE: usize = X86_FPSTATE_PTR;
/// x86_64: the FP area's alignment.
pub(crate) const X86_AREA_ALIGN: u64 = 64;

/// After the frame is written: x86_64 handlers start with the FP registers
/// reset, as on Linux.
pub(crate) fn enter_handler(layout: FpLayout, saved: bool) {
    if layout == FpLayout::X86_64 && saved {
        reset_current();
    }
}

/// `rt_sigreturn`: checks the FP state in the frame (`head`, read from user
/// memory; `mc` is `uc_mcontext` within it) and loads it. `EINVAL` (or
/// `EFAULT`) for a frame that is malformed or whose state could not be
/// loaded: the program must then end.
pub(crate) fn restore(p: &Process, layout: FpLayout, head: &[u8], mc: usize) -> Result<(), Errno> {
    let cur = current();
    match layout {
        FpLayout::Riscv64 => {
            // The extension header after the D state: a zero `reserved`
            // word, then the terminating header (magic 0, size 0).
            if u32_at(head, mc + RISCV_EXT_RESERVED)? != 0
                || u32_at(head, mc + RISCV_EXT_RESERVED + 4)? != 0
                || u32_at(head, mc + RISCV_EXT_RESERVED + 8)? != 0
            {
                return Err(Errno::EINVAL);
            }
            let Some(mut img) = cur.filter(|i| layout.fits(i)) else { return Ok(()) };
            let b = img.as_mut_slice();
            put(b, 0, slice(head, mc + RISCV_FP, 256)?)?;
            put(b, 256, &u64::from(u32_at(head, mc + RISCV_FP + 256)?).to_ne_bytes())?;
            set_current(&img)
        }
        FpLayout::Aarch64 => {
            let fpsimd = aarch64_records(head, mc + AARCH64_RESERVED)?;
            let Some(mut img) = cur.filter(|i| layout.fits(i)) else { return Ok(()) };
            // Linux refuses a frame without one.
            let rec = fpsimd.ok_or(Errno::EINVAL)?;
            let b = img.as_mut_slice();
            put(b, 0, slice(head, rec + 16, 512)?)?;
            put(b, 512, &u64::from(u32_at(head, rec + 12)?).to_ne_bytes())?;
            put(b, 520, &u64::from(u32_at(head, rec + 8)?).to_ne_bytes())?;
            set_current(&img)
        }
        FpLayout::X86_64 => {
            let Some(img) = cur.filter(|i| layout.fits(i)) else { return Ok(()) };
            match u64_at(head, mc + X86_FPSTATE_PTR)? {
                0 => {
                    reset_current();
                    Ok(())
                }
                va => set_current(&x86_from_user(p, va, img)?),
            }
        }
    }
}

/// Walks AArch64's `__reserved` records from `at` to the terminating one,
/// within `head`, and returns where the `fpsimd_context` is, if any.
fn aarch64_records(head: &[u8], at: usize) -> Result<Option<usize>, Errno> {
    let mut off = at;
    let mut fpsimd = None;
    loop {
        let (magic, size) = (u32_at(head, off)?, u32_at(head, off + 4)? as usize);
        match magic {
            0 if size == 0 => return Ok(fpsimd),
            FPSIMD_MAGIC if size == FPSIMD_SIZE && fpsimd.is_none() => fpsimd = Some(off),
            ESR_MAGIC if size == 16 => {}
            _ => return Err(Errno::EINVAL),
        }
        // Records past the part of the frame read (`head`) fail the next read.
        off = off.checked_add(size).ok_or(Errno::EINVAL)?;
    }
}

/// x86_64: the state at `va` in user memory, in the layout of `cur` (the
/// calling task's): a whole XSAVE area if `fpx_sw_bytes` and
/// `FP_XSTATE_MAGIC2` say there is one of that size, else the FXSAVE part
/// with the other components reset.
fn x86_from_user(p: &Process, va: u64, cur: Image) -> Result<Image, Errno> {
    let mut img = cur;
    let len = img.len;
    let mut fx = [0u8; 512];
    p.memory().read(va, &mut fx)?;
    let xsave = img.xfeatures != 0 && {
        let sw = |off: usize| u32_at(&fx, X86_SW_BYTES + off);
        let mut magic2 = [0u8; 4];
        sw(0)? == FP_XSTATE_MAGIC1
            && sw(4)? as usize == len + 4
            && sw(16)? as usize == len
            && p.memory().read(va.checked_add(len as u64).ok_or(Errno::EFAULT)?, &mut magic2).is_ok()
            && u32::from_ne_bytes(magic2) == FP_XSTATE_MAGIC2
    };
    let b = img.as_mut_slice();
    if xsave {
        p.memory().read(va, b)?;
        // Only the components the frame says it holds (`FpState::set_bytes`
        // refuses any that are not enabled).
        let bv = u64_at(b, 512)? & u64_at(&fx, X86_SW_BYTES + 8)?;
        put(b, 512, &bv.to_ne_bytes())?;
    } else {
        b.fill(0);
        put(b, 0, &fx)?;
        if len > 512 {
            // XSTATE_BV: x87 and SSE from the area, AVX reset.
            put(b, 512, &3u64.to_ne_bytes())?;
        }
    }
    Ok(img)
}

/// Stand-ins for the calling task's registers, so that every
/// architecture's layout runs on the host.
#[cfg(test)]
pub(crate) mod test_regs {
    use core::cell::RefCell;
    use std::vec::Vec;

    use super::{Errno, Image};

    std::thread_local! {
        static CURRENT: RefCell<Option<Image>> = const { RefCell::new(None) };
        /// What each `set_current` loaded (`None` for a reset).
        static LOADED: RefCell<Vec<Option<Vec<u8>>>> = const { RefCell::new(Vec::new()) };
    }

    /// Makes `img` the calling thread's registers (`None`: FP is off).
    pub(crate) fn set(img: Option<Image>) {
        CURRENT.with(|c| *c.borrow_mut() = img);
        LOADED.with(|l| l.borrow_mut().clear());
    }

    /// What was loaded since [`set`], oldest first.
    pub(crate) fn loaded() -> Vec<Option<Vec<u8>>> {
        LOADED.with(|l| l.borrow().clone())
    }

    pub(super) fn current() -> Option<Image> {
        CURRENT.with(|c| c.borrow().clone())
    }

    pub(super) fn set_current(img: &Image) -> Result<(), Errno> {
        // x86_64's check, as `FpState::set_bytes` makes it, for the tests' MXCSR.
        if img.xfeatures != 0 || img.len == 512 {
            let mxcsr = crate::bytes::u32_at(img.as_slice(), 24)?;
            if mxcsr & !0xffbf != 0 {
                return Err(Errno::EINVAL);
            }
        }
        LOADED.with(|l| l.borrow_mut().push(Some(img.as_slice().to_vec())));
        Ok(())
    }

    pub(super) fn reset_current() {
        LOADED.with(|l| l.borrow_mut().push(None));
    }
}
