use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use osmium_sync::IrqSpinLock;

use crate::bus::{BusDevice, get_le};

/// Size of one hart's interrupt file in the MMIO window.
pub const IMSIC_FILE_SIZE: u64 = 0x1000;

/// Indirect register numbers (`siselect` values) of an interrupt file.
pub mod isel {
    /// `eidelivery`: 0 = off, 1 = on.
    pub const EIDELIVERY: u64 = 0x70;
    /// `eithreshold`: identities at or above a non-zero value are masked.
    pub const EITHRESHOLD: u64 = 0x72;
    /// First `eip` register (pending bits); on RV64 only even ones exist, 64 identities each.
    pub const EIP0: u64 = 0x80;
    /// Last register number of the `eip` array.
    pub const EIP_LAST: u64 = 0xbf;
    /// First `eie` register (enable bits).
    pub const EIE0: u64 = 0xc0;
    /// Last register number of the `eie` array.
    pub const EIE_LAST: u64 = 0xff;
}

type Output = Box<dyn Fn(usize, bool) + Send + Sync>;

struct File {
    eidelivery: u64,
    eithreshold: u64,
    /// Bit `i` of word `i / 64` is identity `i`; identity 0 does not exist.
    eip: Vec<u64>,
    eie: Vec<u64>,
    asserted: bool,
}

struct State {
    files: Vec<File>,
    /// The highest identity (`2^k - 1`, so `ids + 1` is a multiple of 64).
    ids: u32,
}

impl File {
    /// The highest-priority (lowest-numbered) identity that is pending,
    /// enabled and under the threshold: what `stopei` reports.
    fn top(&self, ids: u32) -> u32 {
        for (w, (&p, &e)) in self.eip.iter().zip(&self.eie).enumerate() {
            let mut live = p & e;
            // Identity 0 does not exist.
            if w == 0 {
                live &= !1;
            }
            if live == 0 {
                continue;
            }
            let id = w as u32 * 64 + live.trailing_zeros();
            if id > ids || (self.eithreshold != 0 && u64::from(id) >= self.eithreshold) {
                // The remaining identities are numbered higher still.
                return 0;
            }
            return id;
        }
        0
    }
}

/// An emulated RISC-V IMSIC: one interrupt file per hart, each a 4 KiB
/// MMIO page that devices (or an [`VirtualAplic`](super::VirtualAplic)) write
/// interrupt identities to, plus the file's registers.
///
/// # Scope
///
/// - A single privilege level's files (the supervisor-level files a guest
///   sees), one per hart, laid out back to back. No machine-level files, no
///   guest interrupt files (`hgeip`) for nested guests.
/// - Identities `1..=ids` with `ids + 1` a multiple of 64 (63 to 2047);
///   `eidelivery`, `eithreshold`, `eip` and `eie` follow the RV64 layout (only
///   the even `eip`/`eie` registers exist).
/// - The file's registers are reached by the hart's `siselect`/`sireg`/`stopei`
///   CSRs, which a guest executes through the hypervisor
///   ([`RiscvVcpu::with_imsic`](crate::riscv::RiscvVcpu::with_imsic)): they
///   trap as virtual-instruction exceptions while `hstatus.VGEIN` is zero.
///
/// Each hart's external-interrupt output (delivery on and a deliverable
/// identity) is reported through the callback, meant for that vCPU's
/// [`external_irq`](crate::riscv::RiscvVcpu::external_irq) line.
pub struct VirtualImsic {
    state: IrqSpinLock<State>,
    output: Output,
}

impl VirtualImsic {
    /// An IMSIC for `harts` harts with identities `1..=ids` (`ids` is
    /// rounded up to the next `2^k - 1` of at least 63 and at most 2047).
    /// `output(hart, level)` reports changes of each hart's interrupt line.
    pub fn new(harts: usize, ids: u32, output: impl Fn(usize, bool) + Send + Sync + 'static) -> Self {
        let words = (ids.clamp(63, 2047) as usize + 1).div_ceil(64).next_power_of_two();
        let ids = (words * 64 - 1) as u32;
        let file = || File { eidelivery: 0, eithreshold: 0, eip: vec![0; words], eie: vec![0; words], asserted: false };
        let state = State { files: (0..harts).map(|_| file()).collect(), ids };
        Self { state: IrqSpinLock::new(state), output: Box::new(output) }
    }

    /// Size of the MMIO window for `harts` harts.
    pub const fn mmio_size(harts: usize) -> u64 {
        IMSIC_FILE_SIZE * harts as u64
    }

    /// The highest interrupt identity.
    pub fn ids(&self) -> u32 {
        self.state.lock().ids
    }

    /// Delivers message `eiid` to `hart`'s file: what a write of the identity
    /// to its `seteipnum_le` register does. Out-of-range identities and harts
    /// are dropped.
    pub fn set_pending(&self, hart: usize, eiid: u32) {
        let mut s = self.state.lock();
        let ids = s.ids;
        if eiid != 0
            && eiid <= ids
            && let Some(w) = s.files.get_mut(hart).and_then(|f| f.eip.get_mut(eiid as usize / 64))
        {
            *w |= 1 << (eiid % 64);
        }
        self.update(&mut s);
    }

    /// `hart`'s `stopei` value: `identity << 16 | identity` of the top
    /// deliverable interrupt, or 0. Does not claim it.
    pub fn topei(&self, hart: usize) -> u64 {
        let s = self.state.lock();
        s.files.get(hart).map_or(0, |f| top_value(f, s.ids))
    }

    /// A read of `stopei` followed by the write that claims what it
    /// reported: returns the reported value and clears that identity's
    /// pending bit.
    pub fn claim(&self, hart: usize) -> u64 {
        let mut s = self.state.lock();
        let ids = s.ids;
        let Some(f) = s.files.get_mut(hart) else { return 0 };
        let v = top_value(f, ids);
        let id = (v >> 16) as usize;
        if id != 0
            && let Some(w) = f.eip.get_mut(id / 64)
        {
            *w &= !(1 << (id % 64));
        }
        self.update(&mut s);
        v
    }

    /// Reads indirect register `reg` (a `siselect` value) of `hart`'s file.
    /// `None` for a register that does not exist (the CSR access is illegal).
    pub fn read_reg(&self, hart: usize, reg: u64) -> Option<u64> {
        let s = self.state.lock();
        let f = s.files.get(hart)?;
        Some(match reg {
            isel::EIDELIVERY => f.eidelivery,
            isel::EITHRESHOLD => f.eithreshold,
            isel::EIP0..=isel::EIP_LAST if reg % 2 == 0 => {
                let w = (reg - isel::EIP0) / 2;
                f.eip.get(w as usize).copied().unwrap_or(0) & word_mask(w, 0)
            }
            isel::EIE0..=isel::EIE_LAST if reg % 2 == 0 => {
                let w = (reg - isel::EIE0) / 2;
                f.eie.get(w as usize).copied().unwrap_or(0) & word_mask(w, 0)
            }
            _ => return None,
        })
    }

    /// Writes indirect register `reg` of `hart`'s file; returns whether the
    /// register exists. Bits for identities above [`ids`](Self::ids) and
    /// identity 0 stay zero.
    pub fn write_reg(&self, hart: usize, reg: u64, value: u64) -> bool {
        let mut s = self.state.lock();
        let ids = s.ids;
        let Some(f) = s.files.get_mut(hart) else { return false };
        let ok = match reg {
            // 0 and 1 are the only values; others are ignored (WARL).
            isel::EIDELIVERY => {
                if value <= 1 {
                    f.eidelivery = value;
                }
                true
            }
            isel::EITHRESHOLD => {
                f.eithreshold = value & u64::from(ids);
                true
            }
            isel::EIP0..=isel::EIP_LAST if reg % 2 == 0 => {
                let w = ((reg - isel::EIP0) / 2) as usize;
                if let Some(x) = f.eip.get_mut(w) {
                    *x = value & word_mask(w as u64, ids);
                }
                true
            }
            isel::EIE0..=isel::EIE_LAST if reg % 2 == 0 => {
                let w = ((reg - isel::EIE0) / 2) as usize;
                if let Some(x) = f.eie.get_mut(w) {
                    *x = value & word_mask(w as u64, ids);
                }
                true
            }
            _ => false,
        };
        self.update(&mut s);
        ok
    }

    fn update(&self, s: &mut State) {
        let ids = s.ids;
        for (hart, f) in s.files.iter_mut().enumerate() {
            let now = f.eidelivery == 1 && f.top(ids) != 0;
            if now != f.asserted {
                f.asserted = now;
                (self.output)(hart, now);
            }
        }
    }

    /// Whether `hart`'s interrupt line is asserted.
    pub fn asserted(&self, hart: usize) -> bool {
        self.state.lock().files.get(hart).is_some_and(|f| f.asserted)
    }

    /// The MMIO window of every hart's file ([`mmio_size`](Self::mmio_size)
    /// bytes): hart `n`'s file is at offset `n * 0x1000`.
    pub fn mmio(self: &Arc<Self>) -> Arc<dyn BusDevice> {
        Arc::new(Window { imsic: self.clone() })
    }
}

/// Mask of the valid identity bits in 64-bit word `w` of `eip`/`eie`:
/// identity 0 is absent, and `ids` (when non-zero) is the last one.
fn word_mask(w: u64, ids: u32) -> u64 {
    let mut m = !0u64;
    if w == 0 {
        m &= !1;
    }
    if ids != 0 {
        let top = u64::from(ids);
        if w * 64 > top {
            m = 0;
        } else if w * 64 + 63 > top {
            m &= !0u64 >> (63 - (top - w * 64));
        }
    }
    m
}

fn top_value(f: &File, ids: u32) -> u64 {
    let id = u64::from(f.top(ids));
    id << 16 | id
}

struct Window {
    imsic: Arc<VirtualImsic>,
}

impl BusDevice for Window {
    fn read(&self, _offset: u64, data: &mut [u8]) {
        // The doorbell registers are write-only.
        data.iter_mut().for_each(|d| *d = 0);
    }

    fn write(&self, offset: u64, data: &[u8]) {
        let (hart, reg) = (offset / IMSIC_FILE_SIZE, offset % IMSIC_FILE_SIZE);
        // seteipnum_le at 0 and seteipnum_be at 4: 32-bit writes of an identity.
        let id = match (reg, data.len()) {
            (0, 4) => get_le(data) as u32,
            (4, 4) => (get_le(data) as u32).swap_bytes(),
            _ => return,
        };
        if let Ok(hart) = usize::try_from(hart) {
            self.imsic.set_pending(hart, id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicBool, Ordering};

    fn imsic(harts: usize) -> (Arc<VirtualImsic>, Arc<[AtomicBool; 2]>) {
        let lines = Arc::new([AtomicBool::new(false), AtomicBool::new(false)]);
        let l = lines.clone();
        let i = Arc::new(VirtualImsic::new(harts, 255, move |h, v| {
            if let Some(x) = l.get(h) {
                x.store(v, Ordering::SeqCst)
            }
        }));
        (i, lines)
    }

    #[test]
    fn delivery_threshold_priority_and_claim() {
        let (i, lines) = imsic(2);
        assert_eq!(i.ids(), 255);
        let w = i.mmio();
        // A doorbell write: pending, but not enabled and delivery is off.
        w.write(IMSIC_FILE_SIZE, &20u32.to_le_bytes());
        assert_eq!(i.read_reg(1, isel::EIP0), Some(1 << 20));
        assert!(!lines[1].load(Ordering::SeqCst));
        assert_eq!(i.topei(1), 0);
        // Enable it and delivery: the line rises for hart 1 only.
        assert!(i.write_reg(1, isel::EIE0, 1 << 20 | 1 << 9));
        assert_eq!(i.topei(1), 20 << 16 | 20, "enabled but delivery off still reports");
        assert!(!lines[1].load(Ordering::SeqCst));
        assert!(i.write_reg(1, isel::EIDELIVERY, 1));
        assert!(lines[1].load(Ordering::SeqCst));
        assert!(!lines[0].load(Ordering::SeqCst));
        // A lower-numbered identity wins; the big-endian doorbell works too.
        w.write(IMSIC_FILE_SIZE + 4, &(9u32.swap_bytes()).to_le_bytes());
        assert_eq!(i.topei(1), 9 << 16 | 9);
        // The threshold masks identities at or above it.
        assert!(i.write_reg(1, isel::EITHRESHOLD, 9));
        assert_eq!(i.topei(1), 0);
        assert!(!lines[1].load(Ordering::SeqCst));
        assert!(i.write_reg(1, isel::EITHRESHOLD, 0));
        // Claim takes them in order.
        assert_eq!(i.claim(1), 9 << 16 | 9);
        assert_eq!(i.claim(1), 20 << 16 | 20);
        assert_eq!(i.claim(1), 0);
        assert!(!lines[1].load(Ordering::SeqCst));
    }

    #[test]
    fn registers_and_bounds() {
        let (i, _) = imsic(1);
        // Odd eip/eie and unknown registers do not exist on RV64.
        assert_eq!(i.read_reg(0, isel::EIP0 + 1), None);
        assert_eq!(i.read_reg(0, isel::EIE0 + 3), None);
        assert!(!i.write_reg(0, 0x71, 1));
        assert_eq!(i.read_reg(0, 0x40), None);
        assert_eq!(i.read_reg(1, isel::EIDELIVERY), None, "no such hart");
        // Identity 0 and identities above the maximum cannot be set.
        assert!(i.write_reg(0, isel::EIE0, !0));
        assert_eq!(i.read_reg(0, isel::EIE0), Some(!1));
        assert!(i.write_reg(0, isel::EIE0 + 6, !0));
        assert_eq!(i.read_reg(0, isel::EIE0 + 6), Some(!0), "identities 192-255");
        assert!(i.write_reg(0, isel::EIE0 + 8, !0));
        assert_eq!(i.read_reg(0, isel::EIE0 + 8), Some(0), "past identity 255");
        i.set_pending(0, 256);
        i.set_pending(0, 0);
        i.set_pending(9, 5);
        assert_eq!(i.read_reg(0, isel::EIP0), Some(0));
        // eidelivery only takes 0 and 1.
        assert!(i.write_reg(0, isel::EIDELIVERY, 2));
        assert_eq!(i.read_reg(0, isel::EIDELIVERY), Some(0));
        // A threshold above the last identity is truncated.
        assert!(i.write_reg(0, isel::EITHRESHOLD, 0x1ff));
        assert_eq!(i.read_reg(0, isel::EITHRESHOLD), Some(0xff));
        assert_eq!(VirtualImsic::new(1, 100, |_, _| {}).ids(), 127);
        assert_eq!(VirtualImsic::new(1, 0, |_, _| {}).ids(), 63);
        assert_eq!(VirtualImsic::new(1, 100_000, |_, _| {}).ids(), 2047);
    }

    #[test]
    fn doorbell_ignores_odd_accesses() {
        let (i, _) = imsic(1);
        let w = i.mmio();
        w.write(0, &[5]);
        w.write(0, &5u64.to_le_bytes());
        w.write(8, &5u32.to_le_bytes());
        w.write(IMSIC_FILE_SIZE * 7, &5u32.to_le_bytes());
        let mut b = [0xffu8; 4];
        w.read(0, &mut b);
        assert_eq!(b, [0; 4]);
        assert_eq!(i.read_reg(0, isel::EIP0), Some(0));
    }
}
