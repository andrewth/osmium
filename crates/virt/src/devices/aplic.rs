use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use osmium_sync::{IrqDisabled, IrqSpinLock, SpinLockGuard};

use crate::bus::{BusDevice, get_le, put_le};

const DOMAINCFG: u64 = 0x0000;
const SOURCECFG: u64 = 0x0004;
const MMSIADDRCFG: u64 = 0x1bc0;
const SMSIADDRCFG_H: u64 = 0x1bcc;
const SETIP: u64 = 0x1c00;
const SETIPNUM: u64 = 0x1cdc;
const IN_CLRIP: u64 = 0x1d00;
const CLRIPNUM: u64 = 0x1ddc;
const SETIE: u64 = 0x1e00;
const SETIENUM: u64 = 0x1edc;
const CLRIE: u64 = 0x1f00;
const CLRIENUM: u64 = 0x1fdc;
const SETIPNUM_LE: u64 = 0x2000;
const SETIPNUM_BE: u64 = 0x2004;
const GENMSI: u64 = 0x3000;
const TARGET: u64 = 0x3004;
const IDC: u64 = 0x4000;
const IDC_SIZE: u64 = 32;

/// `domaincfg`: the fixed high byte 0x80, interrupt enable, delivery mode
/// (1 = MSI), big-endian.
const DOMAINCFG_FIXED: u32 = 0x8000_0000;
const DOMAINCFG_IE: u32 = 1 << 8;
const DOMAINCFG_DM: u32 = 1 << 2;
const DOMAINCFG_BE: u32 = 1;

/// `sourcecfg.SM`: source modes.
const SM_INACTIVE: u8 = 0;
const SM_DETACHED: u8 = 1;
const SM_EDGE_RISING: u8 = 4;
const SM_EDGE_FALLING: u8 = 5;
const SM_LEVEL_HIGH: u8 = 6;
const SM_LEVEL_LOW: u8 = 7;

/// The most interrupt sources an APLIC has.
pub const MAX_SOURCES: usize = 1023;
/// The most harts (interrupt delivery controllers) addressed.
const MAX_HARTS: usize = 16384;

type Msi = Box<dyn Fn(u32, u32, u32) + Send + Sync>;
type Wire = Box<dyn Fn(usize, bool) + Send + Sync>;

#[derive(Clone, Copy, Default)]
struct Source {
    /// `sourcecfg.SM`.
    mode: u8,
    /// The wire as the device drives it.
    input: bool,
    pending: bool,
    enabled: bool,
    /// `target`.
    target: u32,
}

impl Source {
    fn active(&self) -> bool {
        matches!(self.mode, SM_DETACHED | SM_EDGE_RISING..=SM_LEVEL_LOW)
    }

    /// The input after the mode's inversion: what the pending logic sees.
    fn rectified(&self) -> bool {
        match self.mode {
            SM_EDGE_RISING | SM_LEVEL_HIGH => self.input,
            SM_EDGE_FALLING | SM_LEVEL_LOW => !self.input,
            _ => false,
        }
    }

    fn level(&self) -> bool {
        matches!(self.mode, SM_LEVEL_HIGH | SM_LEVEL_LOW)
    }
}

/// One hart's interrupt delivery control (direct delivery mode).
#[derive(Clone, Copy, Default)]
struct Idc {
    idelivery: bool,
    iforce: bool,
    ithreshold: u32,
    asserted: bool,
}

struct State {
    domaincfg: u32,
    /// Sources `1..=n` live at index `n - 1`.
    sources: Vec<Source>,
    idcs: Vec<Idc>,
    genmsi: u32,
}

impl State {
    fn msi_mode(&self) -> bool {
        self.domaincfg & DOMAINCFG_DM != 0
    }

    fn src(&self, i: u32) -> Option<&Source> {
        self.sources.get((i as usize).checked_sub(1)?)
    }

    fn src_mut(&mut self, i: u32) -> Option<&mut Source> {
        self.sources.get_mut((i as usize).checked_sub(1)?)
    }

    /// Recomputes a source's pending bit after its input or mode changed.
    fn input_changed(&mut self, i: u32, was: bool) {
        let msi = self.msi_mode();
        let Some(s) = self.src_mut(i) else { return };
        let now = s.rectified();
        match s.mode {
            SM_EDGE_RISING | SM_EDGE_FALLING if now && !was => s.pending = true,
            // A level source: in direct mode the pending bit follows the
            // wire; in MSI mode a rise pends it (it is cleared when sent).
            SM_LEVEL_HIGH | SM_LEVEL_LOW => {
                if msi {
                    s.pending |= now && !was;
                } else {
                    s.pending = now;
                }
            }
            SM_INACTIVE => s.pending = false,
            _ => {}
        }
    }

    /// The sources that would be forwarded to `hart` in direct mode, as the
    /// `topi` value `source << 16 | priority` of the best (lowest priority
    /// number, then lowest source), if it clears `ithreshold`.
    fn topi(&self, hart: usize) -> u32 {
        let Some(idc) = self.idcs.get(hart) else { return 0 };
        let mut best: Option<(u32, u32)> = None;
        for (n, s) in self.sources.iter().enumerate() {
            if !(s.active() && s.pending && s.enabled) || (s.target >> 18) as usize != hart {
                continue;
            }
            let prio = s.target & 0xff;
            if best.is_none_or(|(bp, _)| prio < bp) {
                best = Some((prio, n as u32 + 1));
            }
        }
        match best {
            Some((prio, src)) if idc.ithreshold == 0 || prio < idc.ithreshold => src << 16 | prio,
            _ => 0,
        }
    }

    fn read_word(&mut self, off: u64) -> u32 {
        let n = self.sources.len() as u64;
        match off {
            DOMAINCFG => DOMAINCFG_FIXED | self.domaincfg,
            o if (SOURCECFG..SOURCECFG + 4 * n).contains(&o) => {
                self.src(((o - SOURCECFG) / 4 + 1) as u32).map_or(0, |s| u32::from(s.mode))
            }
            // MSI address configuration is the machine domain's.
            o if (MMSIADDRCFG..=SMSIADDRCFG_H).contains(&o) => 0,
            o if (SETIP..SETIP + 0x80).contains(&o) => self.bits((o - SETIP) as u32 / 4, |s| s.active() && s.pending),
            SETIPNUM => 0,
            o if (IN_CLRIP..IN_CLRIP + 0x80).contains(&o) => self.bits((o - IN_CLRIP) as u32 / 4, |s| s.rectified()),
            CLRIPNUM => 0,
            o if (SETIE..SETIE + 0x80).contains(&o) => self.bits((o - SETIE) as u32 / 4, |s| s.active() && s.enabled),
            SETIENUM | CLRIENUM => 0,
            o if (CLRIE..CLRIE + 0x80).contains(&o) => 0,
            GENMSI => self.genmsi,
            o if (TARGET..TARGET + 4 * n).contains(&o) => {
                self.src(((o - TARGET) / 4 + 1) as u32).map_or(0, |s| s.target)
            }
            o if (IDC..IDC + IDC_SIZE * self.idcs.len() as u64).contains(&o) && !self.msi_mode() => {
                let hart = ((o - IDC) / IDC_SIZE) as usize;
                let Some(idc) = self.idcs.get(hart).copied() else { return 0 };
                match (o - IDC) % IDC_SIZE {
                    0x00 => u32::from(idc.idelivery),
                    0x04 => u32::from(idc.iforce),
                    0x08 => idc.ithreshold,
                    0x18 => self.topi(hart),
                    0x1c => self.claimi(hart),
                    _ => 0,
                }
            }
            _ => 0,
        }
    }

    /// 32 one-bit flags of sources `32 * word ..`.
    fn bits(&self, word: u32, f: impl Fn(&Source) -> bool) -> u32 {
        (0..32u32)
            .filter(|b| {
                let i = word * 32 + b;
                i != 0 && self.src(i).is_some_and(&f)
            })
            .fold(0, |w, b| w | 1 << b)
    }

    /// Reading `claimi`: like `topi`, and takes the interrupt.
    fn claimi(&mut self, hart: usize) -> u32 {
        let top = self.topi(hart);
        let src = top >> 16;
        if src != 0 {
            if let Some(s) = self.src_mut(src) {
                // A level source stays pending while its wire is active.
                s.pending = s.level() && s.rectified();
            }
        } else if let Some(idc) = self.idcs.get_mut(hart) {
            idc.iforce = false;
        }
        top
    }

    fn write_word(&mut self, off: u64, v: u32) {
        let n = self.sources.len() as u64;
        match off {
            DOMAINCFG => {
                // The big-endian bit is read-only zero: this APLIC is little-endian.
                self.domaincfg = v & (DOMAINCFG_IE | DOMAINCFG_DM) & !DOMAINCFG_BE;
            }
            o if (SOURCECFG..SOURCECFG + 4 * n).contains(&o) => {
                let i = ((o - SOURCECFG) / 4 + 1) as u32;
                // D (bit 10, delegate) is read-only zero: there are no child domains.
                let sm = (v & 7) as u8;
                // Reserved modes (2 and 3) read as inactive.
                let sm = if matches!(sm, 2 | 3) { SM_INACTIVE } else { sm };
                if let Some(s) = self.src_mut(i) {
                    s.mode = sm;
                    // A source that becomes inactive loses its pending state.
                    if sm == SM_INACTIVE || sm == SM_DETACHED {
                        s.pending = false;
                    }
                }
                // A level source takes the wire's value; an edge source sees no edge.
                self.input_changed(i, sm < SM_LEVEL_HIGH);
            }
            o if (SETIP..SETIP + 0x80).contains(&o) => self.apply((o - SETIP) as u32 / 4, v, |s| s.pending = true),
            SETIPNUM | SETIPNUM_LE => self.apply_num(v, |s| s.pending = true),
            SETIPNUM_BE => self.apply_num(v.swap_bytes(), |s| s.pending = true),
            o if (IN_CLRIP..IN_CLRIP + 0x80).contains(&o) => {
                // A level source's pending bit follows its wire; only edge ones clear.
                self.apply((o - IN_CLRIP) as u32 / 4, v, |s| s.pending = s.level() && s.rectified());
            }
            CLRIPNUM => self.apply_num(v, |s| s.pending = s.level() && s.rectified()),
            o if (SETIE..SETIE + 0x80).contains(&o) => self.apply((o - SETIE) as u32 / 4, v, |s| s.enabled = true),
            SETIENUM => self.apply_num(v, |s| s.enabled = true),
            o if (CLRIE..CLRIE + 0x80).contains(&o) => self.apply((o - CLRIE) as u32 / 4, v, |s| s.enabled = false),
            CLRIENUM => self.apply_num(v, |s| s.enabled = false),
            GENMSI => self.genmsi = v & (0x3fff << 18 | 0x7ff),
            o if (TARGET..TARGET + 4 * n).contains(&o) => {
                let i = ((o - TARGET) / 4 + 1) as u32;
                let msi = self.msi_mode();
                if let Some(s) = self.src_mut(i) {
                    s.target = if msi {
                        // Hart index, guest index, EIID.
                        v & (0x3fff << 18 | 0x3f << 12 | 0x7ff)
                    } else {
                        // Hart index and priority; priority 0 reads as 1.
                        let prio = (v & 0xff).max(1);
                        v & (0x3fff << 18) | prio
                    };
                }
            }
            o if (IDC..IDC + IDC_SIZE * self.idcs.len() as u64).contains(&o) && !self.msi_mode() => {
                let hart = ((o - IDC) / IDC_SIZE) as usize;
                if let Some(idc) = self.idcs.get_mut(hart) {
                    match (o - IDC) % IDC_SIZE {
                        0x00 => idc.idelivery = v & 1 != 0,
                        0x04 => idc.iforce = v & 1 != 0,
                        0x08 => idc.ithreshold = v & 0xff,
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    /// Applies `f` to the active sources named by the 32 bits of `v` for word `word`.
    fn apply(&mut self, word: u32, v: u32, f: impl Fn(&mut Source)) {
        for b in 0..32u32 {
            let i = word * 32 + b;
            if v & (1 << b) != 0
                && i != 0
                && let Some(s) = self.src_mut(i)
                && s.active()
            {
                f(s);
            }
        }
    }

    fn apply_num(&mut self, i: u32, f: impl Fn(&mut Source)) {
        if let Some(s) = self.src_mut(i)
            && s.active()
        {
            f(s);
        }
    }
}

/// An emulated RISC-V APLIC: one interrupt domain with 1 to 1023 wired
/// sources, in either delivery mode.
///
/// # Scope
///
/// - A single domain, presented at supervisor level (what a guest's APLIC
///   driver programs): `domaincfg`, `sourcecfg` (detached, rising and falling
///   edge, high and low level), `setip`/`in_clrip`/`setie`/`clrie` and their
///   `*num` forms, `setipnum_le/be`, `target`, `genmsi`. No delegation (the
///   `D` bit is read-only zero), no machine-level `mmsiaddrcfg`/`smsiaddrcfg`
///   (read as zero), no big-endian mode.
/// - **MSI delivery** (`domaincfg.DM` = 1): an enabled pending source is sent
///   as a message `(hart, guest, eiid)` to the callback given to
///   [`with_msi`](Self::with_msi), which should write the identity into the
///   target hart's [`VirtualImsic`](super::VirtualImsic); the pending bit then
///   clears. A level source is sent on each rise of its wire.
/// - **Direct delivery** (`DM` = 0): one interrupt delivery control per hart
///   (`idelivery`, `iforce`, `ithreshold`, `topi`, `claimi`); its output
///   line is reported through the callback given to [`new`](Self::new).
///
/// Devices drive sources with [`set_input`](Self::set_input).
pub struct VirtualAplic {
    state: IrqSpinLock<State>,
    wire: Wire,
    msi: Msi,
}

impl VirtualAplic {
    /// An APLIC with `sources` wired sources (1..=1023) and `harts`
    /// interrupt delivery controls for direct mode. `wire(hart, level)`
    /// reports each hart's direct-mode interrupt line.
    pub fn new(sources: usize, harts: usize, wire: impl Fn(usize, bool) + Send + Sync + 'static) -> Self {
        let state = State {
            domaincfg: 0,
            sources: vec![Source::default(); sources.clamp(1, MAX_SOURCES)],
            idcs: vec![Idc::default(); harts.min(MAX_HARTS)],
            genmsi: 0,
        };
        Self { state: IrqSpinLock::new(state), wire: Box::new(wire), msi: Box::new(|_, _, _| {}) }
    }

    /// Sets where MSI-mode messages go: `msi(hart, guest, eiid)`.
    pub fn with_msi(mut self, msi: impl Fn(u32, u32, u32) + Send + Sync + 'static) -> Self {
        self.msi = Box::new(msi);
        self
    }

    /// Size of the register window for `harts` interrupt delivery controls.
    pub const fn mmio_size(harts: usize) -> u64 {
        IDC + IDC_SIZE * harts as u64
    }

    /// Drives source `src` (1-based) to `level`.
    pub fn set_input(&self, src: u32, level: bool) {
        let mut s = self.state.lock();
        let was = match s.src_mut(src) {
            Some(x) => {
                let w = x.rectified();
                x.input = level;
                w
            }
            None => return,
        };
        s.input_changed(src, was);
        self.process(s);
    }

    /// Whether `hart`'s direct-mode interrupt line is asserted.
    pub fn asserted(&self, hart: usize) -> bool {
        self.state.lock().idcs.get(hart).is_some_and(|i| i.asserted)
    }

    /// Forwards what is deliverable: MSIs in MSI mode, the per-hart lines in
    /// direct mode. Consumes the lock so the MSI callback runs without it.
    fn process(&self, mut s: SpinLockGuard<'_, State, IrqDisabled>) {
        let mut msis: Vec<(u32, u32, u32)> = Vec::new();
        let mut lines: Vec<(usize, bool)> = Vec::new();
        if s.domaincfg & DOMAINCFG_IE != 0 && s.msi_mode() {
            for src in s.sources.iter_mut() {
                if src.active() && src.pending && src.enabled {
                    src.pending = false;
                    let eiid = src.target & 0x7ff;
                    if eiid != 0 {
                        msis.push((src.target >> 18, src.target >> 12 & 0x3f, eiid));
                    }
                }
            }
            if s.genmsi & 0x7ff != 0 {
                // A pending `genmsi` is sent at once; it is never busy.
                msis.push((s.genmsi >> 18, 0, s.genmsi & 0x7ff));
                s.genmsi = 0;
            }
        }
        if !s.msi_mode() {
            let ie = s.domaincfg & DOMAINCFG_IE != 0;
            for hart in 0..s.idcs.len() {
                let now = ie && s.idcs.get(hart).is_some_and(|i| i.idelivery && (i.iforce || s.topi(hart) != 0));
                if let Some(idc) = s.idcs.get_mut(hart)
                    && idc.asserted != now
                {
                    idc.asserted = now;
                    lines.push((hart, now));
                }
            }
        }
        drop(s);
        for (hart, level) in lines {
            (self.wire)(hart, level);
        }
        for (hart, guest, eiid) in msis {
            (self.msi)(hart, guest, eiid);
        }
    }
}

impl BusDevice for VirtualAplic {
    fn read(&self, offset: u64, data: &mut [u8]) {
        let mut s = self.state.lock();
        // Registers are 32 bits wide; narrower or unaligned reads pick bytes of the word.
        let v = s.read_word(offset & !3);
        // A claim changes what is pending.
        self.process(s);
        let at = (offset & 3) as usize;
        let b = v.to_le_bytes();
        let mut word = [0u8; 8];
        for (d, s) in word.iter_mut().zip(b.iter().skip(at)) {
            *d = *s;
        }
        put_le(data, u64::from_le_bytes(word));
    }

    fn write(&self, offset: u64, data: &[u8]) {
        if offset & 3 != 0 || data.len() != 4 {
            return;
        }
        let mut s = self.state.lock();
        s.write_word(offset, get_le(data) as u32);
        self.process(s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    fn rd(a: &VirtualAplic, off: u64) -> u32 {
        let mut b = [0u8; 4];
        a.read(off, &mut b);
        u32::from_le_bytes(b)
    }

    fn wr(a: &VirtualAplic, off: u64, v: u32) {
        a.write(off, &v.to_le_bytes());
    }

    type MsiLog = Arc<Mutex<Vec<(u32, u32, u32)>>>;

    fn msi_aplic(sources: usize) -> (VirtualAplic, MsiLog) {
        let log = Arc::new(Mutex::new(Vec::new()));
        let l = log.clone();
        let a = VirtualAplic::new(sources, 2, |_, _| {}).with_msi(move |h, g, e| l.lock().unwrap().push((h, g, e)));
        (a, log)
    }

    #[test]
    fn identification_and_configuration() {
        let (a, _) = msi_aplic(32);
        assert_eq!(rd(&a, DOMAINCFG), 0x8000_0000);
        wr(&a, DOMAINCFG, 0xffff_ffff);
        assert_eq!(rd(&a, DOMAINCFG), 0x8000_0000 | DOMAINCFG_IE | DOMAINCFG_DM, "BE stays clear");
        // sourcecfg: delegation is read-only zero; reserved modes read inactive.
        wr(&a, SOURCECFG, 1 << 10 | SM_LEVEL_HIGH as u32);
        assert_eq!(rd(&a, SOURCECFG), 6);
        wr(&a, SOURCECFG + 4, 2);
        assert_eq!(rd(&a, SOURCECFG + 4), 0);
        // Past the last source: nothing there.
        wr(&a, SOURCECFG + 4 * 32, 6);
        assert_eq!(rd(&a, SOURCECFG + 4 * 32), 0);
        // Targets: MSI layout keeps hart, guest and EIID.
        wr(&a, TARGET, 3 << 18 | 2 << 12 | 0x5);
        assert_eq!(rd(&a, TARGET), 3 << 18 | 2 << 12 | 0x5);
        // The machine's MSI address registers are not here.
        assert_eq!(rd(&a, MMSIADDRCFG), 0);
    }

    #[test]
    fn msi_delivery_edge_level_and_enable() {
        let (a, log) = msi_aplic(32);
        wr(&a, DOMAINCFG, DOMAINCFG_IE | DOMAINCFG_DM);
        // Source 3: rising edge to hart 1, EIID 9. Source 4: high level to hart 0, EIID 6.
        wr(&a, SOURCECFG + 4 * 2, SM_EDGE_RISING as u32);
        wr(&a, TARGET + 4 * 2, 1 << 18 | 9);
        wr(&a, SOURCECFG + 4 * 3, SM_LEVEL_HIGH as u32);
        wr(&a, TARGET + 4 * 3, 6);
        // Pending but not enabled: nothing sent.
        a.set_input(3, true);
        a.set_input(4, true);
        assert_eq!(rd(&a, SETIP), 1 << 3 | 1 << 4);
        assert_eq!(rd(&a, IN_CLRIP), 1 << 3 | 1 << 4, "rectified inputs");
        assert!(log.lock().unwrap().is_empty());
        // Enabling sends each once and clears the pending bits.
        wr(&a, SETIENUM, 3);
        wr(&a, SETIE, 1 << 4);
        assert_eq!(*log.lock().unwrap(), [(1, 0, 9), (0, 0, 6)]);
        assert_eq!(rd(&a, SETIP), 0);
        assert_eq!(rd(&a, SETIE), 1 << 3 | 1 << 4);
        // The edge fires again after a fall and a rise; the held level does not.
        a.set_input(3, false);
        a.set_input(3, true);
        assert_eq!(log.lock().unwrap().len(), 3);
        // The level source fires on each rise.
        a.set_input(4, false);
        a.set_input(4, true);
        assert_eq!(log.lock().unwrap().last(), Some(&(0, 0, 6)));
        // Software can pend a source: setipnum, and the big-endian alias.
        log.lock().unwrap().clear();
        wr(&a, SETIPNUM, 3);
        wr(&a, SETIPNUM_LE, 3);
        wr(&a, SETIPNUM_BE, 3u32.swap_bytes());
        assert_eq!(log.lock().unwrap().len(), 3);
        // Disabled sources stay pending and are sent when enabled.
        wr(&a, CLRIENUM, 3);
        wr(&a, SETIPNUM, 3);
        assert!(rd(&a, SETIP) & 8 != 0);
        assert_eq!(log.lock().unwrap().len(), 3);
        // A global disable holds everything back.
        wr(&a, DOMAINCFG, DOMAINCFG_DM);
        wr(&a, SETIENUM, 3);
        assert_eq!(log.lock().unwrap().len(), 3);
        wr(&a, DOMAINCFG, DOMAINCFG_IE | DOMAINCFG_DM);
        assert_eq!(log.lock().unwrap().len(), 4);
        // genmsi sends an arbitrary message; an inactive source ignores setip.
        wr(&a, GENMSI, 1 << 18 | 0x2a);
        assert_eq!(log.lock().unwrap().last(), Some(&(1, 0, 0x2a)));
        assert_eq!(rd(&a, GENMSI), 0);
        wr(&a, SETIPNUM, 10);
        assert_eq!(rd(&a, SETIP), 0);
    }

    #[test]
    fn falling_edge_and_inverted_level() {
        let (a, log) = msi_aplic(8);
        wr(&a, DOMAINCFG, DOMAINCFG_IE | DOMAINCFG_DM);
        wr(&a, SOURCECFG, SM_EDGE_FALLING as u32);
        wr(&a, TARGET, 1);
        wr(&a, SOURCECFG + 4, SM_LEVEL_LOW as u32);
        wr(&a, TARGET + 4, 2);
        wr(&a, SETIE, 0b110);
        // The low-level source is already active (its wire reads low).
        assert_eq!(*log.lock().unwrap(), [(0, 0, 2)]);
        a.set_input(1, true);
        assert_eq!(log.lock().unwrap().len(), 1);
        a.set_input(1, false);
        assert_eq!(log.lock().unwrap().len(), 2, "a fall");
        // Detached sources take no input at all.
        wr(&a, SOURCECFG + 8, SM_DETACHED as u32);
        a.set_input(3, true);
        assert_eq!(rd(&a, SETIP), 0);
    }

    #[test]
    fn direct_delivery() {
        let lines = Arc::new([AtomicBool::new(false), AtomicBool::new(false)]);
        let l = lines.clone();
        let a = VirtualAplic::new(16, 2, move |h, v| l[h].store(v, Ordering::SeqCst));
        let idc = |hart: u64, reg: u64| IDC + IDC_SIZE * hart + reg;
        wr(&a, DOMAINCFG, DOMAINCFG_IE);
        // Sources 1 and 2 to hart 1 at priorities 5 and 3; source 3 to hart 0.
        for (i, (hart, prio)) in [(1u32, 5u32), (1, 3), (0, 1)].into_iter().enumerate() {
            wr(&a, SOURCECFG + 4 * i as u64, SM_LEVEL_HIGH as u32);
            wr(&a, TARGET + 4 * i as u64, hart << 18 | prio);
        }
        wr(&a, TARGET + 12, 1 << 18); // priority 0 reads back as 1
        assert_eq!(rd(&a, TARGET + 12), 1 << 18 | 1);
        wr(&a, SETIE, 0b1110);
        a.set_input(1, true);
        a.set_input(2, true);
        // idelivery is off: no line, but topi reports.
        assert!(!lines[1].load(Ordering::SeqCst));
        assert_eq!(rd(&a, idc(1, 0x18)), 2 << 16 | 3, "priority 3 beats 5");
        wr(&a, idc(1, 0), 1);
        assert!(lines[1].load(Ordering::SeqCst));
        assert!(!lines[0].load(Ordering::SeqCst));
        // A threshold of 3 masks priority 3 and above; 4 lets source 2 through.
        wr(&a, idc(1, 8), 3);
        assert_eq!(rd(&a, idc(1, 0x18)), 0);
        assert!(!lines[1].load(Ordering::SeqCst));
        wr(&a, idc(1, 8), 4);
        assert!(lines[1].load(Ordering::SeqCst));
        wr(&a, idc(1, 8), 0);
        // claimi: a level source stays pending while its wire is high.
        assert_eq!(rd(&a, idc(1, 0x1c)), 2 << 16 | 3);
        assert_eq!(rd(&a, idc(1, 0x1c)), 2 << 16 | 3);
        a.set_input(2, false);
        assert_eq!(rd(&a, idc(1, 0x1c)), 1 << 16 | 5);
        a.set_input(1, false);
        assert!(!lines[1].load(Ordering::SeqCst));
        // iforce raises the line with nothing pending; claimi clears it.
        wr(&a, idc(1, 4), 1);
        assert!(lines[1].load(Ordering::SeqCst));
        assert_eq!(rd(&a, idc(1, 0x1c)), 0);
        assert!(!lines[1].load(Ordering::SeqCst));
        // IDC registers are absent in MSI mode.
        wr(&a, DOMAINCFG, DOMAINCFG_IE | DOMAINCFG_DM);
        assert_eq!(rd(&a, idc(1, 0)), 0);
    }

    #[test]
    fn odd_accesses_are_ignored() {
        let (a, _) = msi_aplic(4);
        a.write(DOMAINCFG, &[0xff]);
        a.write(DOMAINCFG + 1, &[0xff; 4]);
        a.write(DOMAINCFG, &0x104u64.to_le_bytes());
        assert_eq!(rd(&a, DOMAINCFG), 0x8000_0000);
        let mut b = [0u8; 2];
        a.read(DOMAINCFG + 2, &mut b);
        assert_eq!(b, [0, 0x80]);
        let mut b = [0u8; 8];
        a.read(0x3f_fff0, &mut b);
        assert_eq!(b, [0; 8]);
        wr(&a, 0x1_0000, 1);
        a.set_input(0, true);
        a.set_input(99, true);
    }

    #[test]
    fn aplic_to_imsic_to_hart_line() {
        use super::super::imsic::{VirtualImsic, isel};
        let line = Arc::new(AtomicBool::new(false));
        let l = line.clone();
        let imsic = Arc::new(VirtualImsic::new(1, 255, move |_, v| l.store(v, Ordering::SeqCst)));
        let i = imsic.clone();
        let aplic =
            VirtualAplic::new(8, 1, |_, _| {}).with_msi(move |hart, _guest, eiid| i.set_pending(hart as usize, eiid));
        // What a guest does: file on, identity 5 enabled; APLIC in MSI mode, source 2 -> EIID 5.
        imsic.write_reg(0, isel::EIDELIVERY, 1);
        imsic.write_reg(0, isel::EIE0, 1 << 5);
        wr(&aplic, DOMAINCFG, DOMAINCFG_IE | DOMAINCFG_DM);
        wr(&aplic, SOURCECFG + 4, SM_LEVEL_HIGH as u32);
        wr(&aplic, TARGET + 4, 5);
        wr(&aplic, SETIENUM, 2);
        assert!(!line.load(Ordering::SeqCst));
        aplic.set_input(2, true);
        assert!(line.load(Ordering::SeqCst));
        assert_eq!(imsic.claim(0), 5 << 16 | 5);
        assert!(!line.load(Ordering::SeqCst));
        aplic.set_input(2, false);
    }
}
