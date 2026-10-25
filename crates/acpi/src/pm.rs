//! Power management: entering ACPI mode, sleep states and power off, reset, and the System Control
//! Interrupt (SCI) with the fixed events and general-purpose events (GPEs) behind it.
//!
//! The registers come from the [`Fadt`]; the sleep types come from `_S0_` to `_S5_` and the event
//! handlers from `_Lxx` and `_Exx` in `\_GPE`, so this works on an [`Interpreter`] that has loaded the
//! tables.
//!
//! ```ignore
//! let pm = Pm::new(fadt);
//! pm.enable(aml.host_mut())?;                 // hand the hardware to the OS
//! pm.enable_fixed_events(aml.host_mut(), fixed::POWER_BUTTON)?;
//! pm.enable_gpes(&mut aml)?;
//! // From the SCI handler (or polling):
//! let events = pm.handle_sci(&mut aml)?;
//! if events.fixed & fixed::POWER_BUTTON != 0 { pm.power_off(&mut aml)?; }
//! ```

use alloc::string::String;
use alloc::vec::Vec;

use crate::aml::{AmlError, Host, HostError, Interpreter, NameSeg, PciAddress, Value, space};
use crate::fadt::{Fadt, Gas, flags};

/// Bits of the PM1 status and enable registers.
pub mod fixed {
    /// The PM timer's top bit changed.
    pub const TIMER: u16 = 1 << 0;
    /// The firmware released the global lock.
    pub const GLOBAL_LOCK: u16 = 1 << 5;
    /// The power button was pressed.
    pub const POWER_BUTTON: u16 = 1 << 8;
    /// The sleep button was pressed.
    pub const SLEEP_BUTTON: u16 = 1 << 9;
    /// The real-time clock alarm went off.
    pub const RTC_ALARM: u16 = 1 << 10;
    /// A PCI Express wake event (status only).
    pub const PCIE_WAKE: u16 = 1 << 14;
    /// The system woke from sleep (status only).
    pub const WAKE: u16 = 1 << 15;
    /// The events that can be enabled and that raise the SCI.
    pub const ENABLEABLE: u16 = TIMER | GLOBAL_LOCK | POWER_BUTTON | SLEEP_BUTTON | RTC_ALARM;
}

const SCI_EN: u64 = 1 << 0;
const SLP_TYP_SHIFT: u32 = 10;
const SLP_TYP_MASK: u64 = 0x7 << SLP_TYP_SHIFT;
const SLP_EN: u64 = 1 << 13;

/// Why a power-management operation failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PmError {
    /// AML failed.
    Aml(AmlError),
    /// A register access failed.
    Host(HostError),
    /// The machine lacks what was asked for (named).
    Unsupported(&'static str),
    /// The hardware did not respond in time.
    Timeout,
    /// There is no such sleep state, or the firmware does not offer it (`_Sx_` is missing).
    NoSuchState(u8),
}

impl From<AmlError> for PmError {
    fn from(e: AmlError) -> Self {
        PmError::Aml(e)
    }
}

impl From<HostError> for PmError {
    fn from(e: HostError) -> Self {
        PmError::Host(e)
    }
}

/// What one pass of [`Pm::handle_sci`] found and did.
#[derive(Debug, Default)]
pub struct SciEvents {
    /// Fixed events that were pending and enabled, as [`fixed`] bits. They are cleared.
    pub fixed: u16,
    /// GPEs whose handler ran.
    pub gpes: Vec<u16>,
    /// GPEs that were pending but have no `_Lxx` or `_Exx`; they are disabled so they cannot storm.
    pub unhandled: Vec<u16>,
    /// Handlers that failed, by path.
    pub errors: Vec<(String, AmlError)>,
}

/// Power management of one machine.
#[derive(Clone, Debug)]
pub struct Pm {
    fadt: Fadt,
}

fn read_gas<H: Host>(host: &mut H, gas: &Gas, bits: u8) -> Result<u64, PmError> {
    Ok(match gas.space {
        space::SYSTEM_MEMORY => host.read_memory(gas.address, bits)?,
        space::SYSTEM_IO => host.read_io(u16::try_from(gas.address).map_err(|_| HostError::Fault)?, bits)?,
        space::PCI_CONFIG => {
            let (at, off) = pci_gas(gas);
            host.read_pci(at, off, bits)?
        }
        _ => return Err(PmError::Unsupported("register address space")),
    })
}

fn write_gas<H: Host>(host: &mut H, gas: &Gas, bits: u8, value: u64) -> Result<(), PmError> {
    match gas.space {
        space::SYSTEM_MEMORY => host.write_memory(gas.address, bits, value)?,
        space::SYSTEM_IO => host.write_io(u16::try_from(gas.address).map_err(|_| HostError::Fault)?, bits, value)?,
        space::PCI_CONFIG => {
            let (at, off) = pci_gas(gas);
            host.write_pci(at, off, bits, value)?;
        }
        _ => return Err(PmError::Unsupported("register address space")),
    }
    Ok(())
}

/// A PCI configuration register as a GAS: device in bits 32 to 47, function in 16 to 31, offset in 0 to 15,
/// on bus 0 of segment 0.
fn pci_gas(gas: &Gas) -> (PciAddress, u16) {
    let a = gas.address;
    (PciAddress { segment: 0, bus: 0, device: (a >> 32) as u8 & 0x1f, function: (a >> 16) as u8 & 7 }, a as u16)
}

fn at(gas: &Gas, bytes: u64) -> Gas {
    Gas { address: gas.address.wrapping_add(bytes), ..*gas }
}

impl Pm {
    /// Power management for the machine whose FADT is `fadt`.
    pub fn new(fadt: Fadt) -> Self {
        Self { fadt }
    }

    /// The FADT.
    pub fn fadt(&self) -> &Fadt {
        &self.fadt
    }

    // ----- ACPI mode -----

    /// Whether the hardware is in ACPI mode (`SCI_EN`). Hardware-reduced machines always are.
    pub fn acpi_enabled<H: Host>(&self, host: &mut H) -> Result<bool, PmError> {
        if self.fadt.hw_reduced() {
            return Ok(true);
        }
        Ok(read_gas(host, &self.fadt.pm1a_cnt, 16)? & SCI_EN != 0)
    }

    /// Switches the hardware from legacy to ACPI mode, which makes it raise the SCI for events: writes
    /// `ACPI_ENABLE` to the SMI command port and waits for `SCI_EN`. Does nothing if the firmware already did.
    pub fn enable<H: Host>(&self, host: &mut H) -> Result<(), PmError> {
        if self.acpi_enabled(host)? {
            return Ok(());
        }
        let port = u16::try_from(self.fadt.smi_cmd).map_err(|_| PmError::Unsupported("SMI command port"))?;
        if port == 0 || self.fadt.acpi_enable == 0 {
            return Err(PmError::Unsupported("switching to ACPI mode"));
        }
        host.write_io(port, 8, u64::from(self.fadt.acpi_enable))?;
        self.wait_for(host, |h| Ok(read_gas(h, &self.fadt.pm1a_cnt, 16)? & SCI_EN != 0))
    }

    /// Hands the hardware back to the legacy (SMI) interface.
    pub fn disable<H: Host>(&self, host: &mut H) -> Result<(), PmError> {
        let port = u16::try_from(self.fadt.smi_cmd).map_err(|_| PmError::Unsupported("SMI command port"))?;
        if port == 0 || self.fadt.acpi_disable == 0 {
            return Err(PmError::Unsupported("switching to legacy mode"));
        }
        host.write_io(port, 8, u64::from(self.fadt.acpi_disable))?;
        self.wait_for(host, |h| Ok(read_gas(h, &self.fadt.pm1a_cnt, 16)? & SCI_EN == 0))
    }

    /// Polls `done` for up to about 3 seconds.
    fn wait_for<H: Host>(
        &self,
        host: &mut H,
        mut done: impl FnMut(&mut H) -> Result<bool, PmError>,
    ) -> Result<(), PmError> {
        for _ in 0..3000 {
            if done(host)? {
                return Ok(());
            }
            host.stall(1000);
        }
        Err(PmError::Timeout)
    }

    /// The PM timer: a 3.579545 MHz counter, 24 bits wide or 32 if the FADT says so.
    pub fn timer<H: Host>(&self, host: &mut H) -> Result<u32, PmError> {
        let v = read_gas(host, &self.fadt.pm_tmr, 32)? as u32;
        Ok(if self.fadt.flags & flags::TMR_VAL_EXT != 0 { v } else { v & 0x00ff_ffff })
    }

    // ----- sleep states -----

    /// The `SLP_TYPa` and `SLP_TYPb` values for sleep state `state` (0 to 5), from `\_Sx_`.
    pub fn sleep_types<H: Host>(&self, aml: &mut Interpreter<H>, state: u8) -> Result<(u8, u8), PmError> {
        if state > 5 {
            return Err(PmError::NoSuchState(state));
        }
        let path = alloc::format!("\\_S{state}_");
        let v = match aml.evaluate(&path, &[]) {
            Ok(v) => v,
            Err(AmlError::NotFound) => return Err(PmError::NoSuchState(state)),
            Err(e) => return Err(e.into()),
        };
        let Value::Package(p) = v else { return Err(PmError::Aml(AmlError::TypeMismatch)) };
        let typ = |i: usize| match p.get(i) {
            Some(Value::Integer(v)) => Ok(*v as u8 & 7),
            Some(Value::Buffer(b)) => Ok(b.first().copied().unwrap_or(0) & 7),
            _ => Err(PmError::Aml(AmlError::TypeMismatch)),
        };
        Ok((typ(0)?, typ(1)?))
    }

    /// Runs `\name(arg)` if the firmware defines it.
    fn optional_method<H: Host>(aml: &mut Interpreter<H>, name: &str, arg: u8) -> Result<(), PmError> {
        match aml.evaluate(name, &[Value::Integer(u64::from(arg))]) {
            Ok(_) | Err(AmlError::NotFound) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Puts the machine in sleep state `state` (1 to 5): runs `_TTS`, `_PTS` and `_GTS`, then writes the
    /// sleep type and `SLP_EN` to the PM1 control registers.
    ///
    /// The caller prepares the machine first: devices quiesced, other CPUs stopped, interrupts off, caches
    /// written back. For S1 to S3 this waits for the wake (`WAK_STS`), then runs `_WAK`, and returns `Ok`.
    /// For S4 and S5 the hardware acts at once: if this returns the machine did not power off (S5) or did
    /// not hibernate.
    pub fn enter_sleep_state<H: Host>(&self, aml: &mut Interpreter<H>, state: u8) -> Result<(), PmError> {
        if !(1..=5).contains(&state) {
            return Err(PmError::NoSuchState(state));
        }
        let (typ_a, typ_b) = self.sleep_types(aml, state)?;
        Self::optional_method(aml, "\\_TTS", state)?;
        Self::optional_method(aml, "\\_PTS", state)?;
        Self::optional_method(aml, "\\_GTS", state)?;
        let host = aml.host_mut();
        if self.fadt.hw_reduced() {
            let ctl = &self.fadt.sleep_control;
            if ctl.is_empty() {
                return Err(PmError::Unsupported("sleep control register"));
            }
            write_gas(host, ctl, 8, u64::from(typ_a) << 2 | 1 << 5)?;
        } else {
            self.write_pm1_status(host, fixed::WAKE)?;
            for (reg, typ) in [(&self.fadt.pm1a_cnt, typ_a), (&self.fadt.pm1b_cnt, typ_b)] {
                if reg.is_empty() {
                    continue;
                }
                // The type first, then the enable bit, as the specification has it.
                let cur = read_gas(host, reg, 16)? & !(SLP_TYP_MASK | SLP_EN);
                let with_type = cur | u64::from(typ) << SLP_TYP_SHIFT;
                write_gas(host, reg, 16, with_type)?;
                write_gas(host, reg, 16, with_type | SLP_EN)?;
            }
        }
        if (1..=3).contains(&state) && !self.fadt.hw_reduced() {
            self.wait_for(aml.host_mut(), |h| Ok(self.read_pm1_status(h)? & fixed::WAKE != 0))?;
            self.write_pm1_status(aml.host_mut(), fixed::WAKE)?;
            Self::optional_method(aml, "\\_WAK", state)?;
        } else {
            // Give the hardware a moment to act, so a caller that halts afterwards is not racing it.
            aml.host_mut().stall(100_000);
        }
        Ok(())
    }

    /// Powers the machine off (S5).
    pub fn power_off<H: Host>(&self, aml: &mut Interpreter<H>) -> Result<(), PmError> {
        self.enter_sleep_state(aml, 5)
    }

    /// Resets the machine through the FADT's reset register.
    pub fn reset<H: Host>(&self, host: &mut H) -> Result<(), PmError> {
        let reg = &self.fadt.reset_reg;
        if self.fadt.flags & flags::RESET_REG_SUP == 0 || reg.is_empty() {
            return Err(PmError::Unsupported("reset register"));
        }
        write_gas(host, reg, 8, u64::from(self.fadt.reset_value))
    }

    // ----- fixed events -----

    fn pm1_blocks(&self) -> impl Iterator<Item = (Gas, Gas)> + '_ {
        let half = u64::from(self.fadt.pm1_evt_len / 2);
        [&self.fadt.pm1a_evt, &self.fadt.pm1b_evt]
            .into_iter()
            .filter(move |g| !g.is_empty() && half >= 2)
            .map(move |g| (*g, at(g, half)))
    }

    fn read_pm1_status<H: Host>(&self, host: &mut H) -> Result<u16, PmError> {
        let mut v = 0;
        for (sts, _) in self.pm1_blocks() {
            v |= read_gas(host, &sts, 16)? as u16;
        }
        Ok(v)
    }

    fn write_pm1_status<H: Host>(&self, host: &mut H, bits: u16) -> Result<(), PmError> {
        for (sts, _) in self.pm1_blocks() {
            write_gas(host, &sts, 16, u64::from(bits))?;
        }
        Ok(())
    }

    /// Enables the fixed events in `mask` (see [`fixed`]), so they raise the SCI.
    pub fn enable_fixed_events<H: Host>(&self, host: &mut H, mask: u16) -> Result<(), PmError> {
        self.update_pm1_enable(host, |en| en | (mask & fixed::ENABLEABLE))
    }

    /// Disables the fixed events in `mask`.
    pub fn disable_fixed_events<H: Host>(&self, host: &mut H, mask: u16) -> Result<(), PmError> {
        self.update_pm1_enable(host, |en| en & !mask)
    }

    fn update_pm1_enable<H: Host>(&self, host: &mut H, f: impl Fn(u16) -> u16) -> Result<(), PmError> {
        let mut any = false;
        for (_, en) in self.pm1_blocks() {
            any = true;
            let cur = read_gas(host, &en, 16)? as u16;
            write_gas(host, &en, 16, u64::from(f(cur)))?;
        }
        if any { Ok(()) } else { Err(PmError::Unsupported("PM1 event registers")) }
    }

    // ----- general-purpose events -----

    /// The status and enable registers of GPE `n`, and its bit in them.
    fn gpe_registers(&self, n: u16) -> Option<(Gas, Gas, u8)> {
        let f = &self.fadt;
        for (blk, len, base) in [(&f.gpe0, f.gpe0_len, 0u16), (&f.gpe1, f.gpe1_len, u16::from(f.gpe1_base))] {
            let regs = u16::from(len / 2);
            if blk.is_empty() || n < base || n - base >= regs * 8 {
                continue;
            }
            let i = u64::from((n - base) / 8);
            return Some((at(blk, i), at(blk, u64::from(regs) + i), ((n - base) % 8) as u8));
        }
        None
    }

    /// How many GPEs the machine has: the end of the highest block.
    fn gpe_count(&self) -> u16 {
        let f = &self.fadt;
        let end0 = if f.gpe0.is_empty() { 0 } else { u16::from(f.gpe0_len / 2) * 8 };
        let end1 = if f.gpe1.is_empty() { 0 } else { u16::from(f.gpe1_base) + u16::from(f.gpe1_len / 2) * 8 };
        end0.max(end1)
    }

    /// Enables GPE `n`, clearing any stale event first.
    pub fn enable_gpe<H: Host>(&self, host: &mut H, n: u16) -> Result<(), PmError> {
        let (sts, en, bit) = self.gpe_registers(n).ok_or(PmError::Unsupported("no such GPE"))?;
        write_gas(host, &sts, 8, 1 << bit)?;
        let cur = read_gas(host, &en, 8)?;
        write_gas(host, &en, 8, cur | 1 << bit)
    }

    /// Disables GPE `n`.
    pub fn disable_gpe<H: Host>(&self, host: &mut H, n: u16) -> Result<(), PmError> {
        let (_, en, bit) = self.gpe_registers(n).ok_or(PmError::Unsupported("no such GPE"))?;
        let cur = read_gas(host, &en, 8)?;
        write_gas(host, &en, 8, cur & !(1 << bit))
    }

    /// Enables every GPE the firmware has a handler for (`_Lxx` or `_Exx` in `\_GPE`) and returns their
    /// numbers.
    pub fn enable_gpes<H: Host>(&self, aml: &mut Interpreter<H>) -> Result<Vec<u16>, PmError> {
        let mut enabled = Vec::new();
        let Some(scope) = aml.namespace().find("\\_GPE") else { return Ok(enabled) };
        let mut numbers: Vec<u16> = aml.namespace().children(scope).filter_map(|(seg, _)| gpe_number(seg)).collect();
        numbers.sort_unstable();
        numbers.dedup();
        for n in numbers {
            if n < self.gpe_count() && self.gpe_registers(n).is_some() {
                self.enable_gpe(aml.host_mut(), n)?;
                enabled.push(n);
            }
        }
        Ok(enabled)
    }

    // ----- the SCI -----

    /// Services the System Control Interrupt: finds the fixed events and GPEs that are both pending and
    /// enabled, clears them, and runs the handlers of GPEs.
    ///
    /// An edge-triggered GPE (`_Exx`) is cleared before its method runs; a level-triggered one (`_Lxx`) is
    /// disabled while the method runs, then cleared and enabled again. The method usually ends in a
    /// `Notify`, which reaches the host.
    pub fn handle_sci<H: Host>(&self, aml: &mut Interpreter<H>) -> Result<SciEvents, PmError> {
        let mut ev = SciEvents::default();
        if !self.fadt.hw_reduced() {
            let host = aml.host_mut();
            let (mut sts, mut en) = (0u16, 0u16);
            for (s, e) in self.pm1_blocks() {
                sts |= read_gas(host, &s, 16)? as u16;
                en |= read_gas(host, &e, 16)? as u16;
            }
            let pending = sts & en & fixed::ENABLEABLE;
            if pending != 0 {
                self.write_pm1_status(host, pending)?;
                ev.fixed = pending;
            }
        }
        for n in 0..self.gpe_count() {
            let Some((sts, en, bit)) = self.gpe_registers(n) else { continue };
            let host = aml.host_mut();
            let pending = read_gas(host, &sts, 8)? & read_gas(host, &en, 8)?;
            if pending & 1 << bit == 0 {
                continue;
            }
            self.dispatch_gpe(aml, n, (sts, en, bit), &mut ev)?;
        }
        Ok(ev)
    }

    fn dispatch_gpe<H: Host>(
        &self,
        aml: &mut Interpreter<H>,
        n: u16,
        (sts, en, bit): (Gas, Gas, u8),
        ev: &mut SciEvents,
    ) -> Result<(), PmError> {
        let level = alloc::format!("\\_GPE._L{n:02X}");
        let edge = alloc::format!("\\_GPE._E{n:02X}");
        let (path, is_level) = if aml.namespace().find(&level).is_some() {
            (level, true)
        } else if aml.namespace().find(&edge).is_some() {
            (edge, false)
        } else {
            self.disable_gpe(aml.host_mut(), n)?;
            write_gas(aml.host_mut(), &sts, 8, 1 << bit)?;
            ev.unhandled.push(n);
            return Ok(());
        };
        if is_level {
            let cur = read_gas(aml.host_mut(), &en, 8)?;
            write_gas(aml.host_mut(), &en, 8, cur & !(1 << bit))?;
        } else {
            write_gas(aml.host_mut(), &sts, 8, 1 << bit)?;
        }
        if let Err(e) = aml.evaluate(&path, &[]) {
            ev.errors.push((path, e));
        }
        if is_level {
            write_gas(aml.host_mut(), &sts, 8, 1 << bit)?;
            let cur = read_gas(aml.host_mut(), &en, 8)?;
            write_gas(aml.host_mut(), &en, 8, cur | 1 << bit)?;
        }
        ev.gpes.push(n);
        Ok(())
    }
}

/// The GPE number in a method name `_Lxx` or `_Exx`.
fn gpe_number(seg: NameSeg) -> Option<u16> {
    let [b'_', kind, hi, lo] = seg.0 else { return None };
    if kind != b'L' && kind != b'E' {
        return None;
    }
    let digit = |c: u8| char::from(c).to_digit(16).filter(|_| !c.is_ascii_lowercase());
    Some((digit(hi)? * 16 + digit(lo)?) as u16)
}
