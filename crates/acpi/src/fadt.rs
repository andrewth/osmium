//! The Fixed ACPI Description Table (`FACP`): where the power-management registers are.

use osmium_boot::acpi::Table;

use crate::aml::space;

/// A Generic Address Structure: a register in memory or I/O space.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Gas {
    /// Address space: 0 system memory, 1 system I/O.
    pub space: u8,
    /// Register width in bits (0 when unspecified).
    pub bit_width: u8,
    /// Offset of the register within the addressed unit, in bits.
    pub bit_offset: u8,
    /// Access size: 0 undefined, 1 byte, 2 word, 3 dword, 4 qword.
    pub access_size: u8,
    /// The address.
    pub address: u64,
}

impl Gas {
    /// An I/O-port register of `len` bytes at `port`; empty (`None`) if either is 0.
    pub fn io(port: u32, len: u8) -> Option<Self> {
        (port != 0 && len != 0).then_some(Self {
            space: space::SYSTEM_IO,
            bit_width: len.saturating_mul(8),
            bit_offset: 0,
            access_size: 0,
            address: u64::from(port),
        })
    }

    /// Whether the register is absent (a zero address).
    pub fn is_empty(&self) -> bool {
        self.address == 0
    }

    fn parse(b: &[u8]) -> Self {
        Self {
            space: b.first().copied().unwrap_or(0),
            bit_width: b.get(1).copied().unwrap_or(0),
            bit_offset: b.get(2).copied().unwrap_or(0),
            access_size: b.get(3).copied().unwrap_or(0),
            address: b.get(4..12).and_then(|a| a.first_chunk().copied()).map_or(0, u64::from_le_bytes),
        }
    }
}

/// Flags in [`Fadt::flags`].
pub mod flags {
    /// The power button is handled by control-method code, not the fixed-feature register.
    pub const PWR_BUTTON: u32 = 1 << 4;
    /// The sleep button is handled by control-method code.
    pub const SLP_BUTTON: u32 = 1 << 5;
    /// The PM timer is 32 bits wide, not 24.
    pub const TMR_VAL_EXT: u32 = 1 << 8;
    /// `reset_reg` is valid.
    pub const RESET_REG_SUP: u32 = 1 << 10;
    /// ACPI hardware-reduced: no fixed hardware registers.
    pub const HW_REDUCED_ACPI: u32 = 1 << 20;
}

/// The parts of the FADT that matter to power management.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Fadt {
    /// Table revision.
    pub revision: u8,
    /// Physical address of the FACS (32-bit field).
    pub firmware_ctrl: u64,
    /// Physical address of the DSDT; the 64-bit field if set, else the 32-bit one.
    pub dsdt: u64,
    /// System Control Interrupt (a GSI, or an ISA IRQ number on legacy hardware).
    pub sci_int: u16,
    /// I/O port of the SMI command register.
    pub smi_cmd: u32,
    /// Value written to `smi_cmd` to hand the hardware to the OS.
    pub acpi_enable: u8,
    /// Value written to `smi_cmd` to hand it back.
    pub acpi_disable: u8,
    /// PM1a event register block (status, then enable).
    pub pm1a_evt: Gas,
    /// PM1b event register block.
    pub pm1b_evt: Gas,
    /// PM1a control register.
    pub pm1a_cnt: Gas,
    /// PM1b control register.
    pub pm1b_cnt: Gas,
    /// PM timer register.
    pub pm_tmr: Gas,
    /// Length in bytes of each PM1 event block (status plus enable).
    pub pm1_evt_len: u8,
    /// General-purpose event block 0 (status registers, then enable registers).
    pub gpe0: Gas,
    /// Length in bytes of GPE block 0.
    pub gpe0_len: u8,
    /// General-purpose event block 1.
    pub gpe1: Gas,
    /// Length in bytes of GPE block 1.
    pub gpe1_len: u8,
    /// GPE number of the first event in block 1.
    pub gpe1_base: u8,
    /// Fixed feature flags (see [`flags`]).
    pub flags: u32,
    /// The sleep control register of a hardware-reduced machine.
    pub sleep_control: Gas,
    /// The sleep status register of a hardware-reduced machine.
    pub sleep_status: Gas,
    /// The reset register.
    pub reset_reg: Gas,
    /// Value written to `reset_reg` to reset the machine.
    pub reset_value: u8,
    /// IA-PC boot architecture flags (legacy devices, 8042, VGA not present, ...).
    pub iapc_boot_arch: u16,
}

impl Fadt {
    /// Reads a `FACP` table.
    pub fn parse(t: Table<'_>) -> Option<Self> {
        if &t.signature() != b"FACP" {
            return None;
        }
        let d = t.data;
        let u8_at = |o: usize| d.get(o).copied();
        let u16_at = |o: usize| Some(u16::from_le_bytes(*d.get(o..)?.first_chunk()?));
        let u32_at = |o: usize| Some(u32::from_le_bytes(*d.get(o..)?.first_chunk()?));
        let u64_at = |o: usize| Some(u64::from_le_bytes(*d.get(o..)?.first_chunk()?));
        let gas_at = |o: usize| d.get(o..o + 12).map(Gas::parse);
        // The extended fields exist from revision 2 on; a short table has only the legacy ones.
        let extended = |o: usize| gas_at(o).filter(|g| !g.is_empty());
        let legacy = |port: usize, len: usize| Gas::io(u32_at(port)?, u8_at(len)?);
        let pick = |x: usize, port: usize, len: usize| extended(x).or_else(|| legacy(port, len)).unwrap_or_default();
        let dsdt = u64_at(140).filter(|&a| a != 0).or_else(|| u32_at(40).map(u64::from)).unwrap_or(0);
        Some(Self {
            revision: u8_at(8)?,
            firmware_ctrl: u64_at(132).filter(|&a| a != 0).or_else(|| u32_at(36).map(u64::from)).unwrap_or(0),
            dsdt,
            sci_int: u16_at(46)?,
            smi_cmd: u32_at(48)?,
            acpi_enable: u8_at(52)?,
            acpi_disable: u8_at(53)?,
            pm1a_evt: pick(148, 56, 88),
            pm1b_evt: pick(160, 60, 88),
            pm1a_cnt: pick(172, 64, 89),
            pm1b_cnt: pick(184, 68, 89),
            pm_tmr: pick(208, 76, 91),
            pm1_evt_len: u8_at(88)?,
            gpe0: pick(220, 80, 92),
            gpe0_len: u8_at(92)?,
            gpe1: pick(232, 84, 93),
            gpe1_len: u8_at(93)?,
            gpe1_base: u8_at(94)?,
            flags: u32_at(112)?,
            sleep_control: gas_at(244).unwrap_or_default(),
            sleep_status: gas_at(256).unwrap_or_default(),
            reset_reg: gas_at(116).unwrap_or_default(),
            reset_value: u8_at(128).unwrap_or(0),
            iapc_boot_arch: u16_at(109).unwrap_or(0),
        })
    }

    /// Physical address of the DSDT.
    pub fn dsdt_address(&self) -> u64 {
        self.dsdt
    }

    /// Whether the machine is hardware-reduced ACPI, with no fixed registers to drive.
    pub fn hw_reduced(&self) -> bool {
        self.flags & flags::HW_REDUCED_ACPI != 0
    }
}
