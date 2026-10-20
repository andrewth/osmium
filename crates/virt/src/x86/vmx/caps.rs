//! What the CPU's VMX capability MSRs allow, and the controls a [`VmxVcpu`](super::VmxVcpu) asks for.

/// VMX capability MSRs (Intel SDM vol. 3D, appendix A).
pub mod msr {
    /// Revision identifier, VMCS size, and whether the TRUE_* MSRs exist.
    pub const BASIC: u32 = 0x480;
    /// Pin-based controls.
    pub const PINBASED: u32 = 0x481;
    /// Primary processor-based controls.
    pub const PROCBASED: u32 = 0x482;
    /// VM-exit controls.
    pub const EXIT: u32 = 0x483;
    /// VM-entry controls.
    pub const ENTRY: u32 = 0x484;
    /// Bits CR0 must have set while in VMX operation.
    pub const CR0_FIXED0: u32 = 0x486;
    /// Bits CR0 may have set.
    pub const CR0_FIXED1: u32 = 0x487;
    /// Bits CR4 must have set.
    pub const CR4_FIXED0: u32 = 0x488;
    /// Bits CR4 may have set.
    pub const CR4_FIXED1: u32 = 0x489;
    /// Secondary processor-based controls.
    pub const PROCBASED2: u32 = 0x48b;
    /// EPT and VPID capabilities.
    pub const EPT_VPID_CAP: u32 = 0x48c;
    /// Pin-based controls, when bit 55 of `BASIC` is set.
    pub const TRUE_PINBASED: u32 = 0x48d;
    /// Primary controls, when bit 55 of `BASIC` is set.
    pub const TRUE_PROCBASED: u32 = 0x48e;
    /// Exit controls, when bit 55 of `BASIC` is set.
    pub const TRUE_EXIT: u32 = 0x48f;
    /// Entry controls, when bit 55 of `BASIC` is set.
    pub const TRUE_ENTRY: u32 = 0x490;
}

/// Pin-based control bits.
pub mod pin {
    /// Host interrupts exit.
    pub const EXTERNAL_INTERRUPT: u32 = 1 << 0;
    /// NMIs exit.
    pub const NMI: u32 = 1 << 3;
}

/// Primary processor-based control bits.
pub mod proc {
    /// Exit when the guest can take an interrupt.
    pub const INTERRUPT_WINDOW: u32 = 1 << 2;
    /// HLT exits.
    pub const HLT: u32 = 1 << 7;
    /// MWAIT exits.
    pub const MWAIT: u32 = 1 << 10;
    /// RDPMC exits.
    pub const RDPMC: u32 = 1 << 11;
    /// MOV to CR8 exits.
    pub const CR8_LOAD: u32 = 1 << 19;
    /// MOV from CR8 exits.
    pub const CR8_STORE: u32 = 1 << 20;
    /// MOV to and from debug registers exit.
    pub const MOV_DR: u32 = 1 << 23;
    /// Every I/O instruction exits.
    pub const UNCONDITIONAL_IO: u32 = 1 << 24;
    /// The MSR bitmap decides which RDMSR/WRMSR exit.
    pub const MSR_BITMAPS: u32 = 1 << 28;
    /// MONITOR exits.
    pub const MONITOR: u32 = 1 << 29;
    /// The secondary controls exist.
    pub const SECONDARY: u32 = 1 << 31;
}

/// Secondary processor-based control bits.
pub mod proc2 {
    /// Extended page tables.
    pub const EPT: u32 = 1 << 1;
    /// RDTSCP is available to the guest.
    pub const RDTSCP: u32 = 1 << 3;
    /// Virtual processor identifiers tag the TLB.
    pub const VPID: u32 = 1 << 5;
    /// WBINVD exits.
    pub const WBINVD: u32 = 1 << 6;
    /// Real mode and unpaged protected mode run natively.
    pub const UNRESTRICTED_GUEST: u32 = 1 << 7;
}

/// VM-exit control bits.
pub mod exit_ctl {
    /// The host is in 64-bit mode.
    pub const HOST_64: u32 = 1 << 9;
    /// Save the guest's PAT.
    pub const SAVE_PAT: u32 = 1 << 18;
    /// Load the host's PAT.
    pub const LOAD_PAT: u32 = 1 << 19;
    /// Save the guest's EFER.
    pub const SAVE_EFER: u32 = 1 << 20;
    /// Load the host's EFER.
    pub const LOAD_EFER: u32 = 1 << 21;
}

/// VM-entry control bits.
pub mod entry_ctl {
    /// The guest is in IA-32e mode (EFER.LMA).
    pub const IA32E_GUEST: u32 = 1 << 9;
    /// Load the guest's PAT.
    pub const LOAD_PAT: u32 = 1 << 14;
    /// Load the guest's EFER.
    pub const LOAD_EFER: u32 = 1 << 15;
}

/// Why VMX cannot be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmxError {
    /// The CPU does not implement VMX.
    Unsupported,
    /// Firmware locked `IA32_FEATURE_CONTROL` with VMXON disabled.
    Disabled,
    /// A control the vCPU needs (the payload names its MSR) is not available.
    MissingControl(u32),
    /// The CPU lacks 4-level write-back EPT, INVEPT or INVVPID.
    NoEpt,
    /// The CPU has no task register loaded; VM exit needs one for the host
    /// (load a TSS with `CpuTables::load` first).
    NoTaskRegister,
}

/// The adjusted controls and fixed bits of this machine's CPUs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caps {
    /// VMCS revision identifier.
    pub revision: u32,
    /// Pin-based controls.
    pub pin: u32,
    /// Primary processor-based controls (without the interrupt window).
    pub proc: u32,
    /// Secondary processor-based controls.
    pub proc2: u32,
    /// VM-exit controls.
    pub exit: u32,
    /// VM-entry controls (without IA-32e mode guest).
    pub entry: u32,
    /// CR0 bits that must be 1.
    pub cr0_fixed0: u64,
    /// CR0 bits that may be 1.
    pub cr0_fixed1: u64,
    /// CR4 bits that must be 1.
    pub cr4_fixed0: u64,
    /// CR4 bits that may be 1.
    pub cr4_fixed1: u64,
    /// INVEPT type to use: 1 (single context) or 2 (all contexts).
    pub invept: u64,
    /// INVVPID type to use: 1 (single context) or 2 (all contexts).
    pub invvpid: u64,
}

/// `want`, plus the bits the CPU forces to 1, if the CPU can set every bit
/// of `want`. `cap` is a capability MSR: bits 31:0 must be 1, bits 63:32 may be 1.
pub fn adjust(want: u32, cap: u64) -> Option<u32> {
    let (must, may) = (cap as u32, (cap >> 32) as u32);
    (want & !may == 0).then_some(want | must)
}

impl Caps {
    /// The controls a vCPU wants.
    pub const PIN: u32 = pin::EXTERNAL_INTERRUPT | pin::NMI;
    /// See [`Caps::PIN`].
    pub const PROC: u32 = proc::HLT
        | proc::MWAIT
        | proc::RDPMC
        | proc::CR8_LOAD
        | proc::CR8_STORE
        | proc::MOV_DR
        | proc::UNCONDITIONAL_IO
        | proc::MSR_BITMAPS
        | proc::MONITOR
        | proc::SECONDARY;
    /// See [`Caps::PIN`].
    pub const PROC2: u32 = proc2::EPT | proc2::RDTSCP | proc2::VPID | proc2::WBINVD | proc2::UNRESTRICTED_GUEST;
    /// See [`Caps::PIN`].
    pub const EXIT: u32 =
        exit_ctl::HOST_64 | exit_ctl::SAVE_PAT | exit_ctl::LOAD_PAT | exit_ctl::SAVE_EFER | exit_ctl::LOAD_EFER;
    /// See [`Caps::PIN`].
    pub const ENTRY: u32 = entry_ctl::LOAD_PAT | entry_ctl::LOAD_EFER;

    /// Reads the capability MSRs through `rdmsr` and picks the controls.
    pub fn from_msrs(rdmsr: impl Fn(u32) -> u64) -> Result<Self, VmxError> {
        let basic = rdmsr(msr::BASIC);
        let t = basic & (1 << 55) != 0;
        let pick =
            |want, std, tru, name| adjust(want, rdmsr(if t { tru } else { std })).ok_or(VmxError::MissingControl(name));
        let pin = pick(Self::PIN, msr::PINBASED, msr::TRUE_PINBASED, msr::TRUE_PINBASED)?;
        let proc = pick(Self::PROC, msr::PROCBASED, msr::TRUE_PROCBASED, msr::TRUE_PROCBASED)?;
        let exit = pick(Self::EXIT, msr::EXIT, msr::TRUE_EXIT, msr::TRUE_EXIT)?;
        let entry = pick(Self::ENTRY, msr::ENTRY, msr::TRUE_ENTRY, msr::TRUE_ENTRY)?;
        // The IA-32e guest bit is set and cleared at run time.
        adjust(entry_ctl::IA32E_GUEST, rdmsr(if t { msr::TRUE_ENTRY } else { msr::ENTRY }))
            .ok_or(VmxError::MissingControl(msr::TRUE_ENTRY))?;
        let proc2 = adjust(Self::PROC2, rdmsr(msr::PROCBASED2)).ok_or(VmxError::MissingControl(msr::PROCBASED2))?;
        // Also the interrupt-window control, toggled at run time.
        adjust(proc::INTERRUPT_WINDOW, rdmsr(if t { msr::TRUE_PROCBASED } else { msr::PROCBASED }))
            .ok_or(VmxError::MissingControl(msr::TRUE_PROCBASED))?;
        let ept = rdmsr(msr::EPT_VPID_CAP);
        // 4-level walks (bit 6), write-back EPT paging structures (bit 14), INVEPT (20), INVVPID (32).
        if ept & (1 << 6 | 1 << 14 | 1 << 20 | 1 << 32) != 1 << 6 | 1 << 14 | 1 << 20 | 1 << 32 {
            return Err(VmxError::NoEpt);
        }
        Ok(Self {
            revision: basic as u32 & 0x7fff_ffff,
            pin,
            proc,
            proc2,
            exit,
            entry,
            cr0_fixed0: rdmsr(msr::CR0_FIXED0),
            cr0_fixed1: rdmsr(msr::CR0_FIXED1),
            cr4_fixed0: rdmsr(msr::CR4_FIXED0),
            cr4_fixed1: rdmsr(msr::CR4_FIXED1),
            invept: if ept & 1 << 25 != 0 { 1 } else { 2 },
            invvpid: if ept & 1 << 41 != 0 { 1 } else { 2 },
        })
    }

    /// A CPU that allows everything, for host tests.
    pub fn permissive() -> Self {
        Self::from_msrs(|m| match m {
            msr::CR0_FIXED0 => 0x8000_0021,
            msr::CR0_FIXED1 | msr::CR4_FIXED1 => 0xffff_ffff,
            msr::CR4_FIXED0 => 1 << 13,
            msr::EPT_VPID_CAP => 1 << 6 | 1 << 14 | 1 << 20 | 1 << 25 | 1 << 32 | 1 << 41,
            msr::BASIC => 1,
            _ => 0xffff_ffff_0000_0000,
        })
        .expect("permissive capabilities")
    }
}
