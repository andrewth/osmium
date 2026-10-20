//! Page-table entry encodings.
//!
//! | Format | Use | Levels | Input bits |
//! |---|---|---|---|
//! | [`X86_64`] | x86_64 4-level paging | 4 | 48, sign-extended |
//! | [`Aarch64`] | AArch64 stage 1, 4 KiB granule | 4 | 48, sign-extended |
//! | [`Aarch64El2`] | AArch64 EL2 stage 1 (non-VHE), 4 KiB granule | 4 | 48 |
//! | [`Sv39`] / [`Sv48`] | RISC-V supervisor paging | 3 / 4 | 39 / 48, sign-extended |
//! | [`Sv39x4`] / [`Sv48x4`] | RISC-V G-stage (guest physical), 16 KiB root | 3 / 4 | 41 / 50 |
//! | [`Ept`] | Intel extended page tables (guest physical) | 4 | 48 |
//! | [`Aarch64Stage2`] | AArch64 stage 2 (guest IPA), starting level 0 | 4 | 48 |

use super::{MapFlags, PageTableFormat};
use crate::addr::PhysAddr;

const fn addr_mask(level: usize) -> u64 {
    // Bits 51..12 of the output address, minus the low bits a leaf at
    // `level` must have clear.
    0x000f_ffff_ffff_f000 & !((1u64 << (12 + 9 * level)) - 1)
}

/// x86_64 4-level paging. `EXEC` requires `EFER.NXE`; `DEVICE` sets PCD|PWT.
pub struct X86_64;

mod x86 {
    pub const P: u64 = 1 << 0;
    pub const RW: u64 = 1 << 1;
    pub const US: u64 = 1 << 2;
    pub const PWT: u64 = 1 << 3;
    pub const PCD: u64 = 1 << 4;
    pub const A: u64 = 1 << 5;
    pub const D: u64 = 1 << 6;
    pub const PS: u64 = 1 << 7;
    pub const G: u64 = 1 << 8;
    pub const NX: u64 = 1 << 63;
}

impl PageTableFormat for X86_64 {
    const LEVELS: usize = 4;
    const VA_BITS: u32 = 48;
    const SIGN_EXTEND: bool = true;
    const MAX_LEAF_LEVEL: usize = 2;

    fn table(pa: PhysAddr) -> u64 {
        // Permissions are enforced at the leaf.
        pa.0 | x86::P | x86::RW | x86::US
    }

    fn leaf(pa: PhysAddr, f: MapFlags, level: usize) -> u64 {
        let mut e = pa.0 | x86::P | x86::A;
        if f.contains(MapFlags::WRITE) {
            e |= x86::RW | x86::D;
        }
        if f.contains(MapFlags::USER) {
            e |= x86::US;
        }
        if f.contains(MapFlags::GLOBAL) {
            e |= x86::G;
        }
        if !f.contains(MapFlags::EXEC) || f.contains(MapFlags::DEVICE) {
            e |= x86::NX;
        }
        if f.contains(MapFlags::DEVICE) {
            e |= x86::PCD | x86::PWT;
        }
        if level > 0 {
            e |= x86::PS;
        }
        e
    }

    fn is_valid(pte: u64) -> bool {
        pte & x86::P != 0
    }

    fn is_leaf(pte: u64, level: usize) -> bool {
        level == 0 || pte & x86::PS != 0
    }

    fn addr(pte: u64, level: usize) -> PhysAddr {
        let level = if Self::is_leaf(pte, level) { level } else { 0 };
        PhysAddr::new(pte & addr_mask(level))
    }

    fn flags(pte: u64, _level: usize) -> MapFlags {
        let mut f = MapFlags::READ;
        if pte & x86::RW != 0 {
            f = f | MapFlags::WRITE;
        }
        if pte & x86::US != 0 {
            f = f | MapFlags::USER;
        }
        if pte & x86::G != 0 {
            f = f | MapFlags::GLOBAL;
        }
        if pte & x86::NX == 0 {
            f = f | MapFlags::EXEC;
        }
        if pte & x86::PCD != 0 {
            f = f | MapFlags::DEVICE;
        }
        f
    }
}

/// AArch64 stage 1, 4 KiB granule, 48-bit VA, for TTBR0 or TTBR1.
///
/// Attribute index 0 must be Normal memory and index 1 Device-nGnRE, as in
/// `osmium_arch::aarch64::MAIR_VALUE`.
pub struct Aarch64;

mod arm {
    pub const VALID: u64 = 1 << 0;
    pub const TABLE_OR_PAGE: u64 = 1 << 1;
    pub const ATTR_DEVICE: u64 = 1 << 2;
    pub const AP_EL0: u64 = 1 << 6;
    pub const AP_RO: u64 = 1 << 7;
    pub const SH_INNER: u64 = 0b11 << 8;
    pub const AF: u64 = 1 << 10;
    pub const NG: u64 = 1 << 11;
    pub const PXN: u64 = 1 << 53;
    pub const UXN: u64 = 1 << 54;
    pub const ATTR_MASK: u64 = 0b111 << 2;
}

impl PageTableFormat for Aarch64 {
    const LEVELS: usize = 4;
    const VA_BITS: u32 = 48;
    const SIGN_EXTEND: bool = true;
    const MAX_LEAF_LEVEL: usize = 2;

    fn table(pa: PhysAddr) -> u64 {
        pa.0 | arm::VALID | arm::TABLE_OR_PAGE
    }

    fn leaf(pa: PhysAddr, f: MapFlags, level: usize) -> u64 {
        let mut e = pa.0 | arm::VALID | arm::AF;
        if level == 0 {
            e |= arm::TABLE_OR_PAGE;
        }
        if f.contains(MapFlags::DEVICE) {
            e |= arm::ATTR_DEVICE;
        } else {
            e |= arm::SH_INNER;
        }
        if !f.contains(MapFlags::WRITE) {
            e |= arm::AP_RO;
        }
        if f.contains(MapFlags::USER) {
            e |= arm::AP_EL0;
        }
        if !f.contains(MapFlags::GLOBAL) {
            e |= arm::NG;
        }
        let exec = f.contains(MapFlags::EXEC) && !f.contains(MapFlags::DEVICE);
        let user = f.contains(MapFlags::USER);
        // Never let the kernel execute user-writable pages, and vice versa.
        if !exec || user {
            e |= arm::PXN;
        }
        if !exec || !user {
            e |= arm::UXN;
        }
        e
    }

    fn is_valid(pte: u64) -> bool {
        pte & arm::VALID != 0
    }

    fn is_leaf(pte: u64, level: usize) -> bool {
        level == 0 || pte & arm::TABLE_OR_PAGE == 0
    }

    fn addr(pte: u64, level: usize) -> PhysAddr {
        let level = if Self::is_leaf(pte, level) { level } else { 0 };
        PhysAddr::new(pte & addr_mask(level) & 0x0000_ffff_ffff_f000)
    }

    fn flags(pte: u64, _level: usize) -> MapFlags {
        let mut f = MapFlags::READ;
        if pte & arm::AP_RO == 0 {
            f = f | MapFlags::WRITE;
        }
        let user = pte & arm::AP_EL0 != 0;
        if user {
            f = f | MapFlags::USER;
        }
        if pte & arm::NG == 0 {
            f = f | MapFlags::GLOBAL;
        }
        if (user && pte & arm::UXN == 0) || (!user && pte & arm::PXN == 0) {
            f = f | MapFlags::EXEC;
        }
        if pte & arm::ATTR_MASK == arm::ATTR_DEVICE {
            f = f | MapFlags::DEVICE;
        }
        f
    }
}

/// AArch64 stage 1 for the EL2 translation regime with `HCR_EL2.E2H` = 0:
/// one VA range starting at 0, no ASIDs and no EL0. `AP[1]` is RES1, `nG`
/// stays 0 and bit 54 is the only execute-never bit. `USER` and `GLOBAL`
/// are ignored.
pub struct Aarch64El2;

impl PageTableFormat for Aarch64El2 {
    const LEVELS: usize = 4;
    const VA_BITS: u32 = 48;
    const SIGN_EXTEND: bool = false;
    const MAX_LEAF_LEVEL: usize = 2;

    fn table(pa: PhysAddr) -> u64 {
        Aarch64::table(pa)
    }

    fn leaf(pa: PhysAddr, f: MapFlags, level: usize) -> u64 {
        let mut e = pa.0 | arm::VALID | arm::AF | arm::AP_EL0;
        if level == 0 {
            e |= arm::TABLE_OR_PAGE;
        }
        if f.contains(MapFlags::DEVICE) {
            e |= arm::ATTR_DEVICE;
        } else {
            e |= arm::SH_INNER;
        }
        if !f.contains(MapFlags::WRITE) {
            e |= arm::AP_RO;
        }
        if !f.contains(MapFlags::EXEC) || f.contains(MapFlags::DEVICE) {
            e |= arm::UXN; // XN in this regime
        }
        e
    }

    fn is_valid(pte: u64) -> bool {
        Aarch64::is_valid(pte)
    }

    fn is_leaf(pte: u64, level: usize) -> bool {
        Aarch64::is_leaf(pte, level)
    }

    fn addr(pte: u64, level: usize) -> PhysAddr {
        Aarch64::addr(pte, level)
    }

    fn flags(pte: u64, _level: usize) -> MapFlags {
        let mut f = MapFlags::READ;
        if pte & arm::AP_RO == 0 {
            f = f | MapFlags::WRITE;
        }
        if pte & arm::UXN == 0 {
            f = f | MapFlags::EXEC;
        }
        if pte & arm::ATTR_MASK == arm::ATTR_DEVICE {
            f = f | MapFlags::DEVICE;
        }
        f
    }
}

mod rv {
    pub const V: u64 = 1 << 0;
    pub const R: u64 = 1 << 1;
    pub const W: u64 = 1 << 2;
    pub const X: u64 = 1 << 3;
    pub const U: u64 = 1 << 4;
    pub const G: u64 = 1 << 5;
    pub const A: u64 = 1 << 6;
    pub const D: u64 = 1 << 7;
    pub const PPN_MASK: u64 = (1 << 44) - 1;
}

/// Shared RISC-V encoding. `DEVICE` is ignored: without the Svpbmt extension
/// memory types come from the platform's PMAs.
pub struct Riscv<const LEVELS: usize, const VA_BITS: u32>;

/// RISC-V Sv39.
pub type Sv39 = Riscv<3, 39>;
/// RISC-V Sv48.
pub type Sv48 = Riscv<4, 48>;

impl<const LEVELS: usize, const VA_BITS: u32> PageTableFormat for Riscv<LEVELS, VA_BITS> {
    const LEVELS: usize = LEVELS;
    const VA_BITS: u32 = VA_BITS;
    const SIGN_EXTEND: bool = true;
    const MAX_LEAF_LEVEL: usize = 2;

    fn table(pa: PhysAddr) -> u64 {
        (pa.0 >> 12) << 10 | rv::V
    }

    fn leaf(pa: PhysAddr, f: MapFlags, _level: usize) -> u64 {
        // A and D are preset so hardware without A/D updating does not fault.
        let mut e = (pa.0 >> 12) << 10 | rv::V | rv::A;
        // W without R is reserved, so writable implies readable.
        if f.contains(MapFlags::READ) || f.contains(MapFlags::WRITE) {
            e |= rv::R;
        }
        if f.contains(MapFlags::WRITE) {
            e |= rv::W | rv::D;
        }
        if f.contains(MapFlags::EXEC) && !f.contains(MapFlags::DEVICE) {
            e |= rv::X;
        }
        if f.contains(MapFlags::USER) {
            e |= rv::U;
        }
        if f.contains(MapFlags::GLOBAL) {
            e |= rv::G;
        }
        e
    }

    fn is_valid(pte: u64) -> bool {
        pte & rv::V != 0
    }

    fn is_leaf(pte: u64, level: usize) -> bool {
        // Hardware treats a valid level-0 entry without R/W/X as a fault, not
        // a pointer; `map` never writes one.
        level == 0 || pte & (rv::R | rv::W | rv::X) != 0
    }

    fn addr(pte: u64, _level: usize) -> PhysAddr {
        PhysAddr::new(((pte >> 10) & rv::PPN_MASK) << 12)
    }

    fn flags(pte: u64, _level: usize) -> MapFlags {
        let mut f = MapFlags::NONE;
        for (bit, flag) in [
            (rv::R, MapFlags::READ),
            (rv::W, MapFlags::WRITE),
            (rv::X, MapFlags::EXEC),
            (rv::U, MapFlags::USER),
            (rv::G, MapFlags::GLOBAL),
        ] {
            if pte & bit != 0 {
                f = f | flag;
            }
        }
        f
    }
}

/// RISC-V G-stage translation (the hypervisor extension's guest-physical
/// stage). Entries use the Sv39/Sv48 encoding, with `U` always set because
/// G-stage checks every guest access as a user access; `USER` and `GLOBAL`
/// are ignored. The root has 2048 entries over four pages, giving two extra
/// address bits.
pub struct RiscvGStage<const LEVELS: usize, const VA_BITS: u32>;

/// RISC-V Sv39x4 (`hgatp.MODE` 8).
pub type Sv39x4 = RiscvGStage<3, 41>;
/// RISC-V Sv48x4 (`hgatp.MODE` 9).
pub type Sv48x4 = RiscvGStage<4, 50>;

impl<const LEVELS: usize, const VA_BITS: u32> PageTableFormat for RiscvGStage<LEVELS, VA_BITS> {
    const LEVELS: usize = LEVELS;
    const VA_BITS: u32 = VA_BITS;
    const SIGN_EXTEND: bool = false;
    const MAX_LEAF_LEVEL: usize = 2;
    const ROOT_PAGES: usize = 4;

    fn table(pa: PhysAddr) -> u64 {
        Sv39::table(pa)
    }

    fn leaf(pa: PhysAddr, f: MapFlags, level: usize) -> u64 {
        let f = f.difference(MapFlags::USER | MapFlags::GLOBAL);
        Sv39::leaf(pa, f, level) | rv::U
    }

    fn is_valid(pte: u64) -> bool {
        Sv39::is_valid(pte)
    }

    fn is_leaf(pte: u64, level: usize) -> bool {
        Sv39::is_leaf(pte, level)
    }

    fn addr(pte: u64, level: usize) -> PhysAddr {
        Sv39::addr(pte, level)
    }

    fn flags(pte: u64, level: usize) -> MapFlags {
        Sv39::flags(pte & !(rv::U | rv::G), level)
    }
}

/// Intel EPT, 4 levels. `DEVICE` selects UC memory type, otherwise WB with
/// guest PAT ignored. `USER` and `GLOBAL` have no meaning and are dropped.
pub struct Ept;

mod ept {
    pub const R: u64 = 1 << 0;
    pub const W: u64 = 1 << 1;
    pub const X: u64 = 1 << 2;
    pub const MT_WB: u64 = 6 << 3;
    pub const MT_MASK: u64 = 7 << 3;
    pub const IGNORE_PAT: u64 = 1 << 6;
    pub const LARGE: u64 = 1 << 7;
}

impl PageTableFormat for Ept {
    const LEVELS: usize = 4;
    const VA_BITS: u32 = 48;
    const SIGN_EXTEND: bool = false;
    const MAX_LEAF_LEVEL: usize = 2;

    fn table(pa: PhysAddr) -> u64 {
        pa.0 | ept::R | ept::W | ept::X
    }

    fn leaf(pa: PhysAddr, f: MapFlags, level: usize) -> u64 {
        let mut e = pa.0;
        if f.contains(MapFlags::READ) {
            e |= ept::R;
        }
        if f.contains(MapFlags::WRITE) {
            e |= ept::W | ept::R;
        }
        if f.contains(MapFlags::EXEC) {
            e |= ept::X;
        }
        if !f.contains(MapFlags::DEVICE) {
            e |= ept::MT_WB | ept::IGNORE_PAT;
        }
        if level > 0 {
            e |= ept::LARGE;
        }
        e
    }

    fn is_valid(pte: u64) -> bool {
        pte & (ept::R | ept::W | ept::X) != 0
    }

    fn is_leaf(pte: u64, level: usize) -> bool {
        level == 0 || pte & ept::LARGE != 0
    }

    fn addr(pte: u64, level: usize) -> PhysAddr {
        let level = if Self::is_leaf(pte, level) { level } else { 0 };
        PhysAddr::new(pte & addr_mask(level))
    }

    fn flags(pte: u64, _level: usize) -> MapFlags {
        let mut f = MapFlags::NONE;
        if pte & ept::R != 0 {
            f = f | MapFlags::READ;
        }
        if pte & ept::W != 0 {
            f = f | MapFlags::WRITE;
        }
        if pte & ept::X != 0 {
            f = f | MapFlags::EXEC;
        }
        if pte & ept::MT_MASK != ept::MT_WB {
            f = f | MapFlags::DEVICE;
        }
        f
    }
}

/// AArch64 stage 2, 4 KiB granule, 48-bit IPA, starting at level 0
/// (`VTCR_EL2.SL0 = 2`, `T0SZ = 16`). `USER` and `GLOBAL` are dropped.
pub struct Aarch64Stage2;

mod s2 {
    pub const MEMATTR_NORMAL_WB: u64 = 0b1111 << 2;
    pub const MEMATTR_DEVICE: u64 = 0b0001 << 2;
    pub const MEMATTR_MASK: u64 = 0b1111 << 2;
    pub const S2AP_R: u64 = 1 << 6;
    pub const S2AP_W: u64 = 1 << 7;
    pub const XN: u64 = 1 << 54;
}

impl PageTableFormat for Aarch64Stage2 {
    const LEVELS: usize = 4;
    const VA_BITS: u32 = 48;
    const SIGN_EXTEND: bool = false;
    const MAX_LEAF_LEVEL: usize = 2;

    fn table(pa: PhysAddr) -> u64 {
        Aarch64::table(pa)
    }

    fn leaf(pa: PhysAddr, f: MapFlags, level: usize) -> u64 {
        let mut e = pa.0 | arm::VALID | arm::AF;
        if level == 0 {
            e |= arm::TABLE_OR_PAGE;
        }
        if f.contains(MapFlags::DEVICE) {
            e |= s2::MEMATTR_DEVICE;
        } else {
            e |= s2::MEMATTR_NORMAL_WB | arm::SH_INNER;
        }
        if f.contains(MapFlags::READ) {
            e |= s2::S2AP_R;
        }
        if f.contains(MapFlags::WRITE) {
            e |= s2::S2AP_W;
        }
        if !f.contains(MapFlags::EXEC) || f.contains(MapFlags::DEVICE) {
            e |= s2::XN;
        }
        e
    }

    fn is_valid(pte: u64) -> bool {
        Aarch64::is_valid(pte)
    }

    fn is_leaf(pte: u64, level: usize) -> bool {
        Aarch64::is_leaf(pte, level)
    }

    fn addr(pte: u64, level: usize) -> PhysAddr {
        Aarch64::addr(pte, level)
    }

    fn flags(pte: u64, _level: usize) -> MapFlags {
        let mut f = MapFlags::NONE;
        if pte & s2::S2AP_R != 0 {
            f = f | MapFlags::READ;
        }
        if pte & s2::S2AP_W != 0 {
            f = f | MapFlags::WRITE;
        }
        if pte & s2::XN == 0 {
            f = f | MapFlags::EXEC;
        }
        if pte & s2::MEMATTR_MASK == s2::MEMATTR_DEVICE {
            f = f | MapFlags::DEVICE;
        }
        f
    }
}
