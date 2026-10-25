//! PCIe Address Translation Services and Process Address Space IDs.
//!
//! A function with the ATS capability can ask its IOMMU for translations and
//! cache them in a device TLB (an "ATC"), and the IOMMU must then tell the
//! function when a translation changes (an Invalidate Request, which the IOMMU
//! sends and the function answers). A function with the PASID capability tags
//! its DMA with a process address space ID of at most 20 bits, so one
//! function can use many address spaces. [`Function::ats`] and
//! [`Function::pasid`] read the capabilities, and [`Ats::enable`] and
//! [`PasidCap::enable`] switch them on.
//!
//! Enable ATS only once the IOMMU is ready to translate for the function
//! (an unmapped request would otherwise be a fault) and after the IOMMU side
//! has been told that the device may issue translated requests. Both
//! capabilities live in extended configuration space, so as with SR-IOV they
//! exist only behind an [`Ecam`](super::Ecam) window.
//!
//! This module only touches the function. Invalidating its device TLB goes
//! through the IOMMU (see
//! [`Iommu::invalidate_device_tlb`](crate::iommu::Iommu::invalidate_device_tlb)).

use super::{ConfigAccess, Function};

/// Extended capability IDs added by this module.
pub mod ext_cap {
    #![allow(missing_docs)]
    pub const ATS: u16 = 0x000f;
    pub const PASID: u16 = 0x001b;
}

/// Offset of the capability register (low half) and control register (high half).
const REGS: u16 = 0x04;
/// The capability must fit in configuration space.
const LENGTH: u16 = 0x08;
const CONFIG_END: u16 = 0x1000;

const ATS_QUEUE_DEPTH: u32 = 0x1f;
const ATS_PAGE_ALIGNED: u32 = 1 << 5;
const ATS_GLOBAL_INVALIDATE: u32 = 1 << 6;
const ATS_CTRL_STU_SHIFT: u32 = 16;
const ATS_CTRL_STU_MASK: u32 = 0x1f << ATS_CTRL_STU_SHIFT;
const ATS_CTRL_ENABLE: u32 = 1 << 31;

const PASID_EXEC: u32 = 1 << 1;
const PASID_PRIVILEGED: u32 = 1 << 2;
const PASID_WIDTH_SHIFT: u32 = 8;
const PASID_CTRL_ENABLE: u32 = 1 << 16;
const PASID_CTRL_EXEC: u32 = 1 << 17;
const PASID_CTRL_PRIVILEGED: u32 = 1 << 18;

/// Why enabling ATS or PASID failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AtsError {
    /// The function lacks the capability.
    NotPresent,
    /// The capability does not fit configuration space.
    BadCapability,
    /// The Smallest Translation Unit is more than the 5 bits the register holds.
    BadStu,
    /// A PASID feature was requested that the function does not support.
    Unsupported,
}

/// A function's ATS capability, from [`Function::ats`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ats {
    offset: u16,
    capability: u32,
}

impl Ats {
    /// How many invalidate requests the function can have outstanding (the
    /// register's zero means 32).
    pub fn queue_depth(&self) -> u32 {
        match self.capability & ATS_QUEUE_DEPTH {
            0 => 32,
            n => n,
        }
    }

    /// True if the function only issues page-aligned translation requests.
    pub fn page_aligned_request(&self) -> bool {
        self.capability & ATS_PAGE_ALIGNED != 0
    }

    /// True if the function honours "invalidate all PASIDs" requests.
    pub fn global_invalidate(&self) -> bool {
        self.capability & ATS_GLOBAL_INVALIDATE != 0
    }

    /// Turns ATS on with Smallest Translation Unit `stu_log2` (the log2 of
    /// the smallest translation, in 4 KiB units, the IOMMU returns: 0 for
    /// 4 KiB). Returns the function's invalidate queue depth, which IOMMU
    /// device-TLB invalidations need.
    pub fn enable<C: ConfigAccess + ?Sized>(&self, func: &Function<'_, C>, stu_log2: u8) -> Result<u32, AtsError> {
        if u32::from(stu_log2) > ATS_CTRL_STU_MASK >> ATS_CTRL_STU_SHIFT {
            return Err(AtsError::BadStu);
        }
        self.write_control(func, ATS_CTRL_ENABLE | u32::from(stu_log2) << ATS_CTRL_STU_SHIFT);
        Ok(self.queue_depth())
    }

    /// Turns ATS off. The function drops its cached translations itself.
    pub fn disable<C: ConfigAccess + ?Sized>(&self, func: &Function<'_, C>) {
        self.write_control(func, 0);
    }

    /// True if ATS is enabled.
    pub fn enabled<C: ConfigAccess + ?Sized>(&self, func: &Function<'_, C>) -> bool {
        func.read32(self.offset + REGS) & ATS_CTRL_ENABLE != 0
    }

    fn write_control<C: ConfigAccess + ?Sized>(&self, func: &Function<'_, C>, control: u32) {
        // The capability half is read-only; keep it as it reads.
        let low = func.read32(self.offset + REGS) & 0xffff;
        func.write32(self.offset + REGS, low | control);
    }
}

/// A function's PASID capability, from [`Function::pasid`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PasidCap {
    offset: u16,
    capability: u32,
}

impl PasidCap {
    /// How many bits of PASID the function can emit (at most 20).
    pub fn width(&self) -> u32 {
        (self.capability >> PASID_WIDTH_SHIFT & 0x1f).min(20)
    }

    /// True if the function can request execute permission.
    pub fn execute_supported(&self) -> bool {
        self.capability & PASID_EXEC != 0
    }

    /// True if the function can request privileged-mode access.
    pub fn privileged_supported(&self) -> bool {
        self.capability & PASID_PRIVILEGED != 0
    }

    /// Turns PASID on. `execute` and `privileged` additionally let the
    /// function use those request attributes, and fail with
    /// [`AtsError::Unsupported`] (before anything is written) if the function
    /// lacks them.
    pub fn enable<C: ConfigAccess + ?Sized>(
        &self,
        func: &Function<'_, C>,
        execute: bool,
        privileged: bool,
    ) -> Result<(), AtsError> {
        if (execute && !self.execute_supported()) || (privileged && !self.privileged_supported()) {
            return Err(AtsError::Unsupported);
        }
        let mut control = PASID_CTRL_ENABLE;
        if execute {
            control |= PASID_CTRL_EXEC;
        }
        if privileged {
            control |= PASID_CTRL_PRIVILEGED;
        }
        self.write_control(func, control);
        Ok(())
    }

    /// Turns PASID off.
    pub fn disable<C: ConfigAccess + ?Sized>(&self, func: &Function<'_, C>) {
        self.write_control(func, 0);
    }

    /// True if PASID is enabled.
    pub fn enabled<C: ConfigAccess + ?Sized>(&self, func: &Function<'_, C>) -> bool {
        func.read32(self.offset + REGS) & PASID_CTRL_ENABLE != 0
    }

    fn write_control<C: ConfigAccess + ?Sized>(&self, func: &Function<'_, C>, control: u32) {
        let low = func.read32(self.offset + REGS) & 0xffff;
        func.write32(self.offset + REGS, low | control);
    }
}

impl<C: ConfigAccess + ?Sized> Function<'_, C> {
    fn ext_cap_registers(&self, id: u16) -> Result<(u16, u32), AtsError> {
        let offset = self.find_extended_capability(id).ok_or(AtsError::NotPresent)?;
        if offset.checked_add(LENGTH).is_none_or(|end| end > CONFIG_END) {
            return Err(AtsError::BadCapability);
        }
        Ok((offset, self.read32(offset + REGS) & 0xffff))
    }

    /// The Address Translation Services capability.
    pub fn ats(&self) -> Result<Ats, AtsError> {
        let (offset, capability) = self.ext_cap_registers(ext_cap::ATS)?;
        Ok(Ats { offset, capability })
    }

    /// The PASID capability.
    pub fn pasid(&self) -> Result<PasidCap, AtsError> {
        let (offset, capability) = self.ext_cap_registers(ext_cap::PASID)?;
        Ok(PasidCap { offset, capability })
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::cell::RefCell;
    use std::collections::BTreeMap;

    use super::*;
    use crate::pci::{Address, ConfigAccess};

    const FN: Address = Address::new(1, 0, 0);

    #[derive(Default)]
    struct Config(RefCell<BTreeMap<u16, u32>>);

    impl Config {
        fn set(&self, offset: u16, v: u32) {
            self.0.borrow_mut().insert(offset, v);
        }
        fn get(&self, offset: u16) -> u32 {
            self.0.borrow().get(&offset).copied().unwrap_or(0)
        }
    }

    impl ConfigAccess for Config {
        fn read32(&self, addr: Address, offset: u16) -> u32 {
            if addr == FN { self.get(offset) } else { !0 }
        }
        fn write32(&self, _addr: Address, offset: u16, value: u32) {
            // The capability half is read-only.
            let ro = self.get(offset) & 0xffff;
            self.set(offset, value & !0xffff | ro);
        }
    }

    /// ATS at 0x100 (queue depth 8), PASID at 0x140 (20 bits, exec only).
    fn config() -> Config {
        let c = Config::default();
        c.set(0x100, 0x000f | 1 << 16 | 0x140 << 20);
        c.set(0x104, 8 | ATS_GLOBAL_INVALIDATE);
        c.set(0x140, 0x001b | 1 << 16);
        c.set(0x144, PASID_EXEC | 20 << PASID_WIDTH_SHIFT);
        c
    }

    #[test]
    fn ats_enables_with_stu() {
        let c = config();
        let f = Function::new(&c, FN).unwrap();
        let ats = f.ats().unwrap();
        assert_eq!((ats.queue_depth(), ats.global_invalidate(), ats.page_aligned_request()), (8, true, false));
        assert_eq!(ats.enable(&f, 32), Err(AtsError::BadStu));
        assert!(!ats.enabled(&f));
        assert_eq!(ats.enable(&f, 0), Ok(8));
        assert!(ats.enabled(&f));
        assert_eq!(c.get(0x104), 8 | ATS_GLOBAL_INVALIDATE | ATS_CTRL_ENABLE);
        ats.disable(&f);
        assert_eq!(c.get(0x104), 8 | ATS_GLOBAL_INVALIDATE, "capability bits kept");
    }

    #[test]
    fn pasid_enables_only_supported_features() {
        let c = config();
        let f = Function::new(&c, FN).unwrap();
        let p = f.pasid().unwrap();
        assert_eq!((p.width(), p.execute_supported(), p.privileged_supported()), (20, true, false));
        assert_eq!(p.enable(&f, false, true), Err(AtsError::Unsupported));
        assert!(!p.enabled(&f));
        p.enable(&f, true, false).unwrap();
        assert_eq!(c.get(0x144) >> 16, 0b011);
        p.disable(&f);
        assert!(!p.enabled(&f));
    }

    #[test]
    fn missing_capabilities() {
        let c = Config::default();
        c.set(0x100, 0x0010);
        let f = Function::new(&c, FN).unwrap();
        assert_eq!(f.ats(), Err(AtsError::NotPresent));
        assert_eq!(f.pasid(), Err(AtsError::NotPresent));
    }
}
