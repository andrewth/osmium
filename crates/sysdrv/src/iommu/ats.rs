//! Wire formats for invalidating a device's ATS translation cache.
//!
//! When a mapping changes, an IOMMU whose device has ATS on must also tell
//! the device to drop what it cached, by posting a command that makes the
//! unit send a PCIe Invalidate Request:
//!
//! - Intel VT-d: a device-TLB invalidate descriptor in the invalidation
//!   queue ([`vtd_device_tlb`]), or its PASID form ([`vtd_pasid_device_tlb`]);
//! - Arm SMMUv3: `CMD_ATC_INV` in the command queue ([`smmuv3_atc_inv`]).
//!
//! These functions only build the command words, from the same
//! [`ats_span`] encoding the generic layer uses, so a driver with a queue
//! can post them. The VT-d driver still invalidates through registers (a
//! queue the firmware left on is switched off) and the SMMUv3 driver does not
//! enable ATS in its stream table entries, so neither posts these today; the layouts follow
//! the specifications and are checked only against the field positions
//! written here, not against hardware.

use osmium_hal::iommu::{DeviceId, Pasid, ats_address, ats_span};

/// VT-d queued-invalidation descriptor type: device-TLB invalidate.
const VTD_DEV_IOTLB: u64 = 0x3;
/// VT-d queued-invalidation descriptor type: PASID-based device-TLB invalidate.
const VTD_PASID_DEV_IOTLB: u64 = 0x8;
/// SMMUv3 command opcode: `CMD_ATC_INV`.
const SMMU_ATC_INV: u64 = 0x40;

/// Why a command could not be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AtsCmdError {
    /// The range wraps around the address space.
    BadRange,
    /// The device's invalidate queue depth does not fit the 5-bit field.
    BadQueueDepth,
}

/// A VT-d device-TLB invalidate descriptor (128 bits, low and high word).
///
/// `queue_depth` is the function's ATS Invalidate Queue Depth (32 encodes as
/// 0), `pf` the requester ID of its physical function (the function itself
/// for a PF), for virtual functions that share their PF's ATS configuration.
/// The range `[iova, iova + len)` (everything if `len` is 0) is widened to a
/// naturally aligned power-of-two span.
pub fn vtd_device_tlb(
    device: DeviceId,
    pf: DeviceId,
    queue_depth: u32,
    iova: u64,
    len: u64,
) -> Result<[u64; 2], AtsCmdError> {
    if queue_depth > 32 {
        return Err(AtsCmdError::BadQueueDepth);
    }
    let (base, log2) = ats_span(iova, len).ok_or(AtsCmdError::BadRange)?;
    let (addr, size) = ats_address(base, log2);
    let pfsid = u64::from(pf.bdf());
    let low = VTD_DEV_IOTLB
        | (u64::from(queue_depth & 0x1f)) << 16
        | u64::from(device.bdf()) << 32
        | (pfsid & 0xf) << 12
        | (pfsid >> 4) << 52;
    Ok([low, addr | u64::from(size)])
}

/// A VT-d PASID-based device-TLB invalidate descriptor (the first 128 bits
/// of the 256-bit descriptor scalable mode uses; the rest is zero). `global`
/// invalidates the range for every PASID of the device.
pub fn vtd_pasid_device_tlb(
    device: DeviceId,
    pf: DeviceId,
    queue_depth: u32,
    pasid: Pasid,
    iova: u64,
    len: u64,
    global: bool,
) -> Result<[u64; 2], AtsCmdError> {
    if queue_depth > 32 {
        return Err(AtsCmdError::BadQueueDepth);
    }
    let (base, log2) = ats_span(iova, len).ok_or(AtsCmdError::BadRange)?;
    let (addr, size) = ats_address(base, log2);
    let pfsid = u64::from(pf.bdf());
    let low = VTD_PASID_DEV_IOTLB
        | u64::from(queue_depth & 0x1f) << 4
        | (pfsid & 0xf) << 12
        | u64::from(device.bdf()) << 16
        | u64::from(pasid.value()) << 32
        | (pfsid >> 4) << 52;
    Ok([low, addr | u64::from(size) << 11 | u64::from(global)])
}

/// An SMMUv3 `CMD_ATC_INV` for `stream_id` (and substream `pasid`, if
/// given): the two command doublewords. A zero `len` invalidates every
/// address; `global` applies the command to all substreams of the stream.
pub fn smmuv3_atc_inv(
    stream_id: u32,
    pasid: Option<Pasid>,
    iova: u64,
    len: u64,
    global: bool,
) -> Result<[u64; 2], AtsCmdError> {
    let (base, log2) = ats_span(iova, len).ok_or(AtsCmdError::BadRange)?;
    let mut q0 = SMMU_ATC_INV | u64::from(stream_id) << 32;
    if let Some(p) = pasid {
        q0 |= 1 << 11 | u64::from(p.value()) << 12;
    }
    if global {
        q0 |= 1 << 9;
    }
    // The address is the span's base; the size field is its log2 in pages.
    Ok([q0, base & !0xfff | u64::from(log2)])
}

#[cfg(test)]
mod tests {
    use super::*;
    use osmium_hal::pci::Address;

    const DEV: DeviceId = DeviceId::new(0, Address::new(0x12, 3, 1));
    const PF: DeviceId = DeviceId::new(0, Address::new(0x12, 3, 0));

    #[test]
    fn vtd_single_page() {
        let [lo, hi] = vtd_device_tlb(DEV, PF, 8, 0x5123, 0x10).unwrap();
        assert_eq!(lo & 0xf, 3);
        assert_eq!(lo >> 16 & 0x1f, 8);
        assert_eq!(lo >> 32 & 0xffff, 0x1219);
        assert_eq!((lo >> 12 & 0xf, lo >> 52), (8, 0x121), "PF requester ID 0x1218");
        assert_eq!(hi, 0x5000, "one page: no S bit");
    }

    #[test]
    fn vtd_range_sets_size_bit() {
        // Pages 4 and 5: an 8 KiB span, S set, bit 12 clear.
        let [_, hi] = vtd_device_tlb(DEV, PF, 32, 0x4000, 0x2000).unwrap();
        assert_eq!(hi, 0x4000 | 1);
        let [lo, hi] = vtd_device_tlb(DEV, PF, 32, 0, 0).unwrap();
        assert_eq!(lo >> 16 & 0x1f, 0, "queue depth 32 encodes as 0");
        assert_eq!(hi, 0x7fff_ffff_ffff_f000 | 1, "everything");
        assert_eq!(vtd_device_tlb(DEV, PF, 33, 0, 0), Err(AtsCmdError::BadQueueDepth));
        assert_eq!(vtd_device_tlb(DEV, PF, 1, u64::MAX - 1, 0x10), Err(AtsCmdError::BadRange));
    }

    #[test]
    fn vtd_pasid_form() {
        let p = Pasid::new(0xabcde).unwrap();
        let [lo, hi] = vtd_pasid_device_tlb(DEV, PF, 4, p, 0x4000, 0x2000, true).unwrap();
        assert_eq!(lo & 0xf, 8);
        assert_eq!(lo >> 4 & 0x1f, 4);
        assert_eq!(lo >> 16 & 0xffff, 0x1219);
        assert_eq!(lo >> 32 & 0xfffff, 0xabcde);
        assert_eq!(hi, 0x4000 | 1 << 11 | 1);
    }

    #[test]
    fn smmuv3_command() {
        let [q0, q1] = smmuv3_atc_inv(0x77, None, 0x4000, 0x2000, false).unwrap();
        assert_eq!((q0 & 0xff, q0 >> 32, q0 & (1 << 11)), (0x40, 0x77, 0));
        assert_eq!(q1, 0x4000 | 1);
        let p = Pasid::new(5).unwrap();
        let [q0, _] = smmuv3_atc_inv(0x77, Some(p), 0x4000, 0x1000, true).unwrap();
        assert_eq!(q0 >> 12 & 0xfffff, 5);
        assert_ne!(q0 & 1 << 11, 0, "SSV");
        assert_ne!(q0 & 1 << 9, 0, "global");
        assert_eq!(smmuv3_atc_inv(1, None, 0, 0, false).unwrap()[1], 52);
    }
}
