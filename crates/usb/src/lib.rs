//! USB host controllers and class drivers built on `osmium-hal`.
//!
//! | Driver | Device | Implements |
//! |---|---|---|
//! | [`xhci::Xhci`] | xHCI USB host controller | `UsbHost` |
//! | [`ehci::Ehci`] | EHCI USB 2.0 host controller (high-speed devices; polled) | `UsbHost` |
//! | [`ohci::Ohci`] | OHCI USB 1.1 host controller (polled) | `UsbHost` |
//! | [`uhci::Uhci`] | UHCI USB 1.1 host controller (I/O ports or MMIO; polled) | `UsbHost` |
//! | [`class::storage::UsbStorage`] | USB mass storage (SCSI, Bulk-Only) on any `UsbHost` | `BlockDevice` |
//! | [`class::hid::BootKeyboard`] | USB keyboard (HID boot protocol) on any `UsbHost` | key events |
//! | [`class::ecm::UsbEthernet`] | USB Ethernet (CDC-ECM) on any `UsbHost` | `NetDevice` |
//! | [`class::ncm::UsbNcm`] | USB Ethernet (CDC-NCM; simulator-tested only) on any `UsbHost` | `NetDevice` |
//!
//! Every controller is constructed from an [`osmium_hal::mmio::IoMem`] (or a
//! port base), so it works the same under any memory map and can be tested
//! against ordinary memory.
#![no_std]

#[cfg(test)]
extern crate std;

pub mod class;
pub mod ehci;
pub mod ohci;
pub mod uhci;
pub(crate) mod usbhc;
pub mod xhci;

/// A host-memory DMA allocator, so tests can play the device's side of a ring.
#[cfg(test)]
pub(crate) mod testing {
    use core::cell::Cell;
    use core::ptr::NonNull;
    use std::alloc::{Layout, alloc_zeroed, dealloc};

    use osmium_hal::dma::{DmaAllocator, DmaBuffer};
    use osmium_mm::PhysAddr;

    /// Page-aligned heap memory whose device address is its host address.
    #[derive(Default)]
    pub struct HostDma {
        pub live: Cell<usize>,
    }

    impl DmaAllocator for HostDma {
        fn alloc_coherent(&self, len: usize) -> Option<DmaBuffer> {
            let layout = Layout::from_size_align(len.max(1), 4096).ok()?;
            // SAFETY: non-zero size.
            let p = NonNull::new(unsafe { alloc_zeroed(layout) })?;
            self.live.set(self.live.get() + 1);
            // SAFETY: fresh, exclusively owned memory; identity-mapped.
            Some(unsafe { DmaBuffer::new(p, PhysAddr::new(p.as_ptr() as u64), len) })
        }

        unsafe fn free_coherent(&self, buf: DmaBuffer) {
            self.live.set(self.live.get() - 1);
            let layout = Layout::from_size_align(buf.len().max(1), 4096).expect("allocated with this layout");
            // SAFETY: allocated above with this layout.
            unsafe { dealloc(buf.cpu_ptr().as_ptr(), layout) }
        }
    }
}
