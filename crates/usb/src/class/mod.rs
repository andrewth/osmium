//! USB class drivers, generic over any [`UsbHost`](osmium_hal::usb::UsbHost).
//!
//! Each takes a device already [enumerated](osmium_hal::usb::enumerate) and
//! its configuration descriptor set, and holds the host it was given: a
//! `&mut` borrow for one driver at a time, or `&SpinLock<H>` to share a
//! controller among several.

pub mod ecm;
pub mod hid;
pub mod hub;
pub mod isoch;
pub mod ncm;
pub mod storage;
