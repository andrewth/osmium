//! Boot-protocol parsing.
//!
//! - [`fdt`]: Flattened Device Tree (DTB) parsing, zero-copy and heap-free,
//!   plus an [`fdt::FdtWriter`] (feature `alloc`) for building trees, which a
//!   hypervisor needs to describe its guests.
//! - [`multiboot2`]: the Multiboot2 boot information structure (GRUB).
//! - [`elf`]: ELF64 executables (kernels, guests, user programs).
//! - [`acpi`]: RSDP/RSDT/XSDT, MADT (CPUs, I/O APICs) and MCFG (PCI ECAM).
//! - [`pvh`]: the PVH start-info structure (QEMU, Firecracker, Cloud
//!   Hypervisor), plus a macro for the ELF note that advertises a PVH entry.
//! - [`pe`]: PE32+ images: parse, map and relocate `.efi` files, and move
//!   runtime drivers to their virtual addresses.
//! - [`uefi`]: the UEFI system table, enough to print, set a Graphics Output
//!   Protocol (GOP) mode and take its framebuffer, and shut down.
//!
//! Both can populate an [`osmium_mm::MemoryMap`], the starting point for
//! the frame allocator.
#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod acpi;
pub mod elf;
pub mod fdt;
pub mod multiboot2;
pub mod pe;
pub mod pvh;
pub mod uefi;

/// Reads a big-endian `u32` at `off`.
pub(crate) fn be32(data: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_be_bytes(*data.get(off..)?.first_chunk::<4>()?))
}

/// Reads a big-endian `u64` at `off`.
pub(crate) fn be64(data: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_be_bytes(*data.get(off..)?.first_chunk::<8>()?))
}

/// Reads a little-endian `u32` at `off`.
pub(crate) fn le32(data: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(*data.get(off..)?.first_chunk::<4>()?))
}

/// Reads a little-endian `u64` at `off`.
pub(crate) fn le64(data: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(*data.get(off..)?.first_chunk::<8>()?))
}

/// Returns the string before the first NUL in `bytes`.
pub(crate) fn cstr(bytes: &[u8]) -> Option<&str> {
    let end = bytes.iter().position(|&b| b == 0)?;
    core::str::from_utf8(bytes.get(..end)?).ok()
}
