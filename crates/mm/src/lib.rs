//! Memory management building blocks.
//!
//! - [`addr`]: typed physical and virtual addresses.
//! - [`map`]: [`MemoryMap`], a heap-free region list for boot-time memory
//!   accounting (what the firmware reports, minus the kernel image and
//!   reserved areas).
//! - [`frame`]: physical frame allocators ([`BuddyAllocator`],
//!   [`BitmapAllocator`]) and the [`PhysMapper`] that turns physical
//!   addresses into pointers.
//! - [`paging`]: a generic multi-level [`PageTable`] and PTE formats for
//!   x86_64, AArch64 stage 1, RISC-V Sv39/Sv48, Intel EPT and AArch64 stage 2.
//! - [`heap`]: a slab-style kernel heap usable as `#[global_allocator]`,
//!   backed by a static arena or the frame allocator.
#![no_std]

#[cfg(test)]
extern crate std;

pub mod addr;
pub mod frame;
pub mod heap;
pub mod map;
pub mod paging;

pub use addr::{PAGE_SIZE, PhysAddr, VirtAddr};
pub use frame::{BitmapAllocator, BuddyAllocator, FrameAllocator, LockedFrames, OffsetMapper, PhysMapper};
pub use map::{MemoryMap, Region, RegionKind};
pub use paging::{MapFlags, PageSize, PageTable};
