//! Typed addresses.

use core::fmt;
use core::ops::{Add, AddAssign, Sub};

/// Size of a base page.
pub const PAGE_SIZE: usize = osmium_arch::PAGE_SIZE;

macro_rules! address {
    ($(#[$m:meta])* $name:ident, $prefix:literal) => {
        $(#[$m])*
        #[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(transparent)]
        pub struct $name(pub u64);

        impl $name {
            /// The zero address.
            pub const ZERO: Self = Self(0);

            /// Wraps a raw address.
            pub const fn new(addr: u64) -> Self {
                Self(addr)
            }

            /// Returns the raw address.
            pub const fn as_u64(self) -> u64 {
                self.0
            }

            /// Returns the raw address as `usize`.
            pub const fn as_usize(self) -> usize {
                self.0 as usize
            }

            /// Rounds down to a multiple of `align` (a power of two).
            pub const fn align_down(self, align: u64) -> Self {
                debug_assert!(align.is_power_of_two());
                Self(self.0 & !(align - 1))
            }

            /// Rounds up to a multiple of `align` (a power of two).
            ///
            /// Overflows for addresses in the last `align` bytes of the
            /// address space (a panic in debug builds, 0 in release). Use
            /// [`Self::checked_align_up`] for addresses that come from
            /// firmware or other untrusted sources.
            pub const fn align_up(self, align: u64) -> Self {
                debug_assert!(align.is_power_of_two());
                Self((self.0 + align - 1) & !(align - 1))
            }

            /// Rounds up to a multiple of `align` (a power of two), or
            /// returns `None` if the result does not fit in 64 bits.
            pub const fn checked_align_up(self, align: u64) -> Option<Self> {
                debug_assert!(align.is_power_of_two());
                match self.0.checked_add(align - 1) {
                    Some(x) => Some(Self(x & !(align - 1))),
                    None => None,
                }
            }

            /// Returns true if the address is a multiple of `align`.
            pub const fn is_aligned(self, align: u64) -> bool {
                self.0 & (align - 1) == 0
            }

            /// Returns the offset within a base page.
            pub const fn page_offset(self) -> usize {
                (self.0 as usize) & (PAGE_SIZE - 1)
            }
        }

        impl Add<u64> for $name {
            type Output = Self;
            fn add(self, rhs: u64) -> Self {
                Self(self.0 + rhs)
            }
        }

        impl AddAssign<u64> for $name {
            fn add_assign(&mut self, rhs: u64) {
                self.0 += rhs;
            }
        }

        impl Sub<u64> for $name {
            type Output = Self;
            fn sub(self, rhs: u64) -> Self {
                Self(self.0 - rhs)
            }
        }

        impl Sub for $name {
            type Output = u64;
            fn sub(self, rhs: Self) -> u64 {
                self.0 - rhs.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!($prefix, "({:#x})"), self.0)
            }
        }

        impl fmt::LowerHex for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::LowerHex::fmt(&self.0, f)
            }
        }
    };
}

address!(
    /// A physical address.
    PhysAddr,
    "PA"
);
address!(
    /// A virtual address.
    VirtAddr,
    "VA"
);

impl VirtAddr {
    /// Creates a virtual address from a pointer.
    pub fn from_ptr<T: ?Sized>(ptr: *const T) -> Self {
        Self(ptr as *const u8 as usize as u64)
    }

    /// Returns the address as a pointer.
    pub const fn as_ptr<T>(self) -> *mut T {
        self.0 as usize as *mut T
    }

    /// Returns true if the address is canonical for `bits` significant bits,
    /// i.e. bits `63..bits-1` are all equal (sign extension).
    pub const fn is_canonical(self, bits: u32) -> bool {
        let shift = 64 - bits;
        (((self.0 << shift) as i64) >> shift) as u64 == self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alignment() {
        let a = PhysAddr::new(0x1234);
        assert_eq!(a.align_down(0x1000), PhysAddr::new(0x1000));
        assert_eq!(a.align_up(0x1000), PhysAddr::new(0x2000));
        assert!(PhysAddr::new(0x2000).is_aligned(0x1000));
        assert_eq!(a.page_offset(), 0x234);
        assert_eq!(a.checked_align_up(0x1000), Some(PhysAddr::new(0x2000)));
        assert_eq!(PhysAddr::new(u64::MAX - 0x7ff).checked_align_up(0x1000), None);
        assert_eq!(PhysAddr::new(u64::MAX - 0xfff).checked_align_up(0x1000), Some(PhysAddr::new(u64::MAX - 0xfff)));
    }

    #[test]
    fn canonical() {
        assert!(VirtAddr::new(0x0000_7fff_ffff_f000).is_canonical(48));
        assert!(VirtAddr::new(0xffff_8000_0000_0000).is_canonical(48));
        assert!(!VirtAddr::new(0x0000_8000_0000_0000).is_canonical(48));
        assert!(VirtAddr::new(0xffff_ffc0_0000_0000).is_canonical(39));
    }
}
