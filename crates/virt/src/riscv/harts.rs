//! The harts of a multi-vCPU RISC-V guest: [`GuestHarts`] is
//! [`GuestCpus`](crate::smp::GuestCpus) under its RISC-V name.

pub use crate::smp::{GuestCpus as GuestHarts, StartError, status};
