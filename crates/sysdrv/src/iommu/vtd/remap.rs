//! Interrupt remapping: the interrupt remapping table (IRT) of 128-bit
//! entries (IRTEs), the remappable-format MSI message and I/O APIC entry that
//! select an entry, and the unit's controls for them.
//!
//! With remapping on, an interrupt request in *remappable format* carries an
//! index (the "handle") instead of a destination and vector. The unit looks
//! the index up in the IRT, checks the requester against the entry's source
//! ID and delivers what the entry says. Requests in the old *compatibility
//! format* are blocked unless the caller allowed them.

use osmium_arch::barrier;
use osmium_hal::dma::{DmaAllocator, OwnedDma};
use osmium_hal::iommu::IommuError;
use osmium_hal::pci::{Address, MsiMessage};

use super::{CFI, ECAP_EIM, ECAP_IR, ECAP_QI, IRE, IRTA, SIRTP, Vtd};

/// Bytes per IRTE.
const IRTE_LEN: usize = 16;
/// Most entries a table holds: the handle is 16 bits.
pub const MAX_ENTRIES: u32 = 1 << 16;
/// `IRTA.EIME`: extended interrupt mode (32-bit destinations).
const IRTA_EIME: u64 = 1 << 11;

/// MSI address of the remappable format: the fixed `0xfee` prefix.
const MSI_BASE: u64 = 0xfee0_0000;
/// MSI address bit 4: remappable format.
const MSI_FORMAT: u64 = 1 << 4;
/// MSI address bit 3: the data's low 16 bits are added to the handle.
const MSI_SHV: u64 = 1 << 3;

/// The MSI or MSI-X message that raises the interrupt described by IRTE `handle`.
///
/// The address carries the handle (bits 19:5, and bit 2 for its top bit)
/// with the remappable-format bit set. The data is the sub-handle, which is
/// zero here: no sub-handle is added to the handle. A multi-message MSI
/// device (which cannot use the vectors in its data field) takes
/// [`msi_message_with_subhandle`] instead.
pub const fn msi_message(handle: u16) -> MsiMessage {
    MsiMessage { address: msi_address(handle), data: 0 }
}

/// Like [`msi_message`] for a device that supports `1 << n` MSI vectors and
/// would raise vector `subhandle`: the unit adds the sub-handle to the
/// handle, so the `1 << n` entries from `handle` serve one device. `handle`
/// must be a multiple of the vector count.
pub const fn msi_message_with_subhandle(handle: u16, subhandle: u16) -> MsiMessage {
    MsiMessage { address: msi_address(handle) | MSI_SHV, data: subhandle as u32 }
}

const fn msi_address(handle: u16) -> u64 {
    MSI_BASE | ((handle & 0x7fff) as u64) << 5 | ((handle >> 15) as u64) << 2 | MSI_FORMAT
}

/// The I/O APIC redirection entry, in remappable format, that raises IRTE
/// `handle`. The vector is still the low byte (the unit requires it to match
/// the IRTE's); delivery and destination come from the table.
pub const fn ioapic_entry(handle: u16, vector: u8, active_low: bool, level: bool, masked: bool) -> u64 {
    vector as u64
        | ((handle >> 15) as u64) << 11
        | (active_low as u64) << 13
        | (level as u64) << 15
        | (masked as u64) << 16
        | 1 << 48
        | ((handle & 0x7fff) as u64) << 49
}

/// How an interrupt is delivered (IRTE `DLM`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Delivery {
    /// To the CPU named by the destination.
    #[default]
    Fixed = 0,
    /// To the lowest-priority CPU among those the destination selects.
    LowestPriority = 1,
    /// Non-maskable interrupt.
    Nmi = 4,
    /// INIT.
    Init = 5,
    /// An 8259-style external interrupt.
    ExtInt = 7,
}

/// Which requesters may use an IRTE.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Source {
    /// Any: the entry is not checked against the sender.
    #[default]
    Any,
    /// Exactly this PCI function (all 16 bits of its requester ID).
    Device(Address),
    /// Any function on buses `first ..= last`.
    Buses {
        /// First bus.
        first: u8,
        /// Last bus.
        last: u8,
    },
}

/// An interrupt remapping table entry.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Irte {
    /// The vector delivered.
    pub vector: u8,
    /// Destination: the xAPIC ID (8 bits), or in extended mode the x2APIC ID.
    pub destination: u32,
    /// Delivery mode.
    pub delivery: Delivery,
    /// The destination is a logical (cluster or flat) ID, not a physical one.
    pub logical: bool,
    /// Level-triggered, not edge-triggered.
    pub level: bool,
    /// Redirection hint: let the unit pick among a logical destination's CPUs.
    pub redirect: bool,
    /// Who may raise it.
    pub source: Source,
}

impl Irte {
    /// An edge-triggered, fixed-delivery interrupt to the CPU with physical ID `destination`.
    pub const fn fixed(vector: u8, destination: u32, source: Source) -> Self {
        Self { vector, destination, delivery: Delivery::Fixed, logical: false, level: false, redirect: false, source }
    }

    /// The entry's two quadwords, present. `extended` is whether the table
    /// is in extended interrupt mode. Fails if the destination or source does
    /// not fit the format.
    pub fn encode(&self, extended: bool) -> Result<[u64; 2], IommuError> {
        let dest = if extended {
            (self.destination as u64) << 32
        } else {
            // xAPIC mode: the 8-bit ID sits in bits 47:40.
            if self.destination > 0xff {
                return Err(IommuError::OutOfRange);
            }
            (self.destination as u64) << 40
        };
        let lo = 1
            | (self.logical as u64) << 2
            | (self.redirect as u64) << 3
            | (self.level as u64) << 4
            | (self.delivery as u64) << 5
            | (self.vector as u64) << 16
            | dest;
        // Source ID, qualifier (compare all bits) and verification type.
        let hi = match self.source {
            Source::Any => 0,
            Source::Device(a) => {
                ((a.bus as u64) << 8 | ((a.device & 31) as u64) << 3 | (a.function & 7) as u64) | 1 << 18
            }
            Source::Buses { first, last } => {
                if first > last {
                    return Err(IommuError::OutOfRange);
                }
                (first as u64) << 8 | last as u64 | 2 << 18
            }
        };
        Ok([lo, hi])
    }

    /// Decodes the quadwords of a present entry; `None` if `P` is clear or
    /// the entry is in a format this type does not express (posted).
    pub fn decode(raw: [u64; 2], extended: bool) -> Option<Self> {
        let [lo, hi] = raw;
        if lo & 1 == 0 || lo & 1 << 15 != 0 {
            return None;
        }
        let delivery = match lo >> 5 & 7 {
            0 => Delivery::Fixed,
            1 => Delivery::LowestPriority,
            4 => Delivery::Nmi,
            5 => Delivery::Init,
            7 => Delivery::ExtInt,
            _ => return None,
        };
        let source = match hi >> 18 & 3 {
            0 => Source::Any,
            1 => Source::Device(Address::new((hi >> 8) as u8, (hi >> 3) as u8 & 31, hi as u8 & 7)),
            2 => Source::Buses { first: (hi >> 8) as u8, last: hi as u8 },
            _ => return None,
        };
        Some(Self {
            vector: (lo >> 16) as u8,
            destination: if extended { (lo >> 32) as u32 } else { (lo >> 40) as u8 as u32 },
            delivery,
            logical: lo & 1 << 2 != 0,
            level: lo & 1 << 4 != 0,
            redirect: lo & 1 << 3 != 0,
            source,
        })
    }
}

/// The table and mode of an enabled interrupt remapping unit.
pub(super) struct Remap<'d, D: DmaAllocator + ?Sized> {
    pub(super) table: OwnedDma<'d, D>,
    pub(super) entries: u32,
    pub(super) extended: bool,
}

impl<'d, D: DmaAllocator + Sync + ?Sized> Vtd<'d, D> {
    /// Whether the unit supports interrupt remapping (`ECAP.IR`, with queued
    /// invalidation, which keeps its entry cache coherent).
    pub fn supports_interrupt_remapping(&self) -> bool {
        self.ecap & ECAP_IR != 0 && self.ecap & ECAP_QI != 0
    }

    /// Whether the unit can address 32-bit APIC IDs in the table (`ECAP.EIM`).
    pub fn supports_extended_interrupt_mode(&self) -> bool {
        self.ecap & ECAP_EIM != 0
    }

    /// Whether remapping is on.
    pub fn interrupt_remapping_enabled(&self) -> bool {
        self.regs.r32(super::GSTS) & IRE != 0
    }

    /// Entries in the table, or zero if remapping is off.
    pub fn interrupt_entries(&self) -> u32 {
        self.state.lock().ir.as_ref().map_or(0, |ir| ir.entries)
    }

    /// Switches interrupt remapping on with a table of `entries` entries (a
    /// power of two, 2 to 65536; every one starts not present, so interrupts
    /// are blocked until [`set_irte`](Self::set_irte)). The first call also
    /// switches invalidation to the queue.
    ///
    /// `extended` selects extended interrupt mode (32-bit destinations, for
    /// x2APIC): the unit must support it, and the CPUs should already be in
    /// x2APIC mode. `allow_compatibility` lets old-format interrupts through
    /// unremapped; leave it false to block them.
    ///
    /// Devices that raise interrupts must be moved to the remappable format
    /// ([`msi_message`], [`ioapic_entry`]) before this blocks theirs. Fails
    /// with [`IommuError::Busy`] if remapping is on already.
    pub fn enable_interrupt_remapping(
        &self,
        entries: u32,
        extended: bool,
        allow_compatibility: bool,
    ) -> Result<(), IommuError> {
        if !self.supports_interrupt_remapping() || (extended && !self.supports_extended_interrupt_mode()) {
            return Err(IommuError::Unsupported);
        }
        if !entries.is_power_of_two() || !(2..=MAX_ENTRIES).contains(&entries) {
            return Err(IommuError::OutOfRange);
        }
        let mut st = self.state.lock();
        if st.ir.is_some() {
            return Err(IommuError::Busy);
        }
        self.enable_qi(&mut st)?;
        let table = OwnedDma::new(self.dma, entries as usize * IRTE_LEN).ok_or(IommuError::OutOfMemory)?;
        // Size field: the table holds 2^(S+1) entries.
        let size = entries.trailing_zeros() as u64 - 1;
        self.regs.w64(IRTA, table.device_addr().as_u64() | if extended { IRTA_EIME } else { 0 } | size);
        barrier::mb();
        // A failure below leaves the unit possibly pointing at the table, so it is
        // leaked then rather than freed.
        let table = core::mem::ManuallyDrop::new(table);
        self.regs.w32(super::GCMD, st.gcmd | SIRTP);
        self.wait(|| self.regs.r32(super::GSTS) & SIRTP != 0)?;
        self.qi_iec(None)?;
        // CFI goes in the same command as IRE, and only IRE's status is waited for:
        // units need not report CFI (QEMU's does not).
        st.gcmd = if allow_compatibility { st.gcmd | CFI } else { st.gcmd & !CFI } | IRE;
        self.regs.w32(super::GCMD, st.gcmd);
        self.wait(|| self.regs.r32(super::GSTS) & IRE != 0)?;
        st.ir = Some(Remap { table: core::mem::ManuallyDrop::into_inner(table), entries, extended });
        Ok(())
    }

    /// Switches interrupt remapping off and frees the table. Interrupts then
    /// arrive in compatibility format only, so devices must be put back first.
    pub fn disable_interrupt_remapping(&self) -> Result<(), IommuError> {
        let mut st = self.state.lock();
        if st.ir.is_none() {
            return Err(IommuError::NotAttached);
        }
        self.set_enabled(&mut st, IRE, false)?;
        st.ir = None;
        Ok(())
    }

    /// Programs entry `index` of the table and invalidates the unit's cached copy.
    pub fn set_irte(&self, index: u16, irte: &Irte) -> Result<(), IommuError> {
        let st = self.state.lock();
        let ir = st.ir.as_ref().ok_or(IommuError::NotAttached)?;
        if index as u32 >= ir.entries {
            return Err(IommuError::OutOfRange);
        }
        let [lo, hi] = irte.encode(ir.extended)?;
        let at = index as usize * IRTE_LEN;
        // The unit reads an entry whole, but the CPU stores it in halves: take the
        // old entry out of service, then publish the new one with P last.
        ir.table.store::<u64>(at, 0);
        barrier::dma_wmb();
        ir.table.store::<u64>(at + 8, hi);
        barrier::dma_wmb();
        ir.table.store::<u64>(at, lo);
        barrier::mb();
        self.qi_iec(Some(index))
    }

    /// Marks entry `index` not present, so interrupts using it are blocked,
    /// and invalidates the cached copy.
    pub fn clear_irte(&self, index: u16) -> Result<(), IommuError> {
        let st = self.state.lock();
        let ir = st.ir.as_ref().ok_or(IommuError::NotAttached)?;
        if index as u32 >= ir.entries {
            return Err(IommuError::OutOfRange);
        }
        let at = index as usize * IRTE_LEN;
        ir.table.store::<u64>(at, 0);
        barrier::dma_wmb();
        ir.table.store::<u64>(at + 8, 0);
        barrier::mb();
        self.qi_iec(Some(index))
    }

    /// The entry at `index` as the table holds it, if it is present.
    pub fn irte(&self, index: u16) -> Option<Irte> {
        let st = self.state.lock();
        let ir = st.ir.as_ref()?;
        if index as u32 >= ir.entries {
            return None;
        }
        let at = index as usize * IRTE_LEN;
        Irte::decode([ir.table.load::<u64>(at), ir.table.load::<u64>(at + 8)], ir.extended)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msi_message_carries_the_handle() {
        let m = msi_message(0x8005);
        assert_eq!(m.address, 0xfee0_0000 | 5 << 5 | 1 << 2 | 1 << 4);
        assert_eq!(m.data, 0);
        let m = msi_message_with_subhandle(0x20, 3);
        assert_eq!(m.address, 0xfee0_0000 | 0x20 << 5 | 1 << 4 | 1 << 3);
        assert_eq!(m.data, 3);
    }

    #[test]
    fn ioapic_entry_layout() {
        let e = ioapic_entry(0x8003, 0x41, true, true, false);
        assert_eq!(e & 0xff, 0x41);
        assert_eq!(e >> 11 & 1, 1, "handle bit 15");
        assert_eq!(e >> 13 & 1, 1);
        assert_eq!(e >> 15 & 1, 1);
        assert_eq!(e >> 16 & 1, 0);
        assert_eq!(e >> 48 & 1, 1, "remappable format");
        assert_eq!(e >> 49, 3);
        assert_eq!(ioapic_entry(1, 0x20, false, false, true) >> 16 & 1, 1);
    }

    #[test]
    fn irte_round_trips() {
        let dev = Address::new(0, 3, 1);
        for extended in [false, true] {
            let irte = Irte {
                vector: 0x51,
                destination: 7,
                delivery: Delivery::LowestPriority,
                logical: true,
                level: true,
                redirect: true,
                source: Source::Device(dev),
            };
            let raw = irte.encode(extended).unwrap();
            assert_eq!(raw[0] & 1, 1);
            assert_eq!(raw[0] >> 16 & 0xff, 0x51);
            assert_eq!(raw[1] & 0xffff, 0x19);
            assert_eq!(raw[1] >> 18 & 3, 1);
            assert_eq!(Irte::decode(raw, extended), Some(irte));
        }
        let buses = Irte::fixed(0x30, 0, Source::Buses { first: 2, last: 9 });
        assert_eq!(Irte::decode(buses.encode(false).unwrap(), false), Some(buses));
        assert_eq!(Irte::decode([0, 0], false), None);
    }

    #[test]
    fn destination_width_follows_the_mode() {
        let big = Irte::fixed(0x30, 0x1234, Source::Any);
        assert_eq!(big.encode(false), Err(IommuError::OutOfRange));
        assert_eq!(big.encode(true).unwrap()[0] >> 32, 0x1234);
        assert_eq!(Irte::fixed(0x30, 0xab, Source::Any).encode(false).unwrap()[0] >> 40, 0xab);
        let backwards = Irte::fixed(0x30, 0, Source::Buses { first: 9, last: 2 });
        assert_eq!(backwards.encode(false), Err(IommuError::OutOfRange));
    }
}
