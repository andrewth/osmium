//! PCI interrupt routing: the `_PRT` tables of host bridges and PCI-to-PCI bridges.

use alloc::vec::Vec;

use crate::aml::{AmlError, Host, Interpreter, NameSeg, NodeId, ObjectKind, Ref, Value};
use crate::resource::Resource;

/// Where a PCI interrupt pin is wired to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrtSource {
    /// Straight to a global system interrupt.
    Gsi(u32),
    /// To a PCI interrupt link device (`PNP0C0F`), whose resources say which interrupt it is.
    Link {
        /// The link device.
        node: NodeId,
        /// Which of the link's interrupt resources, normally 0.
        index: u32,
    },
}

/// One row of a `_PRT`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrtEntry {
    /// PCI device number.
    pub device: u8,
    /// Function number, or `None` if the row applies to every function.
    pub function: Option<u8>,
    /// Interrupt pin: 0 INTA#, 1 INTB#, 2 INTC#, 3 INTD#.
    pub pin: u8,
    /// Where the pin goes.
    pub source: PrtSource,
}

/// How an interrupt is delivered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IrqRoute {
    /// The global system interrupt.
    pub gsi: u32,
    /// Level triggered (else edge).
    pub level_triggered: bool,
    /// Active low (else high).
    pub active_low: bool,
    /// May be shared.
    pub shared: bool,
}

impl<H: Host> Interpreter<H> {
    /// Reads the `_PRT` of a bridge.
    pub fn pci_routing_table(&mut self, bridge: NodeId) -> Result<Vec<PrtEntry>, AmlError> {
        let prt = self.namespace().child(bridge, NameSeg(*b"_PRT")).ok_or(AmlError::NotFound)?;
        let Value::Package(rows) = self.evaluate_node(prt, &[])? else { return Err(AmlError::TypeMismatch) };
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let Value::Package(f) = row else { return Err(AmlError::TypeMismatch) };
            let [address, pin, source, index, ..] = f.as_slice() else { return Err(AmlError::TypeMismatch) };
            let (Value::Integer(address), Value::Integer(pin), Value::Integer(index)) = (address, pin, index) else {
                return Err(AmlError::TypeMismatch);
            };
            let source = match source {
                Value::Integer(0) => PrtSource::Gsi(u32::try_from(*index).map_err(|_| AmlError::InvalidOperand)?),
                Value::Reference(Ref::Node(node)) => PrtSource::Link { node: *node, index: *index as u32 },
                Value::String(path) => {
                    let node = self.namespace().find_from(bridge, path).ok_or(AmlError::NotFound)?;
                    PrtSource::Link { node, index: *index as u32 }
                }
                _ => return Err(AmlError::TypeMismatch),
            };
            out.push(PrtEntry {
                device: (address >> 16) as u8 & 0x1f,
                function: (*address & 0xffff != 0xffff).then_some((*address & 7) as u8),
                pin: *pin as u8 & 3,
                source,
            });
        }
        Ok(out)
    }

    /// Where the interrupt `pin` (0 INTA# to 3 INTD#) of a PCI device on `bridge`'s bus goes, or `None` if
    /// the table has no row for it. A pin wired to a link device is resolved through the link's current
    /// resources, so the link must already be configured (`_CRS` names an interrupt); `None` otherwise.
    pub fn route_pci_irq(
        &mut self,
        bridge: NodeId,
        device: u8,
        function: u8,
        pin: u8,
    ) -> Result<Option<IrqRoute>, AmlError> {
        let table = self.pci_routing_table(bridge)?;
        let row = table.iter().find(|e| e.device == device && e.pin == pin && e.function.is_none_or(|f| f == function));
        let Some(row) = row else { return Ok(None) };
        match row.source {
            // PCI interrupts wired straight to a GSI are level triggered and active low.
            PrtSource::Gsi(gsi) => Ok(Some(IrqRoute { gsi, level_triggered: true, active_low: true, shared: true })),
            PrtSource::Link { node, index } => {
                if self.namespace().kind(node) != Some(ObjectKind::Device) {
                    return Err(AmlError::TypeMismatch);
                }
                let mut seen = 0;
                for r in self.current_resources(node)? {
                    let route = match r {
                        Resource::Irq { mask, edge, active_low, shared, .. } if mask.count_ones() == 1 => {
                            IrqRoute { gsi: mask.trailing_zeros(), level_triggered: !edge, active_low, shared }
                        }
                        Resource::ExtendedIrq { edge, active_low, shared, gsis, .. } if gsis.len() == 1 => IrqRoute {
                            gsi: gsis.first().copied().unwrap_or(0),
                            level_triggered: !edge,
                            active_low,
                            shared,
                        },
                        _ => continue,
                    };
                    if seen == index {
                        return Ok(Some(route));
                    }
                    seen += 1;
                }
                Ok(None)
            }
        }
    }
}
