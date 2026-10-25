//! Operation regions and the fields laid over them.

use alloc::vec::Vec;

use super::access::Mode;
use super::error::AmlError;
use super::exec::MAX_FIELD_BITS;
use super::host::{Host, PciAddress, space};
use super::interp::Interpreter;
use super::namespace::{BufferField, FieldKind, FieldUnit, NodeId, Object, ObjectKind, Update};
use super::ops;
use super::value::Value;

/// Deepest chain of PCI bridges followed when finding a device's bus.
const MAX_PCI_DEPTH: u32 = 16;

fn to_usize(v: u64) -> Result<usize, AmlError> {
    usize::try_from(v).map_err(|_| AmlError::OutOfBounds)
}

impl<H: Host> Interpreter<H> {
    /// The width in bits the field is accessed in.
    fn access_bits(&self, f: &FieldUnit) -> Result<u64, AmlError> {
        let want = match f.access {
            1 => 8,
            2 => 16,
            3 => 32,
            4 => 64,
            0 => {
                // The narrowest access that holds the whole field in one aligned unit, else bytes.
                let last = f.bit_offset.saturating_add(f.bit_len.max(1) - 1);
                [8u64, 16, 32, 64].into_iter().find(|w| f.bit_offset / w == last / w).unwrap_or(8)
            }
            _ => return Err(AmlError::Unsupported("buffer-access fields")),
        };
        // An index field cannot be read wider than its data register.
        let cap = match f.kind {
            FieldKind::Index { data, .. } => match self.ns.object(self.ns.resolve_alias(data)) {
                Some(Object::Field(d)) => [64u64, 32, 16].into_iter().find(|w| *w <= d.bit_len).unwrap_or(8),
                _ => 64,
            },
            _ => 64,
        };
        Ok(want.min(cap))
    }

    pub(crate) fn field_read(&mut self, f: &FieldUnit) -> Result<Value, AmlError> {
        if f.bit_len == 0 {
            return Ok(Value::Integer(0));
        }
        if f.bit_len > MAX_FIELD_BITS {
            return Err(AmlError::TooLarge);
        }
        let acc = self.access_bits(f)?;
        let unit_bytes = acc / 8;
        let first = f.bit_offset / acc;
        let last = f.bit_offset.checked_add(f.bit_len - 1).ok_or(AmlError::OutOfBounds)? / acc;
        let mut raw = Vec::new();
        for u in first..=last {
            let off = u.checked_mul(unit_bytes).ok_or(AmlError::OutOfBounds)?;
            let v = self.unit_read(f, off, acc)?;
            raw.extend(v.to_le_bytes().into_iter().take(unit_bytes as usize));
        }
        let shift = to_usize(f.bit_offset - first * acc)?;
        let bits = ops::get_bits(&raw, shift, to_usize(f.bit_len)?).ok_or(AmlError::OutOfBounds)?;
        Ok(if f.bit_len <= if f.int64 { 64 } else { 32 } {
            Value::Integer(ops::le_to_u64(&bits))
        } else {
            Value::Buffer(bits)
        })
    }

    pub(crate) fn field_write(&mut self, f: &FieldUnit, v: Value) -> Result<(), AmlError> {
        let src = match self.deref_data(v)? {
            Value::Integer(i) => i.to_le_bytes().to_vec(),
            Value::Buffer(b) => b,
            Value::String(s) => s.into_bytes(),
            Value::Uninit => return Err(AmlError::NoValue),
            _ => return Err(AmlError::TypeMismatch),
        };
        if f.bit_len == 0 {
            return Ok(());
        }
        if f.bit_len > MAX_FIELD_BITS {
            return Err(AmlError::TooLarge);
        }
        let acc = self.access_bits(f)?;
        let unit_bytes = acc / 8;
        let end = f.bit_offset.checked_add(f.bit_len).ok_or(AmlError::OutOfBounds)?;
        let mask = if acc == 64 { u64::MAX } else { (1u64 << acc) - 1 };
        for u in f.bit_offset / acc..=(end - 1) / acc {
            let unit_start = u * acc;
            let lo = f.bit_offset.max(unit_start);
            let hi = end.min(unit_start + acc);
            let off = u.checked_mul(unit_bytes).ok_or(AmlError::OutOfBounds)?;
            let mut unit = [0u8; 8];
            if lo != unit_start || hi != unit_start + acc {
                unit = match f.update {
                    Update::Preserve => self.unit_read(f, off, acc)?.to_le_bytes(),
                    Update::Ones => [0xff; 8],
                    Update::Zeros => [0; 8],
                };
            }
            let n = to_usize(hi - lo)?;
            let from = to_usize(lo - f.bit_offset)?;
            let available = src.len().saturating_mul(8).saturating_sub(from).min(n);
            let piece = ops::get_bits(&src, from.min(src.len() * 8), available).ok_or(AmlError::OutOfBounds)?;
            ops::put_bits(&mut unit, to_usize(lo - unit_start)?, n, &piece).ok_or(AmlError::OutOfBounds)?;
            self.unit_write(f, off, acc, u64::from_le_bytes(unit) & mask)?;
        }
        Ok(())
    }

    fn unit_read(&mut self, f: &FieldUnit, byte_off: u64, bits: u64) -> Result<u64, AmlError> {
        match f.kind {
            FieldKind::Region(r) => self.region_read(r, byte_off, bits),
            FieldKind::Bank { region, bank, value } => {
                self.write_node(bank, Value::Integer(value), Mode::Store)?;
                self.region_read(region, byte_off, bits)
            }
            FieldKind::Index { index, data } => {
                self.write_node(index, Value::Integer(byte_off), Mode::Store)?;
                match self.read_node(data)? {
                    Value::Integer(i) => Ok(i),
                    Value::Buffer(b) => Ok(ops::le_to_u64(&b)),
                    _ => Err(AmlError::TypeMismatch),
                }
            }
        }
    }

    fn unit_write(&mut self, f: &FieldUnit, byte_off: u64, bits: u64, value: u64) -> Result<(), AmlError> {
        match f.kind {
            FieldKind::Region(r) => self.region_write(r, byte_off, bits, value),
            FieldKind::Bank { region, bank, value: bank_value } => {
                self.write_node(bank, Value::Integer(bank_value), Mode::Store)?;
                self.region_write(region, byte_off, bits, value)
            }
            FieldKind::Index { index, data } => {
                self.write_node(index, Value::Integer(byte_off), Mode::Store)?;
                self.write_node(data, Value::Integer(value), Mode::Store)
            }
        }
    }

    /// Checks an access against the region and gives its space and address.
    fn region_target(&self, region: NodeId, off: u64, bits: u64) -> Result<(u8, u64), AmlError> {
        let Some(Object::Region(r)) = self.ns.object(self.ns.resolve_alias(region)) else {
            return Err(AmlError::TypeMismatch);
        };
        let end = off.checked_add(bits / 8).ok_or(AmlError::OutOfBounds)?;
        if end > r.length {
            return Err(AmlError::OutOfBounds);
        }
        Ok((r.space, r.offset.checked_add(off).ok_or(AmlError::OutOfBounds)?))
    }

    fn region_read(&mut self, region: NodeId, off: u64, bits: u64) -> Result<u64, AmlError> {
        let (sp, addr) = self.region_target(region, off, bits)?;
        let w = bits as u8;
        Ok(match sp {
            space::SYSTEM_MEMORY => self.host.read_memory(addr, w)?,
            space::SYSTEM_IO => {
                let port = u16::try_from(addr).map_err(|_| AmlError::OutOfBounds)?;
                if w == 64 {
                    let hi = self.host.read_io(port.checked_add(4).ok_or(AmlError::OutOfBounds)?, 32)?;
                    self.host.read_io(port, 32)? | hi << 32
                } else {
                    self.host.read_io(port, w)?
                }
            }
            space::PCI_CONFIG => {
                let at = self.pci_address(region)?;
                let o = u16::try_from(addr).ok().filter(|o| *o < 0x1000).ok_or(AmlError::OutOfBounds)?;
                if w == 64 {
                    let hi = self.host.read_pci(at, o + 4, 32)?;
                    self.host.read_pci(at, o, 32)? | hi << 32
                } else {
                    self.host.read_pci(at, o, w)?
                }
            }
            other => self.host.read_region(other, addr, w)?,
        })
    }

    fn region_write(&mut self, region: NodeId, off: u64, bits: u64, value: u64) -> Result<(), AmlError> {
        let (sp, addr) = self.region_target(region, off, bits)?;
        let w = bits as u8;
        match sp {
            space::SYSTEM_MEMORY => self.host.write_memory(addr, w, value)?,
            space::SYSTEM_IO => {
                let port = u16::try_from(addr).map_err(|_| AmlError::OutOfBounds)?;
                if w == 64 {
                    self.host.write_io(port, 32, value & 0xffff_ffff)?;
                    self.host.write_io(port.checked_add(4).ok_or(AmlError::OutOfBounds)?, 32, value >> 32)?;
                } else {
                    self.host.write_io(port, w, value)?;
                }
            }
            space::PCI_CONFIG => {
                let at = self.pci_address(region)?;
                let o = u16::try_from(addr).ok().filter(|o| *o < 0x1000).ok_or(AmlError::OutOfBounds)?;
                if w == 64 {
                    self.host.write_pci(at, o, 32, value & 0xffff_ffff)?;
                    self.host.write_pci(at, o + 4, 32, value >> 32)?;
                } else {
                    self.host.write_pci(at, o, w, value)?;
                }
            }
            other => self.host.write_region(other, addr, w, value)?,
        }
        Ok(())
    }

    // ----- PCI addressing -----

    /// The PCI function whose configuration space `region` (declared inside that device) covers.
    fn pci_address(&mut self, region: NodeId) -> Result<PciAddress, AmlError> {
        if let Some(a) = self.pci_cache.get(&region) {
            return Ok(*a);
        }
        let dev = self.ns.parent(region).ok_or(AmlError::NotFound)?;
        let a = self.pci_device_address(dev, 0)?;
        self.pci_cache.insert(region, a);
        Ok(a)
    }

    /// Where the device `dev` is: its `_ADR` on the bus below its parent bridge, or at the bus number
    /// `_BBN` gives if it is a root bridge.
    pub(crate) fn pci_device_address(&mut self, dev: NodeId, depth: u32) -> Result<PciAddress, AmlError> {
        if depth > MAX_PCI_DEPTH {
            return Err(AmlError::TooDeep);
        }
        let adr = self.child_value(dev, *b"_ADR").and_then(|v| v.as_integer()).unwrap_or(0);
        // A root bridge sits on the bus it names; any other device is on the bus below its parent.
        let (segment, bus) = if self.is_root_bridge(dev) {
            self.root_bus(dev)
        } else {
            match self.ns.parent(dev).filter(|p| self.ns.kind(*p) == Some(ObjectKind::Device)) {
                Some(parent) if self.is_root_bridge(parent) => self.root_bus(parent),
                Some(bridge) => {
                    let at = self.pci_device_address(bridge, depth + 1)?;
                    // The bridge's secondary bus number.
                    let secondary = self.host.read_pci(at, 0x19, 8)? as u8;
                    (at.segment, secondary)
                }
                None => (0, 0),
            }
        };
        Ok(PciAddress { segment, bus, device: ((adr >> 16) & 0x1f) as u8, function: (adr & 7) as u8 })
    }

    fn is_root_bridge(&mut self, dev: NodeId) -> bool {
        self.device_matches(dev, "PNP0A03") || self.device_matches(dev, "PNP0A08")
    }

    /// The segment (`_SEG`) and bus (`_BBN`) a root bridge hosts.
    fn root_bus(&mut self, root: NodeId) -> (u16, u8) {
        let seg = self.child_value(root, *b"_SEG").and_then(|v| v.as_integer()).unwrap_or(0);
        let bbn = self.child_value(root, *b"_BBN").and_then(|v| v.as_integer()).unwrap_or(0);
        (seg as u16, bbn as u8)
    }

    // ----- buffer fields -----

    pub(crate) fn buffer_field_read(&mut self, b: &BufferField) -> Result<Value, AmlError> {
        let Value::Buffer(buf) = self.read_data(&b.source)? else { return Err(AmlError::TypeMismatch) };
        let bits = ops::get_bits(&buf, to_usize(b.bit_offset)?, to_usize(b.bit_len)?).ok_or(AmlError::OutOfBounds)?;
        Ok(if b.bit_len <= if b.int64 { 64 } else { 32 } {
            Value::Integer(ops::le_to_u64(&bits))
        } else {
            Value::Buffer(bits)
        })
    }

    pub(crate) fn buffer_field_write(&mut self, b: &BufferField, v: Value) -> Result<(), AmlError> {
        let src = match self.deref_data(v)? {
            Value::Integer(i) => i.to_le_bytes().to_vec(),
            Value::Buffer(x) => x,
            Value::String(s) => s.into_bytes(),
            Value::Uninit => return Err(AmlError::NoValue),
            _ => return Err(AmlError::TypeMismatch),
        };
        let place = self.resolve_place(b.source.clone())?;
        let (off, len) = (to_usize(b.bit_offset)?, to_usize(b.bit_len)?);
        match self.place_value(&place)? {
            Value::Buffer(buf) => ops::put_bits(buf, off, len, &src).ok_or(AmlError::OutOfBounds),
            _ => Err(AmlError::TypeMismatch),
        }
    }
}
