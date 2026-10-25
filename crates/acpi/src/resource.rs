//! Resource descriptors: the buffers `_CRS`, `_PRS` and `_SRS` pass around.

use alloc::vec::Vec;

use crate::aml::{AmlError, Host, Interpreter, NameSeg, NodeId, Value};

/// What a range of an address-space descriptor is a range of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressKind {
    /// Memory.
    Memory,
    /// I/O ports.
    Io,
    /// Bus numbers.
    BusNumber,
    /// A type this decoder does not know.
    Other(u8),
}

/// A Word, DWord, QWord or Extended Address Space descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressSpace {
    /// What the range is of.
    pub kind: AddressKind,
    /// Width of the descriptor's fields in bits: 16, 32 or 64.
    pub width: u8,
    /// The bridge produces this range for devices behind it (`ResourceProducer`), as opposed to consuming it.
    pub producer: bool,
    /// Subtractive decode.
    pub subtractive: bool,
    /// The minimum address is fixed.
    pub min_fixed: bool,
    /// The maximum address is fixed.
    pub max_fixed: bool,
    /// Address granularity (a mask of the bits the address may not vary in, as a bit pattern).
    pub granularity: u64,
    /// Minimum address.
    pub min: u64,
    /// Maximum address.
    pub max: u64,
    /// Added to a CPU address to give the address on the other side of the bridge.
    pub translation: u64,
    /// Length of the range.
    pub length: u64,
    /// The type-specific flags byte: for memory, bit 0 read/write, bits 1-2 cacheability (3 is
    /// prefetchable); for I/O, bits 0-1 the range type.
    pub type_flags: u8,
}

impl AddressSpace {
    /// Whether this memory range is prefetchable.
    pub fn prefetchable(&self) -> bool {
        self.kind == AddressKind::Memory && (self.type_flags >> 1) & 3 == 3
    }
}

/// One resource descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resource {
    /// An interrupt on the legacy 16-line PIC range.
    Irq {
        /// Bit `n` set means IRQ `n` is a choice.
        mask: u16,
        /// Edge triggered (else level).
        edge: bool,
        /// Active low (else high).
        active_low: bool,
        /// May be shared.
        shared: bool,
        /// Can wake the system.
        wake: bool,
    },
    /// An ISA DMA channel.
    Dma {
        /// Bit `n` set means channel `n` is a choice.
        mask: u8,
        /// The channel transfer width: 0 8-bit, 1 8 or 16-bit, 2 16-bit.
        width: u8,
        /// The device is a bus master.
        bus_master: bool,
    },
    /// `StartDependentFn`: the descriptors up to `EndDependentFn` are alternatives.
    StartDependent {
        /// Priority bytes, if present: compatibility in bits 0-1, performance in bits 2-3.
        priority: Option<u8>,
    },
    /// `EndDependentFn`.
    EndDependent,
    /// An I/O port range.
    Io {
        /// The device decodes all 16 address lines (else 10).
        decode16: bool,
        /// Lowest base address.
        min: u16,
        /// Highest base address.
        max: u16,
        /// Alignment of the base in ports.
        align: u8,
        /// Number of ports.
        length: u8,
    },
    /// A fixed I/O port range.
    FixedIo {
        /// Base port.
        base: u16,
        /// Number of ports.
        length: u8,
    },
    /// A fixed DMA request line and channel.
    FixedDma {
        /// The request line.
        request: u16,
        /// The channel.
        channel: u16,
        /// 0 8-bit, 1 16-bit, 2 both.
        width: u8,
    },
    /// 24-bit memory (addresses in bytes, though the descriptor counts 256-byte units).
    Memory24 {
        /// Writable.
        writable: bool,
        /// Lowest base address.
        min: u32,
        /// Highest base address.
        max: u32,
        /// Alignment in bytes.
        align: u32,
        /// Length in bytes.
        length: u32,
    },
    /// 32-bit memory with a range of base addresses.
    Memory32 {
        /// Writable.
        writable: bool,
        /// Lowest base address.
        min: u32,
        /// Highest base address.
        max: u32,
        /// Alignment in bytes.
        align: u32,
        /// Length in bytes.
        length: u32,
    },
    /// 32-bit memory at a fixed address.
    FixedMemory32 {
        /// Writable.
        writable: bool,
        /// Base address.
        base: u32,
        /// Length in bytes.
        length: u32,
    },
    /// A range of memory, ports or bus numbers.
    Address(AddressSpace),
    /// Interrupts as global system interrupt numbers.
    ExtendedIrq {
        /// The device produces the interrupt (an interrupt controller), as opposed to consuming it.
        producer: bool,
        /// Edge triggered (else level).
        edge: bool,
        /// Active low (else high).
        active_low: bool,
        /// May be shared.
        shared: bool,
        /// Can wake the system.
        wake: bool,
        /// The interrupts.
        gsis: Vec<u32>,
    },
    /// A register described as a Generic Address Structure.
    GenericRegister {
        /// Address space id (0 memory, 1 I/O, ...).
        space: u8,
        /// Register width in bits.
        bit_width: u8,
        /// Offset in bits.
        bit_offset: u8,
        /// Access size.
        access_size: u8,
        /// Address.
        address: u64,
    },
    /// A vendor-defined descriptor (small or large).
    Vendor(Vec<u8>),
    /// A descriptor this decoder does not interpret (GPIO, serial buses, ...), kept raw.
    Unknown {
        /// The descriptor's tag byte (large descriptors: `0x80 | name`).
        tag: u8,
        /// Its data, without the tag and length.
        data: Vec<u8>,
    },
}

/// Why a resource buffer could not be decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Malformed;

fn u16_at(d: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(*d.get(o..)?.first_chunk()?))
}

fn u32_at(d: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(*d.get(o..)?.first_chunk()?))
}

fn u64_at(d: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_le_bytes(*d.get(o..)?.first_chunk()?))
}

/// Decodes a resource template. Decoding stops at the end tag, or at the end of the buffer if it has none.
pub fn decode(buf: &[u8]) -> Result<Vec<Resource>, Malformed> {
    let mut out = Vec::new();
    let mut pos = 0;
    while let Some(&tag) = buf.get(pos) {
        let (name, len, header) = if tag & 0x80 == 0 {
            ((tag >> 3) & 0xf, usize::from(tag & 7), 1)
        } else {
            (tag & 0x7f, usize::from(u16_at(buf, pos + 1).ok_or(Malformed)?), 3)
        };
        let start = pos + header;
        let data = buf.get(start..start + len).ok_or(Malformed)?;
        pos = start + len;
        if tag & 0x80 == 0 && name == 0xf {
            break;
        }
        out.push(if tag & 0x80 == 0 { small(name, tag, data)? } else { large(name, tag, data)? });
    }
    Ok(out)
}

fn small(name: u8, tag: u8, d: &[u8]) -> Result<Resource, Malformed> {
    Ok(match name {
        0x4 => {
            let info = d.get(2).copied().unwrap_or(1);
            Resource::Irq {
                mask: u16_at(d, 0).ok_or(Malformed)?,
                edge: info & 1 != 0,
                active_low: info & 8 != 0,
                shared: info & 0x10 != 0,
                wake: info & 0x20 != 0,
            }
        }
        0x5 => {
            let flags = *d.get(1).ok_or(Malformed)?;
            Resource::Dma { mask: *d.first().ok_or(Malformed)?, width: flags & 3, bus_master: flags & 4 != 0 }
        }
        0x6 => Resource::StartDependent { priority: d.first().copied() },
        0x7 => Resource::EndDependent,
        0x8 => Resource::Io {
            decode16: d.first().ok_or(Malformed)? & 1 != 0,
            min: u16_at(d, 1).ok_or(Malformed)?,
            max: u16_at(d, 3).ok_or(Malformed)?,
            align: *d.get(5).ok_or(Malformed)?,
            length: *d.get(6).ok_or(Malformed)?,
        },
        0x9 => Resource::FixedIo { base: u16_at(d, 0).ok_or(Malformed)?, length: *d.get(2).ok_or(Malformed)? },
        0xa => Resource::FixedDma {
            request: u16_at(d, 0).ok_or(Malformed)?,
            channel: u16_at(d, 2).ok_or(Malformed)?,
            width: *d.get(4).ok_or(Malformed)?,
        },
        0xe => Resource::Vendor(d.to_vec()),
        _ => Resource::Unknown { tag, data: d.to_vec() },
    })
}

fn large(name: u8, tag: u8, d: &[u8]) -> Result<Resource, Malformed> {
    Ok(match name {
        0x01 => Resource::Memory24 {
            writable: d.first().ok_or(Malformed)? & 1 != 0,
            min: u32::from(u16_at(d, 1).ok_or(Malformed)?) << 8,
            max: u32::from(u16_at(d, 3).ok_or(Malformed)?) << 8,
            align: u32::from(u16_at(d, 5).ok_or(Malformed)?),
            length: u32::from(u16_at(d, 7).ok_or(Malformed)?) << 8,
        },
        0x02 => Resource::GenericRegister {
            space: *d.first().ok_or(Malformed)?,
            bit_width: *d.get(1).ok_or(Malformed)?,
            bit_offset: *d.get(2).ok_or(Malformed)?,
            access_size: *d.get(3).ok_or(Malformed)?,
            address: u64_at(d, 4).ok_or(Malformed)?,
        },
        0x04 => Resource::Vendor(d.to_vec()),
        0x05 => Resource::Memory32 {
            writable: d.first().ok_or(Malformed)? & 1 != 0,
            min: u32_at(d, 1).ok_or(Malformed)?,
            max: u32_at(d, 5).ok_or(Malformed)?,
            align: u32_at(d, 9).ok_or(Malformed)?,
            length: u32_at(d, 13).ok_or(Malformed)?,
        },
        0x06 => Resource::FixedMemory32 {
            writable: d.first().ok_or(Malformed)? & 1 != 0,
            base: u32_at(d, 1).ok_or(Malformed)?,
            length: u32_at(d, 5).ok_or(Malformed)?,
        },
        0x07 | 0x08 | 0x0a => address_space(name, d)?,
        0x0b => extended_address_space(d)?,
        0x09 => {
            let flags = *d.first().ok_or(Malformed)?;
            let count = usize::from(*d.get(1).ok_or(Malformed)?);
            let mut gsis = Vec::with_capacity(count);
            for i in 0..count {
                gsis.push(u32_at(d, 2 + 4 * i).ok_or(Malformed)?);
            }
            Resource::ExtendedIrq {
                producer: flags & 1 == 0,
                edge: flags & 2 != 0,
                active_low: flags & 4 != 0,
                shared: flags & 8 != 0,
                wake: flags & 0x10 != 0,
                gsis,
            }
        }
        _ => Resource::Unknown { tag, data: d.to_vec() },
    })
}

fn kind_of(t: u8) -> AddressKind {
    match t {
        0 => AddressKind::Memory,
        1 => AddressKind::Io,
        2 => AddressKind::BusNumber,
        o => AddressKind::Other(o),
    }
}

/// Word (`0x08`), DWord (`0x07`) and QWord (`0x0a`) address space descriptors.
fn address_space(name: u8, d: &[u8]) -> Result<Resource, Malformed> {
    let width = match name {
        0x08 => 2usize,
        0x07 => 4,
        _ => 8,
    };
    let flags = *d.get(1).ok_or(Malformed)?;
    let field = |i: usize| -> Result<u64, Malformed> {
        let o = 3 + i * width;
        match width {
            2 => u16_at(d, o).map(u64::from),
            4 => u32_at(d, o).map(u64::from),
            _ => u64_at(d, o),
        }
        .ok_or(Malformed)
    };
    Ok(Resource::Address(AddressSpace {
        kind: kind_of(*d.first().ok_or(Malformed)?),
        width: (width * 8) as u8,
        producer: flags & 1 == 0,
        subtractive: flags & 2 != 0,
        min_fixed: flags & 4 != 0,
        max_fixed: flags & 8 != 0,
        granularity: field(0)?,
        min: field(1)?,
        max: field(2)?,
        translation: field(3)?,
        length: field(4)?,
        type_flags: *d.get(2).ok_or(Malformed)?,
    }))
}

fn extended_address_space(d: &[u8]) -> Result<Resource, Malformed> {
    let flags = *d.get(1).ok_or(Malformed)?;
    let field = |i: usize| u64_at(d, 5 + i * 8).ok_or(Malformed);
    Ok(Resource::Address(AddressSpace {
        kind: kind_of(*d.first().ok_or(Malformed)?),
        width: 64,
        producer: flags & 1 == 0,
        subtractive: flags & 2 != 0,
        min_fixed: flags & 4 != 0,
        max_fixed: flags & 8 != 0,
        granularity: field(0)?,
        min: field(1)?,
        max: field(2)?,
        translation: field(3)?,
        length: field(4)?,
        type_flags: *d.get(2).ok_or(Malformed)?,
    }))
}

/// Encodes resources as a template ending in an end tag, for `_SRS`. Only the descriptors a device
/// is configured with are supported (interrupts, DMA, I/O, memory); `None` for the others.
pub fn encode(resources: &[Resource]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    for r in resources {
        match r {
            Resource::Irq { mask, edge, active_low, shared, wake } => {
                out.push(0x23);
                out.extend(mask.to_le_bytes());
                out.push(u8::from(*edge) | u8::from(*active_low) << 3 | u8::from(*shared) << 4 | u8::from(*wake) << 5);
            }
            Resource::Dma { mask, width, bus_master } => {
                out.extend([0x2a, *mask, width & 3 | u8::from(*bus_master) << 2]);
            }
            Resource::Io { decode16, min, max, align, length } => {
                out.extend([0x47, u8::from(*decode16)]);
                out.extend(min.to_le_bytes());
                out.extend(max.to_le_bytes());
                out.extend([*align, *length]);
            }
            Resource::FixedIo { base, length } => {
                out.push(0x4b);
                out.extend(base.to_le_bytes());
                out.push(*length);
            }
            Resource::FixedMemory32 { writable, base, length } => {
                out.extend([0x86, 9, 0, u8::from(*writable)]);
                out.extend(base.to_le_bytes());
                out.extend(length.to_le_bytes());
            }
            Resource::ExtendedIrq { producer, edge, active_low, shared, wake, gsis } => {
                let n = u8::try_from(gsis.len()).ok()?;
                let len = 2u16 + 4 * u16::from(n);
                out.push(0x89);
                out.extend(len.to_le_bytes());
                out.push(
                    u8::from(!*producer)
                        | u8::from(*edge) << 1
                        | u8::from(*active_low) << 2
                        | u8::from(*shared) << 3
                        | u8::from(*wake) << 4,
                );
                out.push(n);
                for g in gsis {
                    out.extend(g.to_le_bytes());
                }
            }
            Resource::StartDependent { priority: None } => out.push(0x30),
            Resource::StartDependent { priority: Some(p) } => out.extend([0x31, *p]),
            Resource::EndDependent => out.push(0x38),
            _ => return None,
        }
    }
    // End tag with a checksum of zero, which receivers treat as "don't check".
    out.extend([0x79, 0]);
    Some(out)
}

impl<H: Host> Interpreter<H> {
    /// The device's current resources: `_CRS`, decoded.
    pub fn current_resources(&mut self, dev: NodeId) -> Result<Vec<Resource>, AmlError> {
        self.resources_of(dev, *b"_CRS")
    }

    /// The resources the device can be set to: `_PRS`, decoded.
    pub fn possible_resources(&mut self, dev: NodeId) -> Result<Vec<Resource>, AmlError> {
        self.resources_of(dev, *b"_PRS")
    }

    fn resources_of(&mut self, dev: NodeId, name: [u8; 4]) -> Result<Vec<Resource>, AmlError> {
        let method = self.namespace().child(dev, NameSeg(name)).ok_or(AmlError::NotFound)?;
        match self.evaluate_node(method, &[])? {
            Value::Buffer(b) => decode(&b).map_err(|_| AmlError::InvalidOperand),
            _ => Err(AmlError::TypeMismatch),
        }
    }

    /// Configures the device with `_SRS`.
    pub fn set_resources(&mut self, dev: NodeId, resources: &[Resource]) -> Result<(), AmlError> {
        let method = self.namespace().child(dev, NameSeg(*b"_SRS")).ok_or(AmlError::NotFound)?;
        let buf = encode(resources).ok_or(AmlError::Unsupported("encoding this resource descriptor"))?;
        self.evaluate_node(method, &[Value::Buffer(buf)]).map(|_| ())
    }
}
