//! Decoding the load or store that caused a guest page fault, so it can be
//! emulated as MMIO.

/// A decoded integer load or store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemOp {
    /// True for a store.
    pub store: bool,
    /// Access size in bytes (1, 2, 4 or 8).
    pub size: u8,
    /// Destination register (loads) or source register (stores).
    pub reg: u8,
    /// Whether a load sign-extends its result.
    pub signed: bool,
    /// Instruction length in bytes (2 or 4), to advance `sepc` by.
    pub len: u8,
}

impl MemOp {
    /// Sign- or zero-extends a loaded value according to the access.
    pub fn extend(&self, value: u64) -> u64 {
        let bits = 8 * self.size as u32;
        if bits == 64 {
            return value;
        }
        let v = value & ((1u64 << bits) - 1);
        if self.signed && v >> (bits - 1) != 0 { v | !((1u64 << bits) - 1) } else { v }
    }
}

/// Decodes `insn` as fetched from guest memory: a 32-bit instruction, or a
/// 16-bit compressed one in the low half.
pub fn decode(insn: u32) -> Option<MemOp> {
    if insn & 3 == 3 { decode32(insn, 4) } else { decode16(insn as u16) }
}

/// Decodes a transformed instruction from `htinst`. Loads and stores are
/// always given in their 32-bit form, with bit 1 clear if the original was
/// compressed. Zero (no information) and the pseudo-instructions for
/// implicit page-table accesses (bit 0 clear) return `None`.
pub fn decode_transformed(htinst: u64) -> Option<MemOp> {
    let insn = htinst as u32;
    if insn & 1 == 0 {
        return None;
    }
    decode32(insn | 2, if insn & 2 != 0 { 4 } else { 2 })
}

fn decode32(insn: u32, len: u8) -> Option<MemOp> {
    let funct3 = (insn >> 12) & 7;
    match insn & 0x7f {
        0x03 => {
            let (size, signed) = match funct3 {
                0 => (1, true),
                1 => (2, true),
                2 => (4, true),
                3 => (8, false),
                4 => (1, false),
                5 => (2, false),
                6 => (4, false),
                _ => return None,
            };
            Some(MemOp { store: false, size, reg: ((insn >> 7) & 31) as u8, signed, len })
        }
        0x23 if funct3 <= 3 => {
            Some(MemOp { store: true, size: 1 << funct3, reg: ((insn >> 20) & 31) as u8, signed: false, len })
        }
        _ => None,
    }
}

fn decode16(insn: u16) -> Option<MemOp> {
    let funct3 = insn >> 13;
    let rd_prime = (8 + ((insn >> 2) & 7)) as u8;
    let op = |store, size, reg| Some(MemOp { store, size, reg, signed: size == 4 && !store, len: 2 });
    match (insn & 3, funct3) {
        // Quadrant 0: C.LW, C.LD, C.SW, C.SD with rd'/rs2' in bits 4:2.
        (0, 2) => op(false, 4, rd_prime),
        (0, 3) => op(false, 8, rd_prime),
        (0, 6) => op(true, 4, rd_prime),
        (0, 7) => op(true, 8, rd_prime),
        // Quadrant 2: the sp-relative forms.
        (2, 2) => op(false, 4, ((insn >> 7) & 31) as u8),
        (2, 3) => op(false, 8, ((insn >> 7) & 31) as u8),
        (2, 6) => op(true, 4, ((insn >> 2) & 31) as u8),
        (2, 7) => op(true, 8, ((insn >> 2) & 31) as u8),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_and_stores() {
        // lw a0, 4(a1)
        assert_eq!(decode(0x0045_a503), Some(MemOp { store: false, size: 4, reg: 10, signed: true, len: 4 }));
        // lbu t0, 0(a0)
        assert_eq!(decode(0x0005_4283), Some(MemOp { store: false, size: 1, reg: 5, signed: false, len: 4 }));
        // sd s1, 8(sp)
        assert_eq!(decode(0x0091_3423), Some(MemOp { store: true, size: 8, reg: 9, signed: false, len: 4 }));
        // sb a1, 0(a0)
        assert_eq!(decode(0x00b5_0023), Some(MemOp { store: true, size: 1, reg: 11, signed: false, len: 4 }));
        // add a0, a0, a1: not a memory access
        assert_eq!(decode(0x00b5_0533), None);
    }

    #[test]
    fn compressed() {
        // c.lw a0, 0(a1)
        assert_eq!(decode(0x4188), Some(MemOp { store: false, size: 4, reg: 10, signed: true, len: 2 }));
        // c.sd a5, 8(a0)
        assert_eq!(decode(0xe51c), Some(MemOp { store: true, size: 8, reg: 15, signed: false, len: 2 }));
        // c.sw a5, 0(a0)
        assert_eq!(decode(0xc11c), Some(MemOp { store: true, size: 4, reg: 15, signed: false, len: 2 }));
        // c.ldsp ra, 8(sp)
        assert_eq!(decode(0x60a2), Some(MemOp { store: false, size: 8, reg: 1, signed: false, len: 2 }));
    }

    #[test]
    fn transformed() {
        // htinst for c.lw a0, 0(a1): lw a0, 0(x0) with bit 1 clear.
        assert_eq!(decode_transformed(0x2501), Some(MemOp { store: false, size: 4, reg: 10, signed: true, len: 2 }));
        // htinst for sw a5, 4(a0): rs1 and the offset cleared.
        assert_eq!(decode_transformed(0x00f0_2023), Some(MemOp { store: true, size: 4, reg: 15, signed: false, len: 4 }));
        assert_eq!(decode_transformed(0), None);
        assert_eq!(decode_transformed(0x3000), None, "pseudo-instruction");
    }

    #[test]
    fn extension() {
        let lb = decode(0x0005_0283).unwrap(); // lb t0, 0(a0)
        assert_eq!(lb.extend(0x80), 0xffff_ffff_ffff_ff80);
        assert_eq!(lb.extend(0x1_7f), 0x7f);
        let lhu = decode(0x0005_5283).unwrap(); // lhu t0, 0(a0)
        assert_eq!(lhu.extend(0xffff_8000), 0x8000);
    }
}
