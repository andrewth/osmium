//! Decoding the x86 instruction behind a nested page fault, so the access
//! can be emulated as MMIO. Covers the moves drivers use for device
//! registers: `MOV r/m, r` (88, 89), `MOV r, r/m` (8A, 8B), `MOV r/m, imm`
//! (C6, C7), `MOVZX r, r/m8|16` (0F B6, 0F B7) and the `moffs` forms
//! (A0-A3), with operand-size (66) and REX prefixes; and `TEST r/m, r`
//! (84, 85) and `TEST r/m, imm` (F6 /0, F7 /0), the way drivers poll a
//! status bit, as loads that only set flags.

/// Where the value of an emulated store comes from, or where a load goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operand {
    /// General-purpose register by number (0 = rax ... 15 = r15). For
    /// one-byte accesses without REX, 4-7 mean ah, ch, dh, bh.
    Reg(u8),
    /// An immediate (stores only).
    Imm(u64),
}

/// A decoded memory move.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Access {
    /// True for a store to memory.
    pub store: bool,
    /// Bytes moved (1, 2, 4 or 8).
    pub size: u8,
    /// The register (loads, register stores) or immediate (immediate stores).
    pub operand: Operand,
    /// Bytes written to the destination register: larger than `size` for
    /// MOVZX. Writes of 4 bytes zero the upper half in 64-bit mode.
    pub dest_size: u8,
    /// Whether a one-byte register operand without REX names ah..bh.
    pub high_byte: bool,
    /// Instruction length.
    pub len: u8,
    /// A `TEST`: the loaded value is ANDed with `operand` to set the flags,
    /// and no register is written.
    pub test: bool,
}

/// Decodes `code` (at least the instruction's bytes) executed with default
/// operand and address size `bits` (16, 32 or 64).
pub fn decode(code: &[u8], bits: u8) -> Option<Access> {
    let mut i = 0;
    let (mut opsize16, mut addr_override, mut rex) = (false, false, 0u8);
    // Legacy prefixes, then REX (64-bit mode only).
    loop {
        match *code.get(i)? {
            0x66 => opsize16 = true,
            0x67 => addr_override = true,
            0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0xf0 => {}
            _ => break,
        }
        i += 1;
    }
    if bits == 64 && code.get(i)? & 0xf0 == 0x40 {
        rex = code[i];
        i += 1;
    }
    let w = rex & 8 != 0;
    let full = if w {
        8
    } else if opsize16 != (bits == 16) {
        2
    } else {
        4
    };
    let addr_bits = match (bits, addr_override) {
        (64, false) => 64,
        (64, true) | (32, false) | (16, true) => 32,
        _ => 16,
    };
    let op = *code.get(i)?;
    i += 1;
    let mut test = false;
    let (store, size, imm, movzx) = match op {
        0x88 => (true, 1, 0, false),
        0x89 => (true, full, 0, false),
        0x8a => (false, 1, 0, false),
        0x8b => (false, full, 0, false),
        0xc6 => (true, 1, 1, false),
        0xc7 => (true, full, full.min(4), false),
        0x84 | 0x85 | 0xf6 | 0xf7 => {
            test = true;
            let size = if op & 1 == 0 { 1 } else { full };
            let imm = if op >= 0xf6 { size.min(4) } else { 0 };
            (false, size, imm, false)
        }
        0x0f => {
            let op2 = *code.get(i)?;
            i += 1;
            match op2 {
                0xb6 => (false, 1, 0, true),
                0xb7 => (false, 2, 0, true),
                _ => return None,
            }
        }
        0xa0..=0xa3 => {
            // moffs: the address follows directly; the register is rax.
            let size = if op & 1 == 0 { 1 } else { full };
            let len = i + addr_bits as usize / 8;
            code.get(len - 1)?;
            return Some(Access {
                store: op >= 0xa2,
                size,
                operand: Operand::Reg(0),
                dest_size: size,
                high_byte: false,
                len: len as u8,
                test: false,
            });
        }
        _ => return None,
    };
    let modrm = *code.get(i)?;
    i += 1;
    let (md, reg, rm) = (modrm >> 6, (modrm >> 3) & 7 | (rex & 4) << 1, modrm & 7);
    if md == 3 {
        return None; // register to register: not a memory access
    }
    if op >= 0xf6 && (modrm >> 3) & 7 != 0 {
        return None; // F6/F7 /2../7: NOT, NEG, MUL, DIV
    }
    // Addressing bytes: SIB and displacement.
    if addr_bits == 16 {
        i += match (md, rm) {
            (0, 6) => 2,
            (1, _) => 1,
            (2, _) => 2,
            _ => 0,
        };
    } else {
        if rm == 4 {
            let sib = *code.get(i)?;
            i += 1;
            if md == 0 && sib & 7 == 5 {
                i += 4;
            }
        }
        i += match (md, rm) {
            (0, 5) => 4, // disp32 (RIP-relative in 64-bit mode)
            (1, _) => 1,
            (2, _) => 4,
            _ => 0,
        };
    }
    let operand = if imm > 0 {
        let bytes = code.get(i..i + imm as usize)?;
        i += imm as usize;
        let mut v = bytes.iter().rev().fold(0u64, |v, &b| v << 8 | b as u64);
        if size == 8 {
            v = v as i32 as i64 as u64; // imm32 sign-extended
        }
        Operand::Imm(v)
    } else {
        Operand::Reg(reg)
    };
    code.get(i - 1)?;
    Some(Access {
        store,
        size,
        operand,
        dest_size: if movzx { full } else { size },
        high_byte: size == 1 && rex == 0 && imm == 0,
        len: i as u8,
        test,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(code: &[u8], bits: u8) -> Access {
        decode(code, bits).unwrap()
    }

    #[test]
    fn moves() {
        // mov [ebx], al
        let a = d(&[0x88, 0x03], 32);
        assert_eq!((a.store, a.size, a.operand, a.len), (true, 1, Operand::Reg(0), 2));
        // movzx eax, byte [ebx + 5]
        let a = d(&[0x0f, 0xb6, 0x43, 0x05], 32);
        assert_eq!((a.store, a.size, a.dest_size, a.operand, a.len), (false, 1, 4, Operand::Reg(0), 4));
        // mov ecx, [eax + esi*4 + 0x1000]
        let a = d(&[0x8b, 0x8c, 0xb0, 0x00, 0x10, 0x00, 0x00], 32);
        assert_eq!((a.size, a.operand, a.len), (4, Operand::Reg(1), 7));
        // mov word [edi], 0x1234
        let a = d(&[0x66, 0xc7, 0x07, 0x34, 0x12], 32);
        assert_eq!((a.store, a.size, a.operand, a.len), (true, 2, Operand::Imm(0x1234), 5));
        // mov dword [0xfed00000], 7 (disp32, no base)
        let a = d(&[0xc7, 0x05, 0x00, 0x00, 0xd0, 0xfe, 0x07, 0, 0, 0], 32);
        assert_eq!((a.operand, a.len), (Operand::Imm(7), 10));
        // mov ah, [esi]: a high-byte register
        assert!(d(&[0x8a, 0x26], 32).high_byte);
        // mov eax, [0x1000]: moffs32
        let a = d(&[0xa1, 0x00, 0x10, 0x00, 0x00], 32);
        assert_eq!((a.store, a.size, a.len), (false, 4, 5));
    }

    #[test]
    fn long_mode() {
        // mov [rdi + 8], r9 (REX.WR)
        let a = d(&[0x4c, 0x89, 0x4f, 0x08], 64);
        assert_eq!((a.store, a.size, a.operand, a.len), (true, 8, Operand::Reg(9), 4));
        // mov qword [rax], -1 (imm32 sign-extended)
        let a = d(&[0x48, 0xc7, 0x00, 0xff, 0xff, 0xff, 0xff], 64);
        assert_eq!(a.operand, Operand::Imm(u64::MAX));
        // mov sil, [rax]: REX makes 6 sil, not dh
        let a = d(&[0x40, 0x8a, 0x30], 64);
        assert!(!a.high_byte);
        assert_eq!(a.operand, Operand::Reg(6));
        // mov eax, [rip + 0x10]
        assert_eq!(d(&[0x8b, 0x05, 0x10, 0, 0, 0], 64).len, 6);
    }

    #[test]
    fn rejected() {
        assert_eq!(decode(&[0x89, 0xc3], 32), None, "mov ebx, eax");
        assert_eq!(decode(&[0x01, 0x03], 32), None, "add [ebx], eax");
        assert_eq!(decode(&[0x8b, 0x84, 0xb0], 32), None, "truncated");
        assert_eq!(decode(&[0xf7, 0x10], 32), None, "not dword [eax]");
    }

    #[test]
    fn tests() {
        // test dword [rax + 0x300], 0x1000 (polling a LAPIC status bit)
        let a = d(&[0xf7, 0x80, 0x00, 0x03, 0, 0, 0x00, 0x10, 0, 0], 64);
        assert_eq!((a.test, a.store, a.size, a.operand, a.len), (true, false, 4, Operand::Imm(0x1000), 10));
        // test byte [rdx], 0x20
        let a = d(&[0xf6, 0x02, 0x20], 64);
        assert_eq!((a.test, a.size, a.operand, a.len), (true, 1, Operand::Imm(0x20), 3));
        // test [rbx], ecx
        let a = d(&[0x85, 0x0b], 64);
        assert_eq!((a.test, a.size, a.operand), (true, 4, Operand::Reg(1)));
    }
}
