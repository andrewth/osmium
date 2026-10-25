//! Conversions and bit manipulation that need no interpreter state.

use alloc::string::String;
use alloc::vec::Vec;

/// Parses leading hex digits, as an implicit string-to-integer conversion does: no `0x`, stops at the
/// first other character, at most 16 digits.
pub(crate) fn parse_hex(s: &str) -> u64 {
    let mut v = 0u64;
    for d in s.bytes().take(16) {
        match char::from(d).to_digit(16) {
            Some(d) => v = v << 4 | u64::from(d),
            None => break,
        }
    }
    v
}

/// `ToInteger` on a string: `0x` prefixed is hex, anything else decimal. Leading blanks are skipped, and
/// the number ends at the first character that is not a digit.
pub(crate) fn parse_integer(s: &str, int64: bool) -> Option<u64> {
    let s = s.trim_start_matches([' ', '\t']);
    let (digits, radix) = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => (h, 16),
        None => (s, 10),
    };
    let mut v = 0u64;
    let mut any = false;
    for d in digits.chars() {
        let Some(d) = d.to_digit(radix) else { break };
        v = v.checked_mul(u64::from(radix))?.checked_add(u64::from(d))?;
        any = true;
    }
    if !any {
        return None;
    }
    (int64 || v <= u64::from(u32::MAX)).then_some(v)
}

/// A buffer read as a little-endian integer; bytes past the integer width are ignored.
pub(crate) fn buffer_to_integer(b: &[u8], int64: bool) -> u64 {
    le_to_u64(b.get(..if int64 { 8 } else { 4 }).unwrap_or(b))
}

/// An integer as little-endian bytes: 8, or 4 when integers are 32 bits wide.
pub(crate) fn integer_to_buffer(v: u64, int64: bool) -> Vec<u8> {
    v.to_le_bytes().iter().copied().take(if int64 { 8 } else { 4 }).collect()
}

/// Upper-case hex digits of `v`, zero-padded to at least `width` digits.
pub(crate) fn hex_string(v: u64, width: usize) -> String {
    let digits = (16 - (v.leading_zeros() as usize) / 4).max(1).max(width);
    let mut s = String::with_capacity(digits);
    for i in (0..digits).rev() {
        let nib = if i < 16 { (v >> (4 * i)) & 0xf } else { 0 };
        s.push(char::from_digit(nib as u32, 16).map_or('0', |c| c.to_ascii_uppercase()));
    }
    s
}

/// Position (1-based) of the most significant set bit, or 0.
pub(crate) fn find_set_left(v: u64) -> u64 {
    if v == 0 { 0 } else { 64 - u64::from(v.leading_zeros()) }
}

/// Position (1-based) of the least significant set bit, or 0.
pub(crate) fn find_set_right(v: u64) -> u64 {
    if v == 0 { 0 } else { u64::from(v.trailing_zeros()) + 1 }
}

/// Packed BCD to a number; `None` if a nibble is not a decimal digit.
pub(crate) fn from_bcd(v: u64) -> Option<u64> {
    let mut out = 0u64;
    let mut mul = 1u64;
    for i in 0..16 {
        let d = (v >> (4 * i)) & 0xf;
        if d > 9 {
            return None;
        }
        out += d * mul;
        mul = mul.wrapping_mul(10);
    }
    Some(out)
}

/// A number to packed BCD; `None` if it has more than 16 decimal digits.
pub(crate) fn to_bcd(mut v: u64) -> Option<u64> {
    let mut out = 0u64;
    for i in 0..16 {
        out |= (v % 10) << (4 * i);
        v /= 10;
    }
    (v == 0).then_some(out)
}

fn bit_of(bytes: &[u8], bit: usize) -> Option<bool> {
    Some(bytes.get(bit / 8)? >> (bit % 8) & 1 != 0)
}

/// Copies `len` bits from `src` at `src_bit` to `dst` at `dst_bit`. Fails if either range is out of
/// bounds; `dst` is then unchanged.
pub(crate) fn copy_bits(src: &[u8], src_bit: usize, dst: &mut [u8], dst_bit: usize, len: usize) -> Option<()> {
    if src_bit.checked_add(len)? > src.len().checked_mul(8)? || dst_bit.checked_add(len)? > dst.len().checked_mul(8)? {
        return None;
    }
    if len.is_multiple_of(8) && src_bit.is_multiple_of(8) && dst_bit.is_multiple_of(8) {
        let s = src.get(src_bit / 8..src_bit / 8 + len / 8)?;
        dst.get_mut(dst_bit / 8..dst_bit / 8 + len / 8)?.copy_from_slice(s);
        return Some(());
    }
    for i in 0..len {
        let on = bit_of(src, src_bit + i)?;
        let d = dst.get_mut((dst_bit + i) / 8)?;
        let m = 1u8 << ((dst_bit + i) % 8);
        if on {
            *d |= m;
        } else {
            *d &= !m;
        }
    }
    Some(())
}

/// `len` bits of `src` starting at `bit`, as a zero-padded little-endian byte vector.
pub(crate) fn get_bits(src: &[u8], bit: usize, len: usize) -> Option<Vec<u8>> {
    let mut out = alloc::vec![0u8; len.div_ceil(8)];
    copy_bits(src, bit, &mut out, 0, len)?;
    Some(out)
}

/// Replaces `len` bits of `dst` starting at `bit` with the low bits of `value`, zero-extended if `value`
/// is shorter.
pub(crate) fn put_bits(dst: &mut [u8], bit: usize, len: usize, value: &[u8]) -> Option<()> {
    let have = value.len().checked_mul(8)?.min(len);
    copy_bits(value, 0, dst, bit, have)?;
    if have < len {
        let zeros = alloc::vec![0u8; (len - have).div_ceil(8)];
        copy_bits(&zeros, 0, dst, bit + have, len - have)?;
    }
    Some(())
}

/// Up to eight little-endian bytes as an integer.
pub(crate) fn le_to_u64(b: &[u8]) -> u64 {
    b.iter().take(8).enumerate().fold(0u64, |a, (i, &x)| a | u64::from(x) << (8 * i))
}
