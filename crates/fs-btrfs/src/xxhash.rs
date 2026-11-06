// SPDX-License-Identifier: GPL-2.0-only
//! XXH64, the 64-bit xxHash (used by zstd content checksums and btrfs `xxhash64` checksums).

const P1: u64 = 0x9E37_79B1_85EB_CA87;
const P2: u64 = 0xC2B2_AE3D_27D4_EB4F;
const P3: u64 = 0x1656_67B1_9E37_79F9;
const P4: u64 = 0x85EB_CA77_C2B2_AE63;
const P5: u64 = 0x27D4_EB2F_1656_67C5;

fn round(acc: u64, lane: u64) -> u64 {
    acc.wrapping_add(lane.wrapping_mul(P2)).rotate_left(31).wrapping_mul(P1)
}

fn merge(acc: u64, v: u64) -> u64 {
    (acc ^ round(0, v)).wrapping_mul(P1).wrapping_add(P4)
}

fn le64(b: &[u8; 8]) -> u64 {
    u64::from_le_bytes(*b)
}

/// The XXH64 hash of `data` with `seed`.
pub fn xxh64(data: &[u8], seed: u64) -> u64 {
    let (stripes, tail) = data.as_chunks::<32>();
    let mut h = if stripes.is_empty() {
        seed.wrapping_add(P5)
    } else {
        let mut v = [seed.wrapping_add(P1).wrapping_add(P2), seed.wrapping_add(P2), seed, seed.wrapping_sub(P1)];
        for stripe in stripes {
            for (acc, lane) in v.iter_mut().zip(stripe.as_chunks::<8>().0) {
                *acc = round(*acc, le64(lane));
            }
        }
        let [v1, v2, v3, v4] = v;
        let h = v1
            .rotate_left(1)
            .wrapping_add(v2.rotate_left(7))
            .wrapping_add(v3.rotate_left(12))
            .wrapping_add(v4.rotate_left(18));
        merge(merge(merge(merge(h, v1), v2), v3), v4)
    };
    h = h.wrapping_add(data.len() as u64);

    let (words, rest) = tail.as_chunks::<8>();
    for w in words {
        h = (h ^ round(0, le64(w))).rotate_left(27).wrapping_mul(P1).wrapping_add(P4);
    }
    let bytes = match rest.split_first_chunk::<4>() {
        Some((w, bytes)) => {
            h = (h ^ u64::from(u32::from_le_bytes(*w)).wrapping_mul(P1))
                .rotate_left(23)
                .wrapping_mul(P2)
                .wrapping_add(P3);
            bytes
        }
        None => rest,
    };
    for &b in bytes {
        h = (h ^ u64::from(b).wrapping_mul(P5)).rotate_left(11).wrapping_mul(P1);
    }

    // Avalanche.
    h ^= h >> 33;
    h = h.wrapping_mul(P2);
    h ^= h >> 29;
    h = h.wrapping_mul(P3);
    h ^ (h >> 32)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::xxh64;

    #[test]
    fn known_vectors() {
        // Reference values from the xxHash C implementation.
        const SEED: u64 = 0x9E37_79B9_7F4A_7C15;
        let cases: [(&[u8], u64, u64); 6] = [
            (b"", 0xEF46_DB37_51D8_E999, 0xC434_9FC9_3C01_0000),
            (b"a", 0xD24E_C4F1_A98C_6E5B, 0x9A7C_6D2E_A455_68C9),
            (b"abc", 0x44BC_2CF5_AD77_0999, 0x2ED0_F59D_6B43_AC8B),
            (b"message digest", 0x066E_D728_FCEE_B3BE, 0xDD80_FF41_2A48_92A0),
            (b"abcdefghijklmnopqrstuvwxyz", 0xCFE1_F278_FA89_835C, 0x9C22_0416_FEA1_09C1),
            (
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                0xE04A_477F_19EE_145D,
                0xC8FF_17E8_0174_1950,
            ),
        ];
        for (data, zero, seeded) in cases {
            assert_eq!(xxh64(data, 0), zero);
            assert_eq!(xxh64(data, SEED), seeded);
        }
        let mut pattern = [0u8; 1000];
        for (i, b) in pattern.iter_mut().enumerate() {
            *b = (i * 31 + 7) as u8;
        }
        assert_eq!(xxh64(&pattern, 0), 0x9959_4F48_2804_3D35);
        assert_eq!(xxh64(&pattern, 1), 0x31DB_8080_BC8E_B541);
    }
}
