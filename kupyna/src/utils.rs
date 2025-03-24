use crate::consts::{MDS_MATRIX, SBOXES};

fn multiply_gf(mut x: u8, mut y: u8) -> u8 {
    const BITS_IN_BYTE: u8 = 8;
    const REDUCTION_POLYNOMIAL: u16 = 0x011d;

    let mut r = 0u8;

    for _ in 0..BITS_IN_BYTE {
        if y & 1 == 1 {
            r ^= x;
        }
        let hbit = (x & 0x80) >> 7;
        x <<= 1;
        if hbit == 1 {
            x ^= REDUCTION_POLYNOMIAL as u8;
        }
        y >>= 1;
    }

    r
}

#[allow(clippy::needless_range_loop)]
pub(crate) fn mix_columns<const N: usize>(state: [[u8; 8]; N]) -> [[u8; 8]; N] {
    let mut result = [[0u8; 8]; N];

    for col in 0..N {
        for row in 0..8 {
            let mut product = 0u8;
            for b in 0..8 {
                product ^= multiply_gf(state[col][b], MDS_MATRIX[row][b]);
            }
            result[col][row] = product;
        }
    }

    result
}

pub(crate) fn apply_s_box<const N: usize>(mut state: [[u8; 8]; N]) -> [[u8; 8]; N] {
    for i in 0..8 {
        for row in state.iter_mut() {
            row[i] = SBOXES[i % 4][row[i] as usize];
        }
    }
    state
}

pub(crate) fn add_constant_xor<const N: usize>(
    mut state: [[u8; 8]; N],
    round: usize,
) -> [[u8; 8]; N] {
    for (j, row) in state.iter_mut().enumerate() {
        let constant = ((j * 0x10) ^ round) as u8;
        row[0] ^= constant;
    }
    state
}

pub(crate) fn add_constant_plus<const N: usize>(
    mut state: [[u8; 8]; N],
    round: usize,
) -> [[u8; 8]; N] {
    for (j, row) in state.iter_mut().enumerate() {
        let mut row_as_u64 = u64::from_le_bytes(*row);
        row_as_u64 = row_as_u64
            .wrapping_add(0x00F0F0F0F0F0F0F3u64 ^ (((((N - j - 1) * 0x10) ^ round) as u64) << 56));
        row[0..8].copy_from_slice(&row_as_u64.to_le_bytes());
    }
    state
}

#[inline(always)]
pub(crate) fn xor_bytes<const N: usize>(a: [u8; N], b: [u8; N]) -> [u8; N] {
    let mut result = [0u8; N];
    for i in 0..N {
        result[i] = a[i] ^ b[i];
    }
    result
}

#[inline(always)]
pub(crate) fn read_u64_le<const N: usize, const M: usize>(src: &[u8; N]) -> [u64; M] {
    assert_eq!(N, 8 * M);
    let mut res = [0; M];
    for (src, dst) in src.chunks_exact(8).zip(res.iter_mut()) {
        *dst = u64::from_le_bytes(src.try_into().unwrap());
    }
    res
}

#[inline(always)]
pub(crate) fn write_u64_le(src: &[u64], dst: &mut [u8]) {
    assert_eq!(8 * src.len(), dst.len());
    for (src, dst) in src.iter().zip(dst.chunks_exact_mut(8)) {
        dst.copy_from_slice(&src.to_le_bytes())
    }
}
