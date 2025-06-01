use crate::consts::{MDS_MATRIX, SBOXES};

const fn gf_multiply(x: u8, y: u8) -> u8 {
    const REDUCTION_POLYNOMIAL: u16 = 0x011d;

    let mut x = x;
    let mut y = y;
    let mut r = 0u8;
    let mut i = 0;
    while i < u8::BITS {
        if y & 1 == 1 {
            r ^= x;
        }
        let hbit = (x & 0x80) >> 7;
        x <<= 1;
        if hbit == 1 {
            x ^= REDUCTION_POLYNOMIAL as u8;
        }
        y >>= 1;
        i += 1;
    }

    r
}

const fn generate_gf_lookup_table() -> [[u8; 256]; 256] {
    let mut table = [[0u8; 256]; 256];
    let mut x = 0;
    while x < 256 {
        let mut y = 0;
        while y < 256 {
            table[x][y] = gf_multiply(x as u8, y as u8);
            y += 1;
        }
        x += 1;
    }
    table
}

static GF_LOOKUP_TABLE: [[u8; 256]; 256] = generate_gf_lookup_table();

fn multiply_gf(x: u8, y: u8) -> u8 {
    GF_LOOKUP_TABLE[usize::from(x)][usize::from(y)]
}

fn multiply_gf_array(a: &[u8; 8], b: &[u8; 8]) -> u8 {
    let mut res = 0;
    for i in 0..8 {
        res ^= multiply_gf(a[i], b[i]);
    }
    res
}

#[allow(clippy::needless_range_loop)]
pub(crate) fn mix_columns<const N: usize>(state: &mut [u64; N]) {
    for col in 0..N {
        let input = state[col];
        let bytes = input.to_be_bytes();
        let transformed_bytes = core::array::from_fn(|i|
            multiply_gf_array(&bytes, &MDS_MATRIX[i])
        );
        state[col] = u64::from_be_bytes(transformed_bytes);
    }
}

pub(crate) fn apply_s_box<const N: usize>(state: &mut [u64; N]) {
    for word in state.iter_mut() {
        let bytes = word.to_be_bytes();
        let transformed_bytes = core::array::from_fn(|i| {
            SBOXES[i % 4][bytes[i] as usize]
        });
        *word = u64::from_be_bytes(transformed_bytes);
    }
}

pub(crate) fn add_constant_xor<const N: usize>(state: &mut [u64; N], round: usize) {
    for (i, word) in state.iter_mut().enumerate() {
        let constant = ((i * 0x10) ^ round) as u64;
        *word ^= constant << 56; // Place the constant in the most significant byte
    }
}

pub(crate) fn add_constant_plus<const N: usize>(state: &mut [u64; N], round: usize) {
    for (i, word) in state.iter_mut().enumerate() {
        *word = word.swap_bytes().wrapping_add(0x00F0F0F0F0F0F0F3u64 ^ (((((N - i - 1) * 0x10) ^ round) as u64) << 56)).swap_bytes();
    }
}

#[inline(always)]
pub(crate) fn xor<const N: usize>(a: [u64; N], b: [u64; N]) -> [u64; N] {
    let mut result = [0u64; N];
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

#[inline(always)]
pub(crate) fn convert_message_block<const N: usize, const M: usize>(
    message_block: &[u8; N],
) -> [u64; M] {
    core::array::from_fn(|i| {
        let chunk = message_block[8 * i..][..8].try_into().unwrap();
        u64::from_be_bytes(chunk)
    })
}
