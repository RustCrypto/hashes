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

#[allow(clippy::needless_range_loop)]
pub(crate) fn mix_columns<const N: usize>(state: [u64; N]) -> [u64; N] {
    let mut result = [0u64; N];

    // Process each column independently using bit operations
    for col in 0..N {
        let input = state[col];
        let mut output = 0u64;

        // Extract each byte (row) from the u64 using bit shifts and masks
        let byte0 = ((input >> 56) & 0xFF) as u8;
        let byte1 = ((input >> 48) & 0xFF) as u8;
        let byte2 = ((input >> 40) & 0xFF) as u8;
        let byte3 = ((input >> 32) & 0xFF) as u8;
        let byte4 = ((input >> 24) & 0xFF) as u8;
        let byte5 = ((input >> 16) & 0xFF) as u8;
        let byte6 = ((input >> 8) & 0xFF) as u8;
        let byte7 = (input & 0xFF) as u8;

        // Compute each output row and directly place it in the result u64
        // Row 0: MDS_MATRIX[0] · input_column
        let out0 = multiply_gf(byte0, MDS_MATRIX[0][0]) ^
            multiply_gf(byte1, MDS_MATRIX[0][1]) ^
            multiply_gf(byte2, MDS_MATRIX[0][2]) ^
            multiply_gf(byte3, MDS_MATRIX[0][3]) ^
            multiply_gf(byte4, MDS_MATRIX[0][4]) ^
            multiply_gf(byte5, MDS_MATRIX[0][5]) ^
            multiply_gf(byte6, MDS_MATRIX[0][6]) ^
            multiply_gf(byte7, MDS_MATRIX[0][7]);
        output |= (out0 as u64) << 56;

        // Row 1
        let out1 = multiply_gf(byte0, MDS_MATRIX[1][0]) ^
            multiply_gf(byte1, MDS_MATRIX[1][1]) ^
            multiply_gf(byte2, MDS_MATRIX[1][2]) ^
            multiply_gf(byte3, MDS_MATRIX[1][3]) ^
            multiply_gf(byte4, MDS_MATRIX[1][4]) ^
            multiply_gf(byte5, MDS_MATRIX[1][5]) ^
            multiply_gf(byte6, MDS_MATRIX[1][6]) ^
            multiply_gf(byte7, MDS_MATRIX[1][7]);
        output |= (out1 as u64) << 48;

        // Row 2
        let out2 = multiply_gf(byte0, MDS_MATRIX[2][0]) ^
            multiply_gf(byte1, MDS_MATRIX[2][1]) ^
            multiply_gf(byte2, MDS_MATRIX[2][2]) ^
            multiply_gf(byte3, MDS_MATRIX[2][3]) ^
            multiply_gf(byte4, MDS_MATRIX[2][4]) ^
            multiply_gf(byte5, MDS_MATRIX[2][5]) ^
            multiply_gf(byte6, MDS_MATRIX[2][6]) ^
            multiply_gf(byte7, MDS_MATRIX[2][7]);
        output |= (out2 as u64) << 40;

        // Row 3
        let out3 = multiply_gf(byte0, MDS_MATRIX[3][0]) ^
            multiply_gf(byte1, MDS_MATRIX[3][1]) ^
            multiply_gf(byte2, MDS_MATRIX[3][2]) ^
            multiply_gf(byte3, MDS_MATRIX[3][3]) ^
            multiply_gf(byte4, MDS_MATRIX[3][4]) ^
            multiply_gf(byte5, MDS_MATRIX[3][5]) ^
            multiply_gf(byte6, MDS_MATRIX[3][6]) ^
            multiply_gf(byte7, MDS_MATRIX[3][7]);
        output |= (out3 as u64) << 32;

        // Row 4
        let out4 = multiply_gf(byte0, MDS_MATRIX[4][0]) ^
            multiply_gf(byte1, MDS_MATRIX[4][1]) ^
            multiply_gf(byte2, MDS_MATRIX[4][2]) ^
            multiply_gf(byte3, MDS_MATRIX[4][3]) ^
            multiply_gf(byte4, MDS_MATRIX[4][4]) ^
            multiply_gf(byte5, MDS_MATRIX[4][5]) ^
            multiply_gf(byte6, MDS_MATRIX[4][6]) ^
            multiply_gf(byte7, MDS_MATRIX[4][7]);
        output |= (out4 as u64) << 24;

        // Row 5
        let out5 = multiply_gf(byte0, MDS_MATRIX[5][0]) ^
            multiply_gf(byte1, MDS_MATRIX[5][1]) ^
            multiply_gf(byte2, MDS_MATRIX[5][2]) ^
            multiply_gf(byte3, MDS_MATRIX[5][3]) ^
            multiply_gf(byte4, MDS_MATRIX[5][4]) ^
            multiply_gf(byte5, MDS_MATRIX[5][5]) ^
            multiply_gf(byte6, MDS_MATRIX[5][6]) ^
            multiply_gf(byte7, MDS_MATRIX[5][7]);
        output |= (out5 as u64) << 16;

        // Row 6
        let out6 = multiply_gf(byte0, MDS_MATRIX[6][0]) ^
            multiply_gf(byte1, MDS_MATRIX[6][1]) ^
            multiply_gf(byte2, MDS_MATRIX[6][2]) ^
            multiply_gf(byte3, MDS_MATRIX[6][3]) ^
            multiply_gf(byte4, MDS_MATRIX[6][4]) ^
            multiply_gf(byte5, MDS_MATRIX[6][5]) ^
            multiply_gf(byte6, MDS_MATRIX[6][6]) ^
            multiply_gf(byte7, MDS_MATRIX[6][7]);
        output |= (out6 as u64) << 8;

        // Row 7
        let out7 = multiply_gf(byte0, MDS_MATRIX[7][0]) ^
            multiply_gf(byte1, MDS_MATRIX[7][1]) ^
            multiply_gf(byte2, MDS_MATRIX[7][2]) ^
            multiply_gf(byte3, MDS_MATRIX[7][3]) ^
            multiply_gf(byte4, MDS_MATRIX[7][4]) ^
            multiply_gf(byte5, MDS_MATRIX[7][5]) ^
            multiply_gf(byte6, MDS_MATRIX[7][6]) ^
            multiply_gf(byte7, MDS_MATRIX[7][7]);
        output |= out7 as u64;

        result[col] = output;
    }

    result
}

pub(crate) fn apply_s_box<const N: usize>(state: &mut [u64; N]) {
    for word in state.iter_mut() {
        // Extract all bytes at once
        let bytes = word.to_be_bytes();

        // Transform each byte using the appropriate S-box
        let transformed_bytes = [
            SBOXES[0][bytes[0] as usize], // row 0 -> S-box 0
            SBOXES[1][bytes[1] as usize], // row 1 -> S-box 1
            SBOXES[2][bytes[2] as usize], // row 2 -> S-box 2
            SBOXES[3][bytes[3] as usize], // row 3 -> S-box 3
            SBOXES[0][bytes[4] as usize], // row 4 -> S-box 0 (4 % 4 = 0)
            SBOXES[1][bytes[5] as usize], // row 5 -> S-box 1 (5 % 4 = 1)
            SBOXES[2][bytes[6] as usize], // row 6 -> S-box 2 (6 % 4 = 2)
            SBOXES[3][bytes[7] as usize], // row 7 -> S-box 3 (7 % 4 = 3)
        ];

        // Update the word in-place
        *word = u64::from_be_bytes(transformed_bytes);
    }
}

pub(crate) fn add_constant_xor<const N: usize>(state: &mut [u64; N], round: usize) {
    for (j, word) in state.iter_mut().enumerate() {
        let constant = ((j * 0x10) ^ round) as u8;
        let mut bytes = word.to_be_bytes();
        bytes[0] ^= constant;
        *word = u64::from_be_bytes(bytes);
    }
}

pub(crate) fn add_constant_plus<const N: usize>(state: &mut [u64; N], round: usize) {
    for (j, word) in state.iter_mut().enumerate() {
        // Convert to little-endian bytes to match original behavior
        let mut row_as_u64 = u64::from_le_bytes(word.to_be_bytes());
        row_as_u64 = row_as_u64
            .wrapping_add(0x00F0F0F0F0F0F0F3u64 ^ (((((N - j - 1) * 0x10) ^ round) as u64) << 56));
        *word = u64::from_be_bytes(row_as_u64.to_le_bytes());
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
