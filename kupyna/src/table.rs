use crate::consts::{MDS_MATRIX, SBOXES};

/// GF(2^8) multiplication with reduction polynomial x^8 + x^4 + x^3 + x^2 + 1
const fn gf_multiply(mut x: u8, mut y: u8) -> u8 {
    const REDUCTION_POLYNOMIAL: u8 = 0x1d; // x^4 + x^3 + x^2 + 1

    let mut r = 0u8;
    let mut i = 0;
    while i < 8 {
        if y & 1 == 1 {
            r ^= x;
        }
        let hbit = x & 0x80;
        x <<= 1;
        if hbit != 0 {
            x ^= REDUCTION_POLYNOMIAL;
        }
        y >>= 1;
        i += 1;
    }
    r
}

/// Generate T-tables that fuse SubBytes + MixColumns
///
/// TABLE[row][byte] gives the contribution to an output column when input byte
/// at position `row` has value `byte`, after applying S-box and MDS multiplication.
const fn generate_t_table() -> [[u64; 256]; 8] {
    let mut table = [[0u64; 256]; 8];

    let mut row = 0;
    while row < 8 {
        let mut byte = 0;
        while byte < 256 {
            // Apply S-box for this row position (S-boxes cycle with period 4)
            let s = SBOXES[row % 4][byte];

            // Compute contribution to each output row via MDS multiplication
            let mut out = [0u8; 8];
            let mut out_row = 0;
            while out_row < 8 {
                // Extract MDS coefficient: MDS_MATRIX[out_row] byte at position `row`
                let mds_coef = (MDS_MATRIX[out_row] >> (8 * (7 - row))) as u8;
                out[out_row] = gf_multiply(mds_coef, s);
                out_row += 1;
            }

            // Pack into u64 (big-endian)
            table[row][byte] = ((out[0] as u64) << 56)
                | ((out[1] as u64) << 48)
                | ((out[2] as u64) << 40)
                | ((out[3] as u64) << 32)
                | ((out[4] as u64) << 24)
                | ((out[5] as u64) << 16)
                | ((out[6] as u64) << 8)
                | (out[7] as u64);

            byte += 1;
        }
        row += 1;
    }
    table
}

pub(crate) static TABLE: [[u64; 256]; 8] = generate_t_table();
