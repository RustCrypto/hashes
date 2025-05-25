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

    // Convert state to matrix format (column-major)
    let mut matrix = [[0u8; N]; 8];
    for col in 0..N {
        let bytes = state[col].to_be_bytes();
        for row in 0..8 {
            matrix[row][col] = bytes[row];
        }
    }

    // Apply MDS matrix to each column
    let mut result_matrix = [[0u8; N]; 8];
    for col in 0..N {
        for row in 0..8 {
            let mut product = 0u8;
            for b in 0..8 {
                product ^= multiply_gf(matrix[b][col], MDS_MATRIX[row][b]);
            }
            result_matrix[row][col] = product;
        }
    }

    // Convert back to u64 array
    for col in 0..N {
        let mut bytes = [0u8; 8];
        for row in 0..8 {
            bytes[row] = result_matrix[row][col];
        }
        result[col] = u64::from_be_bytes(bytes);
    }

    result
}

// pub(crate) fn apply_s_box<const N: usize>(state: [u64; N]) -> [u64; N] {
//     let mut result = [0u64; N];
// 
//     for (col, &word) in state.iter().enumerate() {
//         let mut transformed_word = 0u64;
// 
//         // Process each byte position (row) in the u64 word
//         for row in 0..8 {
//             // Extract the byte at position 'row' from the word
//             let byte = ((word >> (56 - row * 8)) & 0xFF) as u8;
// 
//             // Apply the appropriate S-box (π_{row mod 4})
//             let transformed_byte = SBOXES[row % 4][byte as usize];
// 
//             // Place the transformed byte back in the same position
//             transformed_word |= (transformed_byte as u64) << (56 - row * 8);
//         }
// 
//         result[col] = transformed_word;
//     }
// 
//     result
// }
// 
// pub(crate) fn apply_s_box<const N: usize>(state: [u64; N]) -> [u64; N] {
//     let mut result = [0u64; N];
// 
//     // Convert state to matrix format (column-major)
//     let mut matrix = [[0u8; N]; 8];
//     for col in 0..N {
//         let bytes = state[col].to_be_bytes();
//         for row in 0..8 {
//             matrix[row][col] = bytes[row];
//         }
//     }
// 
//     // Apply S-boxes based on row index (π_{i mod 4})
//     let mut result_matrix = [[0u8; N]; 8];
//     for row in 0..8 {
//         for col in 0..N {
//             result_matrix[row][col] = SBOXES[row % 4][matrix[row][col] as usize];
//         }
//     }
// 
//     // Convert back to u64 array
//     for col in 0..N {
//         let mut bytes = [0u8; 8];
//         for row in 0..8 {
//             bytes[row] = result_matrix[row][col];
//         }
//         result[col] = u64::from_be_bytes(bytes);
//     }
// 
//     result
// }

pub(crate) fn apply_s_box<const N: usize>(state: [u64; N]) -> [u64; N] {
    let mut result = [0u64; N];

    for (col, &word) in state.iter().enumerate() {
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

        // Reconstruct the u64 word
        result[col] = u64::from_be_bytes(transformed_bytes);
    }

    result
}

pub(crate) fn add_constant_xor<const N: usize>(
    mut state: [u64; N],
    round: usize,
) -> [u64; N] {
    for (j, word) in state.iter_mut().enumerate() {
        let constant = ((j * 0x10) ^ round) as u8;
        let mut bytes = word.to_be_bytes();
        bytes[0] ^= constant;
        *word = u64::from_be_bytes(bytes);
    }
    state
}

pub(crate) fn add_constant_plus<const N: usize>(
    mut state: [u64; N],
    round: usize,
) -> [u64; N] {
    for (j, word) in state.iter_mut().enumerate() {
        // Convert to little-endian bytes to match original behavior
        let mut row_as_u64 = u64::from_le_bytes(word.to_be_bytes());
        row_as_u64 = row_as_u64
            .wrapping_add(0x00F0F0F0F0F0F0F3u64 ^ (((((N - j - 1) * 0x10) ^ round) as u64) << 56));
        *word = u64::from_be_bytes(row_as_u64.to_le_bytes());
    }
    state
}

#[inline(always)]
pub(crate) fn xor_words<const N: usize>(a: [u64; N], b: [u64; N]) -> [u64; N] {
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