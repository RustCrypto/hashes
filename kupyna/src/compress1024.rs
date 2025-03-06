use crate::tables::{MDS_MATRIX, SBOXES};

pub(crate) const COLS: usize = 16;
const ROUNDS: u64 = 14;

const BITS_IN_BYTE: u8 = 8;
const REDUCTION_POLYNOMIAL: u16 = 0x011d;

type Matrix = [[u8; 8]; 16];

pub(crate) fn compress(prev_vector: &mut [u64; COLS], message_block: &[u8; 128]) {
    let mut prev_vector_u8 = [0u8; 128];
    for (i, &value) in prev_vector.iter().enumerate() {
        let bytes = value.to_be_bytes();
        prev_vector_u8[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
    }

    let m_xor_p = xor_bytes(*message_block, prev_vector_u8);

    let t_xor_mp = t_xor_l(m_xor_p);

    let t_plus_m = t_plus_l(*message_block);

    prev_vector_u8 = xor_bytes(xor_bytes(t_xor_mp, t_plus_m), prev_vector_u8);

    for i in 0..COLS {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&prev_vector_u8[i * 8..(i + 1) * 8]);
        prev_vector[i] = u64::from_be_bytes(bytes);
    }
}

pub fn t_plus_l(block: [u8; 128]) -> [u8; 128] {
    let mut state = block_to_matrix(block);
    for nu in 0..ROUNDS {
        state = add_constant_plus(state, nu as usize);
        state = s_box_layer(state);
        state = rotate_rows(state);
        state = mix_columns(state);
    }
    matrix_to_block(state)
}

fn block_to_matrix(block: [u8; 128]) -> Matrix {
    const ROWS: usize = 16;
    const COLS: usize = 8;

    let mut matrix = [[0u8; COLS]; ROWS];
    for i in 0..ROWS {
        for j in 0..COLS {
            matrix[i][j] = block[i * COLS + j];
        }
    }
    matrix
}

fn matrix_to_block(matrix: Matrix) -> [u8; 128] {
    const ROWS: usize = 16;
    const COLS: usize = 8;

    let mut block = [0u8; ROWS * COLS];
    for i in 0..ROWS {
        for j in 0..COLS {
            block[i * COLS + j] = matrix[i][j];
        }
    }
    block
}

fn add_constant_xor(mut state: Matrix, round: usize) -> Matrix {
    let rows = 16;
    for (j, row) in state.iter_mut().enumerate().take(rows) {
        let constant = ((j * 0x10) ^ round) as u8;
        row[0] ^= constant;
    }
    state
}

fn add_constant_plus(mut state: Matrix, round: usize) -> Matrix {
    let rows = 16;
    for (j, row) in state.iter_mut().enumerate().take(rows) {
        let mut row_as_u64 = u64::from_le_bytes(row[0..8].try_into().unwrap());
        row_as_u64 = row_as_u64.wrapping_add(
            0x00F0F0F0F0F0F0F3u64 ^ (((((rows - j - 1) * 0x10) ^ round) as u64) << 56),
        );
        row[0..8].copy_from_slice(&row_as_u64.to_le_bytes());
    }
    state
}

fn s_box_layer(mut state: Matrix) -> Matrix {
    let cols = 8;
    for i in 0..cols {
        for row in state.iter_mut() {
            row[i] = SBOXES[i % 4][row[i] as usize];
        }
    }
    state
}

fn rotate_rows(mut state: Matrix) -> Matrix {
    const ROWS: usize = 16;
    let cols = 8;

    let mut temp = [0u8; ROWS];
    let mut shift: i32 = -1;
    for i in 0..cols {
        if i == cols - 1 {
            shift = 11;
        } else {
            shift += 1;
        }
        for col in 0..ROWS {
            temp[(col + shift as usize) % ROWS] = state[col][i];
        }
        for col in 0..ROWS {
            state[col][i] = temp[col];
        }
    }
    state
}

fn multiply_gf(mut x: u8, mut y: u8) -> u8 {
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

fn mix_columns(state: Matrix) -> Matrix {
    const ROWS: usize = 16;
    const COLS: usize = 8;

    let mut result = [[0u8; COLS]; ROWS];

    for col in 0..ROWS {
        for row in (0..COLS).rev() {
            let mut product = 0u8;
            for b in (0..COLS).rev() {
                product ^= multiply_gf(state[col][b], MDS_MATRIX[row][b]);
            }
            result[col][row] = product;
        }
    }

    result
}

pub fn t_xor_l(block: [u8; 128]) -> [u8; 128] {
    let mut state = block_to_matrix(block);
    for nu in 0..ROUNDS {
        state = add_constant_xor(state, nu as usize);
        state = s_box_layer(state);
        state = rotate_rows(state);
        state = mix_columns(state);
    }
    matrix_to_block(state)
}

pub(crate) fn xor_bytes(a: [u8; 128], b: [u8; 128]) -> [u8; 128] {
    let mut result = [0u8; 128];
    for i in 0..128 {
        result[i] = a[i] ^ b[i];
    }
    result
}
