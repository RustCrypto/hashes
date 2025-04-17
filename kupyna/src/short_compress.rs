use crate::utils::{add_constant_plus, add_constant_xor, apply_s_box, mix_columns, xor_bytes};

pub(crate) const COLS: usize = 8;
const ROUNDS: u64 = 10;

type Matrix = [[u8; 8]; 8];

pub(crate) fn compress(prev_vector: &mut [u64; COLS], message_block: &[u8; 64]) {
    let mut prev_vector_u8 = [0u8; 64];
    for (src, dst) in prev_vector.iter().zip(prev_vector_u8.chunks_exact_mut(8)) {
        dst.copy_from_slice(&src.to_be_bytes());
    }

    let m_xor_p = xor_bytes(*message_block, prev_vector_u8);

    let t_xor_mp = t_xor_l(m_xor_p);

    let t_plus_m = t_plus_l(*message_block);

    prev_vector_u8 = xor_bytes(xor_bytes(t_xor_mp, t_plus_m), prev_vector_u8);

    for (dst, src) in prev_vector.iter_mut().zip(prev_vector_u8.chunks_exact(8)) {
        *dst = u64::from_be_bytes(src.try_into().unwrap());
    }
}

fn t_plus_l(block: [u8; 64]) -> [u8; 64] {
    let mut state = block_to_matrix(block);
    for nu in 0..ROUNDS {
        state = add_constant_plus(state, nu as usize);
        state = apply_s_box(state);
        state = rotate_rows(state);
        state = mix_columns(state);
    }
    matrix_to_block(state)
}

fn block_to_matrix(block: [u8; 64]) -> Matrix {
    const ROWS: usize = 8;
    const COLS: usize = 8;

    let mut matrix = [[0u8; COLS]; ROWS];
    for i in 0..ROWS {
        for j in 0..COLS {
            matrix[i][j] = block[i * COLS + j];
        }
    }
    matrix
}

fn matrix_to_block(matrix: Matrix) -> [u8; 64] {
    const ROWS: usize = 8;
    const COLS: usize = 8;

    let mut block = [0u8; ROWS * COLS];
    for i in 0..ROWS {
        for j in 0..COLS {
            block[i * COLS + j] = matrix[i][j];
        }
    }
    block
}

fn rotate_rows(mut state: Matrix) -> Matrix {
    const ROWS: usize = 8;
    const COLS: usize = 8;

    for i in 0..COLS {
        let shift = if i == COLS - 1 { 7 } else { i + 1 }; // Calculate the shift amount
        for row in 0..ROWS {
            let new_row = (row + shift) % ROWS; // Calculate the new row index
            state[new_row][i] = state[row][i];  // Perform the rotation
        }
    }

    state
}

pub(crate) fn t_xor_l(block: [u8; 64]) -> [u8; 64] {
    let mut state = block_to_matrix(block);
    for nu in 0..ROUNDS {
        state = add_constant_xor(state, nu as usize);
        state = apply_s_box(state);
        state = rotate_rows(state);
        state = mix_columns(state);
    }
    matrix_to_block(state)
}
