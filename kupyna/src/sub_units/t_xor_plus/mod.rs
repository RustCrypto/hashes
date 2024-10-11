#[cfg(test)]
mod tests;

mod tables;

const ROWS: usize = 16;
const COLS: usize = 8; // For 512-bit state, adjust if needed

const BITS_IN_BYTE: u8 = 8;
const REDUCTION_POLYNOMIAL: u16 = 0x011d;

type Matrix = Vec<Vec<u8>>;

use tables::{MDS_MATRIX, SBOXES};
use crate::KupynaH;

pub(crate) fn block_to_matrix(block: &[u8], hash_params: &KupynaH) -> Matrix {
    let rows = hash_params.state_matrix_rows;
    let cols = hash_params.state_matrix_cols;

    let mut matrix = vec![vec![0u8; cols]; rows];
    for i in 0..rows {
        for j in 0..cols {
            matrix[i][j] = block[i * cols + j];
        }
    }
    matrix
}

fn matrix_to_block(matrix: Matrix) -> Vec<u8> {

    let rows = matrix.len();
    let cols = matrix[0].len();

    let mut block = vec![0u8; rows*cols];
    for i in 0..rows {
        for j in 0..cols {
            block[i * cols + j] = matrix[i][j];
        }
    }
    block
}

pub(crate) fn add_constant_xor(mut state: Matrix, round: usize, hash_params: &KupynaH) -> Matrix {
    let rows = hash_params.state_matrix_rows;
    for (j, row) in state.iter_mut().enumerate().take(rows) {
        let constant = ((j * 0x10) ^ round) as u8;
        row[0] ^= constant;
    }
    state
}

pub(crate) fn add_constant_plus(mut state: Matrix, round: usize, hash_params: &KupynaH) -> Matrix {
    let rows = hash_params.state_matrix_rows;
    for j in 0..rows {
        let mut row_as_u64 = u64::from_le_bytes(state[j][0..8].try_into().unwrap());
        row_as_u64 = row_as_u64.wrapping_add(
            0x00F0F0F0F0F0F0F3u64 ^ (((((rows - j - 1) * 0x10) ^ round) as u64) << 56),
        );
        state[j][0..8].copy_from_slice(&row_as_u64.to_le_bytes());
    }
    state
}

pub(crate) fn s_box_layer(mut state: Matrix, hash_params: &KupynaH) -> Matrix {
    let cols = hash_params.state_matrix_cols;
    for i in 0..cols {
        for row in state.iter_mut() {
            row[i] = SBOXES[i % 4][row[i] as usize];
        }
    }
    state
}

pub(crate) fn rotate_rows(mut state: Matrix, hash_params: &KupynaH) -> Matrix {

    let rows = hash_params.state_matrix_rows;
    let cols = hash_params.state_matrix_cols;

    let mut temp = vec![0u8; rows];
    let mut shift: i32 = -1;
    for i in 0..cols {
        if i == cols - 1 {
            shift = 11;
        } else {
            shift += 1;
        }
        for col in 0..rows {
            temp[(col + shift as usize) % rows] = state[col][i];
        }
        for col in 0..rows {
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

pub(crate) fn mix_columns(state: Matrix, hash_params: &KupynaH) -> Matrix {

    let rows = hash_params.state_matrix_rows;
    let cols = hash_params.state_matrix_cols;

    let mut result = vec![vec![0u8; cols]; rows];

    for col in 0..rows {
        for row in (0..cols).rev() {
            let mut product = 0u8;
            for b in (0..cols).rev() {
                product ^= multiply_gf(state[col][b], MDS_MATRIX[row][b]);
            }
            result[col][row] = product;
        }
    }

    result
}

/// Placeholder for the T⊕l transformation.
///
/// # Arguments
///
/// * `block` - A byte slice representing the block to be transformed.
/// * `_rounds` - The number of rounds to perform.
///
/// # Returns
///
/// * A `Vec<u8>` containing the transformed block.
pub fn t_xor_l(block: &[u8], hash_params: &KupynaH) -> Vec<u8> {
    let mut state = block_to_matrix(block, hash_params);
    for nu in 0..hash_params.rounds {
        state = add_constant_xor(state, nu, hash_params);
        state = s_box_layer(state, hash_params);
        state = rotate_rows(state, hash_params);
        state = mix_columns(state, hash_params);
    }
    matrix_to_block(state)
}

/// Placeholder for the T+l transformation.
///
/// # Arguments
///
/// * `block` - A byte slice representing the block to be transformed.
/// * `_rounds` - The number of rounds to perform.
///
/// # Returns
///
/// * A `Vec<u8>` containing the transformed block.
pub fn t_plus_l(block: &[u8], hash_params: &KupynaH) -> Vec<u8> {
    let mut state = block_to_matrix(block, hash_params);
    for nu in 0..hash_params.rounds {
        state = add_constant_plus(state, nu, hash_params);
        state = s_box_layer(state, hash_params);
        state = rotate_rows(state, hash_params);
        state = mix_columns(state, hash_params);
    }
    matrix_to_block(state)
}
