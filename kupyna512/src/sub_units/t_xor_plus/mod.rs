#[cfg(test)]
mod tests;

mod tables;

const ROWS: usize = 16;
const COLS: usize = 8; // For 512-bit state, adjust if needed

const BITS_IN_BYTE: u8 = 8;
const REDUCTION_POLYNOMIAL: u16 = 0x011d;

type Matrix = [[u8; COLS]; ROWS];

use tables::{MDS_MATRIX, SBOXES};


pub(crate) fn block_to_matrix(block: &[u8]) -> Matrix {
    let mut matrix = [[0u8; COLS]; ROWS];
    for i in 0..ROWS {
        for j in 0..COLS {
            matrix[i][j] = block[i * COLS + j];
        }
    }
    matrix
}

fn matrix_to_block(matrix: Matrix) -> Vec<u8> {
    let mut block = vec![0u8; ROWS * COLS];
    for i in 0..ROWS {
        for j in 0..COLS {
            block[i * COLS + j] = matrix[i][j];
        }
    }
    block
}

pub(crate) fn add_constant_xor(mut state: Matrix, round: usize) -> Matrix {
    for j in 0..ROWS {
        let constant = ((j * 0x10) ^ round) as u8;
        state[j][0] ^= constant;
    }
    state
}

pub(crate) fn add_constant_plus(mut state: Matrix, round: usize) -> Matrix {
    let state_ptr = state.as_mut_ptr() as *mut u64;

    for j in 0..ROWS {
        // dbg!("{}",j);
        unsafe {
            *state_ptr.add(j) = state_ptr.add(j).read().wrapping_add(
                0x00F0F0F0F0F0F0F3u64 ^ (((((ROWS - j - 1) * 0x10) ^ round) as u64) << 56),
            );
        }
    }

    state
}

pub(crate) fn s_box_layer(mut state: Matrix) -> Matrix {
    for i in 0..COLS {
        for j in 0..ROWS {
            state[j][i] = SBOXES[i % 4][state[j][i] as usize];
        }
    }
    state
}

pub(crate) fn rotate_rows(mut state: Matrix) -> Matrix {
    let mut temp = [0u8; ROWS];
    let mut shift: i32 = -1;
    for i in 0..COLS {
        if (i == COLS - 1) && true {
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

pub(crate) fn mix_columns(state: Matrix) -> Matrix {
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
pub fn t_xor_l(block: &[u8], rounds: usize) -> Vec<u8> {
    let mut state = block_to_matrix(block);
    for nu in 0..rounds {
        state = add_constant_xor(state, nu);
        state = s_box_layer(state);
        state = rotate_rows(state);
        state = mix_columns(state);
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
pub fn t_plus_l(block: &[u8], rounds: usize) -> Vec<u8> {
    let mut state = block_to_matrix(block);
    for nu in 0..rounds {
        state = add_constant_plus(state, nu);
        state = s_box_layer(state);
        state = rotate_rows(state);
        state = mix_columns(state);
    }
    matrix_to_block(state)
}