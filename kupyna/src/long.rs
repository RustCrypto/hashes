use crate::utils::{add_constant_plus, add_constant_xor, apply_s_box, convert_message_block, mix_columns, xor_words};

pub(crate) const COLS: usize = 16;
const ROUNDS: u64 = 14;

pub(crate) fn compress(prev_vector: &mut [u64; COLS], message_block: &[u8; 128]) {
    // Convert message block from u8 to u64 (column-major order as per paper)
    let message_u64 = convert_message_block::<128, COLS>(message_block);


    let m_xor_p = xor_words(*prev_vector, message_u64);

    let t_xor_mp = t_xor_l(m_xor_p);

    let t_plus_m = t_plus_l(message_u64);

    *prev_vector = xor_words(xor_words(t_xor_mp, t_plus_m), *prev_vector);
}

pub(crate) fn t_plus_l(state: [u64; COLS]) -> [u64; COLS] {
    let mut state = state;
    for nu in 0..ROUNDS {
        state = add_constant_plus(state, nu as usize);
        state = apply_s_box(state);
        state = rotate_rows(state);
        state = mix_columns(state);
    }
    state
}

fn rotate_rows(state: [u64; COLS]) -> [u64; COLS] {
    // Convert to matrix format (column-major as per paper)
    let mut matrix = [[0u8; COLS]; 8];
    for col in 0..COLS {
        let bytes = state[col].to_be_bytes();
        for row in 0..8 {
            matrix[row][col] = bytes[row];
        }
    }

    // Apply row rotation as per paper: row i rotated by i positions, row 7 by 11 positions for l=1024
    let mut result_matrix = [[0u8; COLS]; 8];

    for row in 0..8 {
        let shift = if row == 7 { 11 } else { row };
        for col in 0..COLS {
            result_matrix[row][(col + shift) % COLS] = matrix[row][col];
        }
    }

    // Convert back to u64 array
    let mut result = [0u64; COLS];
    for col in 0..COLS {
        let mut bytes = [0u8; 8];
        for row in 0..8 {
            bytes[row] = result_matrix[row][col];
        }
        result[col] = u64::from_be_bytes(bytes);
    }

    result
}

pub(crate) fn t_xor_l(state: [u64; COLS]) -> [u64; COLS] {
    let mut state = state;
    for nu in 0..ROUNDS {
        state = add_constant_xor(state, nu as usize);
        state = apply_s_box(state);
        state = rotate_rows(state);
        state = mix_columns(state);
    }
    state
}
