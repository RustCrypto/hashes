use crate::utils::{
    add_constant_plus, add_constant_xor, apply_s_box, convert_message_block, mix_columns, xor,
};

pub(crate) const COLS: usize = 16;
const ROUNDS: u64 = 14;

pub(crate) fn compress(prev_vector: &mut [u64; COLS], message_block: &[u8; 128]) {
    // Convert message block from u8 to u64 (column-major order as per paper)
    let message_u64 = convert_message_block::<128, COLS>(message_block);

    let m_xor_p = xor(*prev_vector, message_u64);

    let t_xor_mp = t_xor_l(m_xor_p);

    let t_plus_m = t_plus_l(message_u64);

    *prev_vector = xor(xor(t_xor_mp, t_plus_m), *prev_vector);
}

pub(crate) fn t_plus_l(state: [u64; COLS]) -> [u64; COLS] {
    let mut state = state;
    for nu in 0..ROUNDS {
        add_constant_plus(&mut state, nu as usize);
        apply_s_box(&mut state);
        state = rotate_rows(state);
        mix_columns(&mut state);
    }
    state
}

fn rotate_rows(state: [u64; COLS]) -> [u64; COLS] {
    //shift amounts for each row (0-6: row index, 7: special case = 11)
    const SHIFTS: [usize; 8] = [0, 1, 2, 3, 4, 5, 6, 11];

    let mut result = [0u64; COLS];

    for col in 0..COLS {
        let mut rotated_bytes = [0u8; 8];

        // Apply rotation for each row
        for row in 0..8 {
            let shift = SHIFTS[row];
            let src_col = (col + COLS - shift) % COLS;  // Reverse the rotation direction
            let src_bytes = state[src_col].to_be_bytes();
            rotated_bytes[row] = src_bytes[row];
        }

        result[col] = u64::from_be_bytes(rotated_bytes);
    }

    result
}

pub(crate) fn t_xor_l(state: [u64; COLS]) -> [u64; COLS] {
    let mut state = state;
    for nu in 0..ROUNDS {
        add_constant_xor(&mut state, nu as usize);
        apply_s_box(&mut state);
        state = rotate_rows(state);
        mix_columns(&mut state);
    }
    state
}
