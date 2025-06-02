use crate::utils::{
    add_constant_plus, add_constant_xor, apply_s_box, mix_columns, read_u64s_be, xor,
};
use core::array;

pub(crate) const COLS: usize = 8;
const ROUNDS: u64 = 10;

pub(crate) fn compress(prev_vector: &mut [u64; COLS], message_block: &[u8; 64]) {
    // Convert message block from u8 to u64 (column-major order as per paper)
    let message_u64 = read_u64s_be::<64, COLS>(message_block);
    let m_xor_p = xor(*prev_vector, message_u64);
    let t_xor_mp = t_xor_l(m_xor_p);
    let t_plus_m = t_plus_l(message_u64);
    *prev_vector = xor(xor(t_xor_mp, t_plus_m), *prev_vector);
}

fn t_plus_l(state: [u64; COLS]) -> [u64; COLS] {
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
    //shift amounts for each row (0-6: row index, 7: special case)
    const SHIFTS: [usize; 8] = [0, 1, 2, 3, 4, 5, 6, 7];

    array::from_fn(|col| {
        let rotated_bytes = array::from_fn(|row| {
            let shift = SHIFTS[row];
            let src_col = (col + COLS - shift) % COLS;
            let src_bytes = state[src_col].to_be_bytes();
            src_bytes[row]
        });
        u64::from_be_bytes(rotated_bytes)
    })
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
