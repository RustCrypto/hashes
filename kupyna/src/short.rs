use crate::utils::{
    add_constant_plus, add_constant_xor, apply_s_box, convert_message_block, mix_columns, xor,
};

pub(crate) const COLS: usize = 8;
const ROUNDS: u64 = 10;

pub(crate) fn compress(prev_vector: &mut [u64; COLS], message_block: &[u8; 64]) {
    // Convert message block from u8 to u64 (column-major order as per paper)
    let message_u64 = convert_message_block::<64, COLS>(message_block);

    // println!("prev vector:=");
    // for v in prev_vector.iter() {
    //     println!("{:016X?}", v);
    // }
    //
    // println!("message block:=");
    // for v in message_u64.iter() {
    //     println!("{:016X?}", v);
    // }

    let m_xor_p = xor(*prev_vector, message_u64);

    // println!("m_xor_p:=");
    // for v in m_xor_p.iter() {
    //     println!("{:016X?}", v);
    // }

    let t_xor_mp = t_xor_l(m_xor_p);

    // println!("t_xor_mp:=");
    // for v in t_xor_mp.iter() {
    //     println!("{:016X?}", v);
    // }

    let t_plus_m = t_plus_l(message_u64);

    // println!("t_plus_m:=");
    // for v in t_plus_m.iter() {
    //     println!("{:016X?}", v);
    // }

    *prev_vector = xor(xor(t_xor_mp, t_plus_m), *prev_vector);

    // println!("prev vector after xor:=");
    // for v in prev_vector.iter() {
    //     println!("{:016X?}", v);
    // }
}

fn t_plus_l(state: [u64; COLS]) -> [u64; COLS] {
    let mut state = state;

    // println!("state before t_plus_l:=");
    // for v in state.iter() {
    //     println!("{:016X?}", v);
    // }

    for nu in 0..ROUNDS {
        add_constant_plus(&mut state, nu as usize);
        state = apply_s_box(state);
        state = rotate_rows(state);
        state = mix_columns(state);
    }

    // println!("state after t_plus_l:=");
    // for v in state.iter() {
    //     println!("{:016X?}", v);
    // }

    state
}

fn rotate_rows(state: [u64; COLS]) -> [u64; COLS] {
    //shift amounts for each row (0-6: row index, 7: special case)
    const SHIFTS: [usize; 8] = [0, 1, 2, 3, 4, 5, 6, 7];

    let mut result = [0u64; COLS];

    for col in 0..COLS {
        let mut rotated_bytes = [0u8; 8];

        // Apply rotation
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

    // println!("state before t_xor_l:=");
    // for v in state.iter() {
    //     println!("{:016X?}", v);
    // }

    for nu in 0..ROUNDS {
        add_constant_xor(&mut state, nu as usize);
        state = apply_s_box(state);
        state = rotate_rows(state);
        state = mix_columns(state);
    }

    // println!("state after t_xor_l:=");
    // for v in state.iter() {
    //     println!("{:016X?}", v);
    // }

    state
}
