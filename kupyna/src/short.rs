use crate::utils::{add_constant_plus, add_constant_xor, apply_s_box, mix_columns, xor_words};

pub(crate) const COLS: usize = 8;
const ROUNDS: u64 = 10;

pub(crate) fn compress(prev_vector: &mut [u64; COLS], message_block: &[u8; 64]) {
    // Convert message block from u8 to u64 (column-major order as per paper)
    let mut message_u64 = [0u64; COLS];
    for (chunk, v) in message_block.chunks_exact(8).zip(message_u64.iter_mut()) {
        *v = u64::from_be_bytes(chunk.try_into().unwrap());
    }

    // println!("prev vector:=");
    // for v in prev_vector.iter() {
    //     println!("{:016X?}", v);
    // }
    //
    // println!("message block:=");
    // for v in message_u64.iter() {
    //     println!("{:016X?}", v);
    // }

    let m_xor_p = xor_words(*prev_vector, message_u64);

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

    *prev_vector = xor_words(xor_words(t_xor_mp, t_plus_m), *prev_vector);

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
        state = add_constant_plus(state, nu as usize);
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
    // Convert to matrix format (column-major as per paper)
    let mut matrix = [[0u8; COLS]; 8];
    for col in 0..COLS {
        let bytes = state[col].to_be_bytes();
        for row in 0..8 {
            matrix[row][col] = bytes[row];
        }
    }

    // Apply row rotation as per paper: row i rotated by i positions, row 7 by 7 positions
    let mut result_matrix = [[0u8; COLS]; 8];

    for row in 0..8 {
        let shift = if row == 7 { 7 } else { row };
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

    // println!("state before t_xor_l:=");
    // for v in state.iter() {
    //     println!("{:016X?}", v);
    // }

    for nu in 0..ROUNDS {
        state = add_constant_xor(state, nu as usize);
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
