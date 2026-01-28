use crate::table::TABLE;
use crate::utils::{read_u64s_be, xor};

pub(crate) const COLS: usize = 8;
const ROUNDS: usize = 10;

// ShiftRows offsets for short variant: row i shifts by i positions
const SHIFTS: [usize; 8] = [0, 1, 2, 3, 4, 5, 6, 7];

pub(crate) fn compress(prev_vector: &mut [u64; COLS], message_block: &[u8; 64]) {
    let message_u64 = read_u64s_be::<64, COLS>(message_block);
    let m_xor_p = xor(*prev_vector, message_u64);
    let t_xor_mp = t_xor_l(m_xor_p);
    let t_plus_m = t_plus_l(message_u64);
    *prev_vector = xor(xor(t_xor_mp, t_plus_m), *prev_vector);
}

/// Compute one output column using T-table lookups
#[inline(always)]
fn column(x: &[u64; COLS], col: usize) -> u64 {
    let mut t = 0u64;
    for row in 0..8 {
        let src_col = (col + COLS - SHIFTS[row]) % COLS;
        let byte = ((x[src_col] >> (8 * (7 - row))) & 0xFF) as usize;
        t ^= TABLE[row][byte];
    }
    t
}

fn t_plus_l(mut state: [u64; COLS]) -> [u64; COLS] {
    for round in 0..ROUNDS {
        // AddConstantPlus
        for i in 0..COLS {
            state[i] = state[i]
                .swap_bytes()
                .wrapping_add(
                    0x00F0F0F0F0F0F0F3u64 ^ (((((COLS - i - 1) * 0x10) ^ round) as u64) << 56),
                )
                .swap_bytes();
        }
        // Fused SubBytes + ShiftRows + MixColumns via T-tables
        let prev = state;
        for col in 0..COLS {
            state[col] = column(&prev, col);
        }
    }
    state
}

pub(crate) fn t_xor_l(mut state: [u64; COLS]) -> [u64; COLS] {
    for round in 0..ROUNDS {
        // AddConstantXor
        for i in 0..COLS {
            let constant = ((i * 0x10) ^ round) as u64;
            state[i] ^= constant << 56;
        }
        // Fused SubBytes + ShiftRows + MixColumns via T-tables
        let prev = state;
        for col in 0..COLS {
            state[col] = column(&prev, col);
        }
    }
    state
}
