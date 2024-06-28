mod t_xor_plus;

use t_xor_plus::{t_xor_l, t_plus_l};

const ROUNDS: usize = 14;

fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

fn silo(message_block: &[u8], prev_vector: &[u8]) -> Vec<u8> {

    let m_xor_p = xor_bytes(message_block, prev_vector);

    let t_xor_mp = t_xor_l(&m_xor_p, ROUNDS);

    let t_plus_m = t_plus_l(&message_block, ROUNDS);

    let return_vector = xor_bytes(&(xor_bytes(&t_xor_mp, &t_plus_m)), prev_vector);

    return_vector

}

pub(crate) fn plant(message_blocks: Vec<&[u8]>, init_vector: &[u8]) -> Vec<u8> {

    let mut last_vector = init_vector.to_vec();

    for block in message_blocks {
        last_vector = silo(block, &last_vector);
    }

    let last_vector = finalize(&last_vector);

    last_vector
}

fn finalize(ult_processed_block: &[u8]) -> Vec<u8> {
    let t_xor_ult_processed_block = t_xor_l(ult_processed_block, ROUNDS);
    let final_state = xor_bytes(ult_processed_block, &t_xor_ult_processed_block);
    final_state
}

