mod t_xor_plus;

use crate::KupynaH;
use t_xor_plus::{t_plus_l, t_xor_l};

fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

fn silo(message_block: &[u8], prev_vector: &[u8], hash_params: &KupynaH) -> Vec<u8> {
    let m_xor_p = xor_bytes(message_block, prev_vector);

    let t_xor_mp = t_xor_l(&m_xor_p, hash_params);

    let t_plus_m = t_plus_l(message_block, hash_params);

    xor_bytes(&(xor_bytes(&t_xor_mp, &t_plus_m)), prev_vector)
}

pub(crate) fn plant(
    message_blocks: Vec<&[u8]>,
    init_vector: &[u8],
    hash_params: &KupynaH,
) -> Vec<u8> {
    let mut last_vector = init_vector.to_vec();

    for block in message_blocks {
        last_vector = silo(block, &last_vector, hash_params);
    }

    finalize(&last_vector, hash_params)
}

fn finalize(ult_processed_block: &[u8], hash_params: &KupynaH) -> Vec<u8> {
    let t_xor_ult_processed_block = t_xor_l(ult_processed_block, hash_params);
    xor_bytes(ult_processed_block, &t_xor_ult_processed_block)
}
