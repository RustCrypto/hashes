#![cfg_attr(feature = "cargo-clippy", allow(identity_op, needless_range_loop, double_parens))]

use generic_array::GenericArray;
use super::BlockSize;
use consts::*;
use byte_tools::read_u64v_be;

pub fn compress(hash: &mut [u64; 8], buffer: &GenericArray<u8, BlockSize>) {
    let mut k = [0u64; 8];
    let mut block = [0u64; 8];
    let mut state = [0u64; 8];
    let mut l = [0u64; 8];

    read_u64v_be(&mut block, buffer.as_slice());
    k.copy_from_slice(hash);

    for i in 0..8 {
        state[i] = block[i] ^ k[i];
    }

    for r in 1..(R + 1) {
        for i in 0..8 {
            l[i] =
                C0[((k[(0 + i) % 8] >> 56)       ) as usize] ^
                C1[((k[(7 + i) % 8] >> 48) & 0xff) as usize] ^
                C2[((k[(6 + i) % 8] >> 40) & 0xff) as usize] ^
                C3[((k[(5 + i) % 8] >> 32) & 0xff) as usize] ^
                C4[((k[(4 + i) % 8] >> 24) & 0xff) as usize] ^
                C5[((k[(3 + i) % 8] >> 16) & 0xff) as usize] ^
                C6[((k[(2 + i) % 8] >>  8) & 0xff) as usize] ^
                C7[((k[(1 + i) % 8]      ) & 0xff) as usize] ^
                if i == 0 { RC[r] } else { 0 };
        }
        k = l;
        for i in 0..8 {
            l[i] =
                C0[((state[(0 + i) % 8] >> 56)       ) as usize] ^
                C1[((state[(7 + i) % 8] >> 48) & 0xff) as usize] ^
                C2[((state[(6 + i) % 8] >> 40) & 0xff) as usize] ^
                C3[((state[(5 + i) % 8] >> 32) & 0xff) as usize] ^
                C4[((state[(4 + i) % 8] >> 24) & 0xff) as usize] ^
                C5[((state[(3 + i) % 8] >> 16) & 0xff) as usize] ^
                C6[((state[(2 + i) % 8] >>  8) & 0xff) as usize] ^
                C7[((state[(1 + i) % 8]      ) & 0xff) as usize] ^
                k[i];
        }
        state = l;
    }

    for i in 0..8 {
        hash[i] ^= state[i] ^ block[i];
    }
}
