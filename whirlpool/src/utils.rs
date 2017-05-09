use super::{GenericArray, BlockSize};
use consts::*;
use core::mem::uninitialized;

pub fn compress(hash: &mut [u64; 8], buffer: &GenericArray<u8, BlockSize>) {
    let mut k: [u64; 8] = unsafe { uninitialized() };
    let mut block: [u64; 8] = unsafe { uninitialized() };
    let mut state: [u64; 8] = unsafe { uninitialized() };
    let mut l: [u64; 8] = unsafe { uninitialized() };

    for i in 0..8 {
        block[i] =
            ((buffer[i * 8 + 0] as u64) << 56) ^
            ((buffer[i * 8 + 1] as u64) << 48) ^
            ((buffer[i * 8 + 2] as u64) << 40) ^
            ((buffer[i * 8 + 3] as u64) << 32) ^
            ((buffer[i * 8 + 4] as u64) << 24) ^
            ((buffer[i * 8 + 5] as u64) << 16) ^
            ((buffer[i * 8 + 6] as u64) <<  8) ^
            ((buffer[i * 8 + 7] as u64)      );
        k[i] = hash[i];
        state[i] = block[i] ^ k[i];
    }

    for r in 1..(R + 1) /* [1, R] */ {
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