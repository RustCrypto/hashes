use crate::BLOCK_SIZE;
use core::convert::TryInto;

#[path = "consts.rs"]
mod consts;
use consts::*;

fn compress_block(state: &mut [u64; 8], b: &[u8; BLOCK_SIZE]) {
    let mut k = [0u64; 8];
    let mut block = [0u64; 8];
    let mut s = [0u64; 8];
    let mut l = [0u64; 8];

    for (o, chunk) in block.iter_mut().zip(b.chunks_exact(8)) {
        *o = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    k.copy_from_slice(state);

    for i in 0..8 {
        s[i] = block[i] ^ k[i];
    }

    #[allow(clippy::needless_range_loop)]
    for r in 0..R {
        for i in 0..8 {
            l[i] = C0[(k[(i) % 8] & 0xff) as usize]
                ^ C1[((k[(7 + i) % 8] >> 8) & 0xff) as usize]
                ^ C2[((k[(6 + i) % 8] >> 16) & 0xff) as usize]
                ^ C3[((k[(5 + i) % 8] >> 24) & 0xff) as usize]
                ^ C4[((k[(4 + i) % 8] >> 32) & 0xff) as usize]
                ^ C5[((k[(3 + i) % 8] >> 40) & 0xff) as usize]
                ^ C6[((k[(2 + i) % 8] >> 48) & 0xff) as usize]
                ^ C7[((k[(1 + i) % 8] >> 56) & 0xff) as usize]
                ^ if i == 0 { RC[r] } else { 0 };
        }
        k = l;
        for i in 0..8 {
            l[i] = C0[(s[(i) % 8] & 0xff) as usize]
                ^ C1[((s[(7 + i) % 8] >> 8) & 0xff) as usize]
                ^ C2[((s[(6 + i) % 8] >> 16) & 0xff) as usize]
                ^ C3[((s[(5 + i) % 8] >> 24) & 0xff) as usize]
                ^ C4[((s[(4 + i) % 8] >> 32) & 0xff) as usize]
                ^ C5[((s[(3 + i) % 8] >> 40) & 0xff) as usize]
                ^ C6[((s[(2 + i) % 8] >> 48) & 0xff) as usize]
                ^ C7[((s[(1 + i) % 8] >> 56) & 0xff) as usize]
                ^ k[i];
        }
        s = l;
    }

    for i in 0..8 {
        state[i] ^= s[i] ^ block[i];
    }
}

pub(crate) fn compress(state: &mut [u64; 8], blocks: &[[u8; BLOCK_SIZE]]) {
    for block in blocks {
        compress_block(state, block);
    }
}
