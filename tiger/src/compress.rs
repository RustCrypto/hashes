use super::tables::{T1, T2, T3, T4};
use super::State;
use core::convert::TryInto;
use digest::generic_array::{typenum::U64, GenericArray};

#[inline(always)]
fn round(a: &mut u64, b: &mut u64, c: &mut u64, x: &u64, mul: u8) {
    *c ^= *x;
    let c2: [u8; 8] = c.to_le_bytes();
    let a2 = T1[usize::from(c2[0])]
        ^ T2[usize::from(c2[2])]
        ^ T3[usize::from(c2[4])]
        ^ T4[usize::from(c2[6])];
    let b2 = T4[usize::from(c2[1])]
        ^ T3[usize::from(c2[3])]
        ^ T2[usize::from(c2[5])]
        ^ T1[usize::from(c2[7])];
    *a = a.wrapping_sub(a2);
    *b = b.wrapping_add(b2).wrapping_mul(u64::from(mul));
}

#[inline(always)]
fn pass(a: &mut u64, b: &mut u64, c: &mut u64, x: &[u64; 8], mul: u8) {
    round(a, b, c, &x[0], mul);
    round(b, c, a, &x[1], mul);
    round(c, a, b, &x[2], mul);
    round(a, b, c, &x[3], mul);
    round(b, c, a, &x[4], mul);
    round(c, a, b, &x[5], mul);
    round(a, b, c, &x[6], mul);
    round(b, c, a, &x[7], mul);
}

#[inline(always)]
fn key_schedule(x: &mut [u64; 8]) {
    x[0] = x[0].wrapping_sub(x[7] ^ 0xA5A5_A5A5_A5A5_A5A5);
    x[1] ^= x[0];
    x[2] = x[2].wrapping_add(x[1]);
    x[3] = x[3].wrapping_sub(x[2] ^ ((!x[1]) << 19));
    x[4] ^= x[3];
    x[5] = x[5].wrapping_add(x[4]);
    x[6] = x[6].wrapping_sub(x[5] ^ ((!x[4]) >> 23));
    x[7] ^= x[6];
    x[0] = x[0].wrapping_add(x[7]);
    x[1] = x[1].wrapping_sub(x[0] ^ ((!x[7]) << 19));
    x[2] ^= x[1];
    x[3] = x[3].wrapping_add(x[2]);
    x[4] = x[4].wrapping_sub(x[3] ^ ((!x[2]) >> 23));
    x[5] ^= x[4];
    x[6] = x[6].wrapping_add(x[5]);
    x[7] = x[7].wrapping_sub(x[6] ^ 0x0123_4567_89AB_CDEF);
}

pub(crate) fn compress(state: &mut State, blocks: &[GenericArray<u8, U64>]) {
    let mut block: [u64; 8] = Default::default();
    for raw_block in blocks {
        for (o, chunk) in block.iter_mut().zip(raw_block.chunks_exact(8)) {
            *o = u64::from_le_bytes(chunk.try_into().unwrap());
        }
        let [mut a, mut b, mut c] = *state;

        pass(&mut a, &mut b, &mut c, &block, 5);
        key_schedule(&mut block);
        pass(&mut c, &mut a, &mut b, &block, 7);
        key_schedule(&mut block);
        pass(&mut b, &mut c, &mut a, &block, 9);

        state[0] ^= a;
        state[1] = b.wrapping_sub(state[1]);
        state[2] = c.wrapping_add(state[2]);
    }
}
