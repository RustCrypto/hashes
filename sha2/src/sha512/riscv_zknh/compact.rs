use super::{sha512sig0, sha512sig1, sha512sum0, sha512sum1};
use crate::consts::K64;

#[inline]
#[target_feature(enable = "zknh")]
pub(super) fn compress_block(state: &mut [u64; 8], block: &[u8; 128]) {
    let mut block: [u64; 16] = {
        let (chunks, tail) = block.as_chunks();
        assert!(tail.is_empty());
        core::array::from_fn(|i| u64::from_be_bytes(chunks[i]))
    };

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    for i in 0..80 {
        let w = if i < 16 {
            block[i]
        } else {
            let s0 = sha512sig0(block[(i - 15) % 16]);
            let s1 = sha512sig1(block[(i - 2) % 16]);
            let new_w = block[i % 16]
                .wrapping_add(s0)
                .wrapping_add(block[(i - 7) % 16])
                .wrapping_add(s1);
            block[i % 16] = new_w;
            new_w
        };

        let s1 = sha512sum1(e);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = s1
            .wrapping_add(ch)
            .wrapping_add(K64[i])
            .wrapping_add(w)
            .wrapping_add(h);
        let s0 = sha512sum0(a);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/*
#[inline]
#[target_feature(enable = "zknh")]
pub(super) fn compress_block(state: &mut [u64; 8], mut block: [u64; 16]) {
    let mut s = *state;

    for r in 0..80 {
        round(&mut s, &block, r);
        if r < 64 {
            schedule(&mut block, r)
        }
    }

    for i in 0..8 {
        state[i] = state[i].wrapping_add(s[i]);
    }
}

#[inline]
#[target_feature(enable = "zknh")]
fn schedule(block: &mut [u64; 16], r: usize) {
    block[r % 16] = block[r % 16]
        .wrapping_add(sha512sig1(block[(r + 14) % 16]))
        .wrapping_add(block[(r + 9) % 16])
        .wrapping_add(sha512sig0(block[(r + 1) % 16]));
}

#[inline]
#[target_feature(enable = "zknh")]
fn round(state: &mut [u64; 8], block: &[u64; 16], r: usize) {
    let n = K64.len() - r;
    let [a, b, c, d, e, f, g, h] = core::array::from_fn(|i| (n + i) % 8);

    state[h] = state[h]
        .wrapping_add(sha512sum1(state[e]))
        .wrapping_add(ch(state[e], state[f], state[g]))
        .wrapping_add(K64[r])
        .wrapping_add(block[r % 16]);
    state[d] = state[d].wrapping_add(state[h]);
    state[h] = state[h]
        .wrapping_add(sha512sum0(state[a]))
        .wrapping_add(maj(state[a], state[b], state[c]))
}

#[inline(always)]
fn ch(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (!x & z)
}

#[inline(always)]
fn maj(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (x & z) ^ (y & z)
}
*/
