use super::{sha256sig0, sha256sig1, sha256sum0, sha256sum1};
use crate::consts::K32;

#[target_feature(enable = "zknh")]
pub(super) fn compress_block(state: &mut [u32; 8], mut block: [u32; 16]) {
    let mut s = *state;

    for r in 0..64 {
        round(&mut s, &block, r);
        if r < 48 {
            schedule(&mut block, r)
        }
    }

    for i in 0..8 {
        state[i] = state[i].wrapping_add(s[i]);
    }
}

#[target_feature(enable = "zknh")]
fn schedule(block: &mut [u32; 16], r: usize) {
    block[r % 16] = block[r % 16]
        .wrapping_add(sha256sig1(block[(r + 14) % 16]))
        .wrapping_add(block[(r + 9) % 16])
        .wrapping_add(sha256sig0(block[(r + 1) % 16]));
}

#[target_feature(enable = "zknh")]
fn round(state: &mut [u32; 8], block: &[u32; 16], r: usize) {
    let n = K32.len() - r;
    let [a, b, c, d, e, f, g, h] = core::array::from_fn(|i| (n + i) % 8);

    state[h] = state[h]
        .wrapping_add(sha256sum1(state[e]))
        .wrapping_add(ch(state[e], state[f], state[g]))
        .wrapping_add(K32[r])
        .wrapping_add(block[r % 16]);
    state[d] = state[d].wrapping_add(state[h]);
    state[h] = state[h]
        .wrapping_add(sha256sum0(state[a]))
        .wrapping_add(maj(state[a], state[b], state[c]))
}

#[inline(always)]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

#[inline(always)]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}
