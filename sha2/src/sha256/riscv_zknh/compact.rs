use super::{sha256sig0, sha256sig1, sha256sum0, sha256sum1};
use crate::consts::K32;

const ROUNDS: usize = K32.len();

#[target_feature(enable = "zknh")]
pub fn compress(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
    // Unforuntately, LLVM is unable to remove `memset` for
    // `fn message_schedule(block: &[u8; 64]) -> [u32; ROUNDS] { ... }`
    // See: https://rust.godbolt.org/z/s61sP3GKj
    // So to prevent unnecessary `memset` call for each block we reuse the buffer.
    let mut msg = [0u32; 64];

    for block in blocks {
        // Pre-computing the whole message schedule instead of doing it during each round
        // with a ring buffer results in a smaller binary with less branching
        // at the cost of using additional stack space
        message_schedule(block, &mut msg);
        rounds(state, &msg);
    }
}

#[inline]
#[target_feature(enable = "zknh")]
fn message_schedule(block: &[u8; 64], msg: &mut [u32; ROUNDS]) {
    let (block_chunks, tail) = block.as_chunks();
    assert!(tail.is_empty());

    let n = block_chunks.len();
    for i in 0..n {
        msg[i] = u32::from_be_bytes(block_chunks[i]);
    }

    for i in n..ROUNDS {
        msg[i] = msg[i - 16]
            .wrapping_add(sha256sig1(msg[i - 2]))
            .wrapping_add(msg[i - 7])
            .wrapping_add(sha256sig0(msg[i - 15]));
    }
}

#[inline]
#[target_feature(enable = "zknh")]
fn rounds(state: &mut [u32; 8], msg: &[u32; ROUNDS]) {
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    for i in 0..ROUNDS {
        let s1 = sha256sum1(e);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = s1
            .wrapping_add(ch)
            .wrapping_add(K32[i])
            .wrapping_add(msg[i])
            .wrapping_add(h);
        let s0 = sha256sum0(a);
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
