#![allow(clippy::many_single_char_names)]
use crate::consts::K64;

/// Not an intrinsic, but works like an unaligned load.
fn sha512load(v0: [u64; 2], v1: [u64; 2]) -> [u64; 2] {
    [v1[1], v0[0]]
}

/// Performs 2 rounds of the SHA-512 message schedule update.
pub fn sha512_schedule_x2(v0: [u64; 2], v1: [u64; 2], v4to5: [u64; 2], v7: [u64; 2]) -> [u64; 2] {
    // sigma 0
    fn sigma0(x: u64) -> u64 {
        ((x << 63) | (x >> 1)) ^ ((x << 56) | (x >> 8)) ^ (x >> 7)
    }

    // sigma 1
    fn sigma1(x: u64) -> u64 {
        ((x << 45) | (x >> 19)) ^ ((x << 3) | (x >> 61)) ^ (x >> 6)
    }

    let [w1, w0] = v0;
    let [_, w2] = v1;
    let [w10, w9] = v4to5;
    let [w15, w14] = v7;

    let w16 = sigma1(w14)
        .wrapping_add(w9)
        .wrapping_add(sigma0(w1))
        .wrapping_add(w0);
    let w17 = sigma1(w15)
        .wrapping_add(w10)
        .wrapping_add(sigma0(w2))
        .wrapping_add(w1);

    [w17, w16]
}

/// Performs one round of the SHA-512 message block digest.
pub fn sha512_digest_round(
    ae: [u64; 2],
    bf: [u64; 2],
    cg: [u64; 2],
    dh: [u64; 2],
    wk0: u64,
) -> [u64; 2] {
    macro_rules! big_sigma0 {
        ($a:expr) => {
            ($a.rotate_right(28) ^ $a.rotate_right(34) ^ $a.rotate_right(39))
        };
    }
    macro_rules! big_sigma1 {
        ($a:expr) => {
            ($a.rotate_right(14) ^ $a.rotate_right(18) ^ $a.rotate_right(41))
        };
    }
    macro_rules! bool3ary_202 {
        ($a:expr, $b:expr, $c:expr) => {
            $c ^ ($a & ($b ^ $c))
        };
    } // Choose, MD5F, SHA1C
    macro_rules! bool3ary_232 {
        ($a:expr, $b:expr, $c:expr) => {
            ($a & $b) ^ ($a & $c) ^ ($b & $c)
        };
    } // Majority, SHA1M

    let [a0, e0] = ae;
    let [b0, f0] = bf;
    let [c0, g0] = cg;
    let [d0, h0] = dh;

    // a round
    let x0 = big_sigma1!(e0)
        .wrapping_add(bool3ary_202!(e0, f0, g0))
        .wrapping_add(wk0)
        .wrapping_add(h0);
    let y0 = big_sigma0!(a0).wrapping_add(bool3ary_232!(a0, b0, c0));
    let (a1, _, _, _, e1, _, _, _) = (
        x0.wrapping_add(y0),
        a0,
        b0,
        c0,
        x0.wrapping_add(d0),
        e0,
        f0,
        g0,
    );

    [a1, e1]
}

#[inline(always)]
fn add_rk(mut w: [u64; 2], i: usize) -> [u64; 2] {
    fn rk(i: usize, j: usize) -> u64 {
        // `read_volatile` forces compiler to read round constants from the static
        // instead of inlining them, which improves codegen and performance
        unsafe {
            let p = K64.as_ptr().add(2 * i + j);
            core::ptr::read_volatile(p)
        }
    }
    w[1] = w[1].wrapping_add(rk(i, 0));
    w[0] = w[0].wrapping_add(rk(i, 1));
    w
}

/// Process a block with the SHA-512 algorithm.
pub fn sha512_digest_block_u64(state: &mut [u64; 8], block: &[u64; 16]) {
    macro_rules! schedule {
        ($v0:expr, $v1:expr, $v4:expr, $v5:expr, $v7:expr) => {
            sha512_schedule_x2($v0, $v1, sha512load($v4, $v5), $v7)
        };
    }

    macro_rules! rounds4 {
        ($ae:ident, $bf:ident, $cg:ident, $dh:ident, $wk0:expr, $wk1:expr) => {{
            let [u, t] = $wk0;
            let [w, v] = $wk1;

            $dh = sha512_digest_round($ae, $bf, $cg, $dh, t);
            $cg = sha512_digest_round($dh, $ae, $bf, $cg, u);
            $bf = sha512_digest_round($cg, $dh, $ae, $bf, v);
            $ae = sha512_digest_round($bf, $cg, $dh, $ae, w);
        }};
    }

    let mut ae = [state[0], state[4]];
    let mut bf = [state[1], state[5]];
    let mut cg = [state[2], state[6]];
    let mut dh = [state[3], state[7]];

    // Rounds 0..20
    let (mut w1, mut w0) = ([block[3], block[2]], [block[1], block[0]]);
    rounds4!(ae, bf, cg, dh, add_rk(w0, 0), add_rk(w1, 1));
    let (mut w3, mut w2) = ([block[7], block[6]], [block[5], block[4]]);
    rounds4!(ae, bf, cg, dh, add_rk(w2, 2), add_rk(w3, 3));
    let (mut w5, mut w4) = ([block[11], block[10]], [block[9], block[8]]);
    rounds4!(ae, bf, cg, dh, add_rk(w4, 4), add_rk(w5, 5));
    let (mut w7, mut w6) = ([block[15], block[14]], [block[13], block[12]]);
    rounds4!(ae, bf, cg, dh, add_rk(w6, 6), add_rk(w7, 7));
    let mut w8 = schedule!(w0, w1, w4, w5, w7);
    let mut w9 = schedule!(w1, w2, w5, w6, w8);
    rounds4!(ae, bf, cg, dh, add_rk(w8, 8), add_rk(w9, 9));

    // Rounds 20..40
    w0 = schedule!(w2, w3, w6, w7, w9);
    w1 = schedule!(w3, w4, w7, w8, w0);
    rounds4!(ae, bf, cg, dh, add_rk(w0, 10), add_rk(w1, 11));
    w2 = schedule!(w4, w5, w8, w9, w1);
    w3 = schedule!(w5, w6, w9, w0, w2);
    rounds4!(ae, bf, cg, dh, add_rk(w2, 12), add_rk(w3, 13));
    w4 = schedule!(w6, w7, w0, w1, w3);
    w5 = schedule!(w7, w8, w1, w2, w4);
    rounds4!(ae, bf, cg, dh, add_rk(w4, 14), add_rk(w5, 15));
    w6 = schedule!(w8, w9, w2, w3, w5);
    w7 = schedule!(w9, w0, w3, w4, w6);
    rounds4!(ae, bf, cg, dh, add_rk(w6, 16), add_rk(w7, 17));
    w8 = schedule!(w0, w1, w4, w5, w7);
    w9 = schedule!(w1, w2, w5, w6, w8);
    rounds4!(ae, bf, cg, dh, add_rk(w8, 18), add_rk(w9, 19));

    // Rounds 40..60
    w0 = schedule!(w2, w3, w6, w7, w9);
    w1 = schedule!(w3, w4, w7, w8, w0);
    rounds4!(ae, bf, cg, dh, add_rk(w0, 20), add_rk(w1, 21));
    w2 = schedule!(w4, w5, w8, w9, w1);
    w3 = schedule!(w5, w6, w9, w0, w2);
    rounds4!(ae, bf, cg, dh, add_rk(w2, 22), add_rk(w3, 23));
    w4 = schedule!(w6, w7, w0, w1, w3);
    w5 = schedule!(w7, w8, w1, w2, w4);
    rounds4!(ae, bf, cg, dh, add_rk(w4, 24), add_rk(w5, 25));
    w6 = schedule!(w8, w9, w2, w3, w5);
    w7 = schedule!(w9, w0, w3, w4, w6);
    rounds4!(ae, bf, cg, dh, add_rk(w6, 26), add_rk(w7, 27));
    w8 = schedule!(w0, w1, w4, w5, w7);
    w9 = schedule!(w1, w2, w5, w6, w8);
    rounds4!(ae, bf, cg, dh, add_rk(w8, 28), add_rk(w9, 29));

    // Rounds 60..80
    w0 = schedule!(w2, w3, w6, w7, w9);
    w1 = schedule!(w3, w4, w7, w8, w0);
    rounds4!(ae, bf, cg, dh, add_rk(w0, 30), add_rk(w1, 31));
    w2 = schedule!(w4, w5, w8, w9, w1);
    w3 = schedule!(w5, w6, w9, w0, w2);
    rounds4!(ae, bf, cg, dh, add_rk(w2, 32), add_rk(w3, 33));
    w4 = schedule!(w6, w7, w0, w1, w3);
    w5 = schedule!(w7, w8, w1, w2, w4);
    rounds4!(ae, bf, cg, dh, add_rk(w4, 34), add_rk(w5, 35));
    w6 = schedule!(w8, w9, w2, w3, w5);
    w7 = schedule!(w9, w0, w3, w4, w6);
    rounds4!(ae, bf, cg, dh, add_rk(w6, 36), add_rk(w7, 37));
    w8 = schedule!(w0, w1, w4, w5, w7);
    w9 = schedule!(w1, w2, w5, w6, w8);
    rounds4!(ae, bf, cg, dh, add_rk(w8, 38), add_rk(w9, 39));

    let [a, e] = ae;
    let [b, f] = bf;
    let [c, g] = cg;
    let [d, h] = dh;

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

pub fn compress(state: &mut [u64; 8], blocks: &[[u8; 128]]) {
    for block in blocks {
        let mut block_u32 = [0u64; 16];
        for (o, chunk) in block_u32.iter_mut().zip(block.chunks_exact(8)) {
            *o = u64::from_be_bytes(chunk.try_into().unwrap());
        }
        sha512_digest_block_u64(state, &block_u32);
    }
}
