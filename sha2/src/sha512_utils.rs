#![allow(clippy::many_single_char_names)]
use crate::consts::{BLOCK_LEN, K64X2};
use core::convert::TryInto;

#[inline(always)]
fn add(a: [u64; 2], b: [u64; 2]) -> [u64; 2] {
    [a[0].wrapping_add(b[0]), a[1].wrapping_add(b[1])]
}

/// Not an intrinsic, but works like an unaligned load.
#[inline]
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

/// Process a block with the SHA-512 algorithm.
pub fn sha512_digest_block_u64(state: &mut [u64; 8], block: &[u64; 16]) {
    let k = &K64X2;

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
    rounds4!(ae, bf, cg, dh, add(k[0], w0), add(k[1], w1));
    let (mut w3, mut w2) = ([block[7], block[6]], [block[5], block[4]]);
    rounds4!(ae, bf, cg, dh, add(k[2], w2), add(k[3], w3));
    let (mut w5, mut w4) = ([block[11], block[10]], [block[9], block[8]]);
    rounds4!(ae, bf, cg, dh, add(k[4], w4), add(k[5], w5));
    let (mut w7, mut w6) = ([block[15], block[14]], [block[13], block[12]]);
    rounds4!(ae, bf, cg, dh, add(k[6], w6), add(k[7], w7));
    let mut w8 = schedule!(w0, w1, w4, w5, w7);
    let mut w9 = schedule!(w1, w2, w5, w6, w8);
    rounds4!(ae, bf, cg, dh, add(k[8], w8), add(k[9], w9));

    // Rounds 20..40
    w0 = schedule!(w2, w3, w6, w7, w9);
    w1 = schedule!(w3, w4, w7, w8, w0);
    rounds4!(ae, bf, cg, dh, add(k[10], w0), add(k[11], w1));
    w2 = schedule!(w4, w5, w8, w9, w1);
    w3 = schedule!(w5, w6, w9, w0, w2);
    rounds4!(ae, bf, cg, dh, add(k[12], w2), add(k[13], w3));
    w4 = schedule!(w6, w7, w0, w1, w3);
    w5 = schedule!(w7, w8, w1, w2, w4);
    rounds4!(ae, bf, cg, dh, add(k[14], w4), add(k[15], w5));
    w6 = schedule!(w8, w9, w2, w3, w5);
    w7 = schedule!(w9, w0, w3, w4, w6);
    rounds4!(ae, bf, cg, dh, add(k[16], w6), add(k[17], w7));
    w8 = schedule!(w0, w1, w4, w5, w7);
    w9 = schedule!(w1, w2, w5, w6, w8);
    rounds4!(ae, bf, cg, dh, add(k[18], w8), add(k[19], w9));

    // Rounds 40..60
    w0 = schedule!(w2, w3, w6, w7, w9);
    w1 = schedule!(w3, w4, w7, w8, w0);
    rounds4!(ae, bf, cg, dh, add(k[20], w0), add(k[21], w1));
    w2 = schedule!(w4, w5, w8, w9, w1);
    w3 = schedule!(w5, w6, w9, w0, w2);
    rounds4!(ae, bf, cg, dh, add(k[22], w2), add(k[23], w3));
    w4 = schedule!(w6, w7, w0, w1, w3);
    w5 = schedule!(w7, w8, w1, w2, w4);
    rounds4!(ae, bf, cg, dh, add(k[24], w4), add(k[25], w5));
    w6 = schedule!(w8, w9, w2, w3, w5);
    w7 = schedule!(w9, w0, w3, w4, w6);
    rounds4!(ae, bf, cg, dh, add(k[26], w6), add(k[27], w7));
    w8 = schedule!(w0, w1, w4, w5, w7);
    w9 = schedule!(w1, w2, w5, w6, w8);
    rounds4!(ae, bf, cg, dh, add(k[28], w8), add(k[29], w9));

    // Rounds 60..80
    w0 = schedule!(w2, w3, w6, w7, w9);
    w1 = schedule!(w3, w4, w7, w8, w0);
    rounds4!(ae, bf, cg, dh, add(k[30], w0), add(k[31], w1));
    w2 = schedule!(w4, w5, w8, w9, w1);
    w3 = schedule!(w5, w6, w9, w0, w2);
    rounds4!(ae, bf, cg, dh, add(k[32], w2), add(k[33], w3));
    w4 = schedule!(w6, w7, w0, w1, w3);
    w5 = schedule!(w7, w8, w1, w2, w4);
    rounds4!(ae, bf, cg, dh, add(k[34], w4), add(k[35], w5));
    w6 = schedule!(w8, w9, w2, w3, w5);
    w7 = schedule!(w9, w0, w3, w4, w6);
    rounds4!(ae, bf, cg, dh, add(k[36], w6), add(k[37], w7));
    w8 = schedule!(w0, w1, w4, w5, w7);
    w9 = schedule!(w1, w2, w5, w6, w8);
    rounds4!(ae, bf, cg, dh, add(k[38], w8), add(k[39], w9));

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

/// Process a block with the SHA-512 algorithm. (See more...)
///
/// Internally, this uses functions that resemble the new Intel SHA
/// instruction set extensions, but since no architecture seems to
/// have any designs, these may not be the final designs if and/or when
/// there are instruction set extensions with SHA-512. So to summarize:
/// SHA-1 and SHA-256 are being implemented in hardware soon (at the time
/// of this writing), but it doesn't look like SHA-512 will be hardware
/// accelerated any time soon.
///
/// # Implementation
///
/// These functions fall into two categories: message schedule calculation, and
/// the message block 64-round digest calculation. The schedule-related
/// functions allow 4 rounds to be calculated as:
///
/// ```ignore
/// use std::simd::[u64; 2];
/// use self::crypto::sha2::{
///     sha512msg,
///     sha512load
/// };
///
/// fn schedule4_data(work: &mut [[u64; 2]], w: &[u64]) {
///
///     // this is to illustrate the data order
///     work[0] = [w[1], w[0]);
///     work[1] = [w[3], w[2]);
///     work[2] = [w[5], w[4]);
///     work[3] = [w[7], w[6]);
///     work[4] = [w[9], w[8]);
///     work[5] = [w[11], w[10]);
///     work[6] = [w[13], w[12]);
///     work[7] = [w[15], w[14]);
/// }
///
/// fn schedule4_work(work: &mut [[u64; 2]], t: usize) {
///
///     // this is the core expression
///     work[t] = sha512msg(work[t - 8],
///                         work[t - 7],
///                         sha512load(work[t - 4], work[t - 3]),
///                         work[t - 1]);
/// }
/// ```
///
/// instead of 4 rounds of:
///
/// ```ignore
/// fn schedule_work(w: &mut [u64], t: usize) {
///     w[t] = sigma1!(w[t - 2]) + w[t - 7] + sigma0!(w[t - 15]) + w[t - 16];
/// }
/// ```
///
/// and the digest-related functions allow 4 rounds to be calculated as:
///
/// ```ignore
/// use std::simd::[u64; 2];
/// use self::crypto::sha2::{K64X2, sha512rnd};
///
/// fn rounds4(state: &mut [u64; 8], work: &mut [[u64; 2]], t: usize) {
///     let [a, b, c, d, e, f, g, h]: [u64; 8] = *state;
///
///     // this is to illustrate the data order
///     let mut ae = [a, e);
///     let mut bf = [b, f);
///     let mut cg = [c, g);
///     let mut dh = [d, h);
///     let [w1, w0) = K64X2[2*t]     + work[2*t];
///     let [w3, w2) = K64X2[2*t + 1] + work[2*t + 1];
///
///     // this is the core expression
///     dh = sha512rnd(ae, bf, cg, dh, w0);
///     cg = sha512rnd(dh, ae, bf, cg, w1);
///     bf = sha512rnd(cg, dh, ae, bf, w2);
///     ae = sha512rnd(bf, cg, dh, ae, w3);
///
///     *state = [ae[0], bf[0], cg[0], dh[0],
///               ae[1], bf[1], cg[1], dh[1]];
/// }
/// ```
///
/// instead of 4 rounds of:
///
/// ```ignore
/// fn round(state: &mut [u64; 8], w: &mut [u64], t: usize) {
///     let [a, b, c, mut d, e, f, g, mut h]: [u64; 8] = *state;
///
///     h += big_sigma1!(e) +   choose!(e, f, g) + K64[t] + w[t]; d += h;
///     h += big_sigma0!(a) + majority!(a, b, c);
///
///     *state = [h, a, b, c, d, e, f, g];
/// }
/// ```
///
pub fn compress512(state: &mut [u64; 8], block: &[u8; 128]) {
    let mut block_u64 = [0u64; BLOCK_LEN];
    for (o, chunk) in block_u64.iter_mut().zip(block.chunks_exact(8)) {
        *o = u64::from_be_bytes(chunk.try_into().unwrap());
    }
    sha512_digest_block_u64(state, &block_u64);
}
