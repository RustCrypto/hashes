use digest::typenum::U20;

pub(super) const DIGEST_BUF_LEN: usize = 5;
pub(super) const WORK_BUF_LEN: usize = 16;
pub(super) type DigestBufByteLen = U20;

pub(super) const H0: [u32; DIGEST_BUF_LEN] = [
    0x6745_2301,
    0xefcd_ab89,
    0x98ba_dcfe,
    0x1032_5476,
    0xc3d2_e1f0,
];

/// Message word index of each step, left line.
const R_L: [u8; 80] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, //
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8, //
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, //
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2, //
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
];

/// Message word index of each step, right line.
const R_R: [u8; 80] = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, //
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2, //
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, //
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14, //
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
];

/// Left rotation of each step, left line.
const S_L: [u32; 80] = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, //
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12, //
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, //
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, //
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
];

/// Left rotation of each step, right line.
const S_R: [u32; 80] = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, //
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11, //
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, //
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8, //
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
];

/// Round constant of each group of 16 steps, left line.
const K_L: [u32; 5] = [
    0x0000_0000,
    0x5a82_7999,
    0x6ed9_eba1,
    0x8f1b_bcdc,
    0xa953_fd4e,
];
/// Round constant of each group of 16 steps, right line.
const K_R: [u32; 5] = [
    0x50a2_8be6,
    0x5c4d_d124,
    0x6d70_3ef3,
    0x7a6d_76e9,
    0x0000_0000,
];

#[inline(always)]
fn f1(x: u32, y: u32, z: u32) -> u32 {
    x ^ (y ^ z)
}

#[inline(always)]
fn f2(x: u32, y: u32, z: u32) -> u32 {
    z ^ (x & (y ^ z))
}

#[inline(always)]
fn f3(x: u32, y: u32, z: u32) -> u32 {
    (x | !y) ^ z
}

#[inline(always)]
fn f4(x: u32, y: u32, z: u32) -> u32 {
    (x & z) | (y & !z)
}

#[inline(always)]
fn f5(x: u32, y: u32, z: u32) -> u32 {
    x ^ (y | !z)
}

#[inline(always)]
fn step(v: &mut [u32; 5], f: u32, x: u32, k: u32, s: u32) {
    let t = v[0]
        .wrapping_add(x)
        .wrapping_add(k)
        .wrapping_add(f)
        .rotate_left(s)
        .wrapping_add(v[4]);
    *v = [v[4], t, v[1], v[2].rotate_left(10), v[3]];
}

// The left and right lines are independent, and each step of a line depends on the previous step
// of that line. The two lines advance together, one step each, so the CPU can overlap them.
macro_rules! pair(
    ($l:ident, $r:ident, $w:ident, $i:expr, $g:expr, $fl:ident, $fr:ident) => {
        let fl = $fl($l[1], $l[2], $l[3]);
        let fr = $fr($r[1], $r[2], $r[3]);
        step(&mut $l, fl, $w[R_L[$i] as usize], K_L[$g], S_L[$i]);
        step(&mut $r, fr, $w[R_R[$i] as usize], K_R[$g], S_R[$i]);
    };
);

macro_rules! rounds(
    ($l:ident, $r:ident, $w:ident, $g:literal, $fl:ident, $fr:ident) => {
        pair!($l, $r, $w, $g * 16, $g, $fl, $fr);
        pair!($l, $r, $w, $g * 16 + 1, $g, $fl, $fr);
        pair!($l, $r, $w, $g * 16 + 2, $g, $fl, $fr);
        pair!($l, $r, $w, $g * 16 + 3, $g, $fl, $fr);
        pair!($l, $r, $w, $g * 16 + 4, $g, $fl, $fr);
        pair!($l, $r, $w, $g * 16 + 5, $g, $fl, $fr);
        pair!($l, $r, $w, $g * 16 + 6, $g, $fl, $fr);
        pair!($l, $r, $w, $g * 16 + 7, $g, $fl, $fr);
        pair!($l, $r, $w, $g * 16 + 8, $g, $fl, $fr);
        pair!($l, $r, $w, $g * 16 + 9, $g, $fl, $fr);
        pair!($l, $r, $w, $g * 16 + 10, $g, $fl, $fr);
        pair!($l, $r, $w, $g * 16 + 11, $g, $fl, $fr);
        pair!($l, $r, $w, $g * 16 + 12, $g, $fl, $fr);
        pair!($l, $r, $w, $g * 16 + 13, $g, $fl, $fr);
        pair!($l, $r, $w, $g * 16 + 14, $g, $fl, $fr);
        pair!($l, $r, $w, $g * 16 + 15, $g, $fl, $fr);
    };
);

pub(super) fn compress(h: &mut [u32; DIGEST_BUF_LEN], data: &[u8; 64]) {
    let mut w = [0u32; WORK_BUF_LEN];
    for (o, chunk) in w.iter_mut().zip(data.chunks_exact(4)) {
        *o = u32::from_le_bytes(chunk.try_into().unwrap());
    }

    let mut l = *h;
    let mut r = *h;
    rounds!(l, r, w, 0, f1, f5);
    rounds!(l, r, w, 1, f2, f4);
    rounds!(l, r, w, 2, f3, f3);
    rounds!(l, r, w, 3, f4, f2);
    rounds!(l, r, w, 4, f5, f1);

    let t = h[1].wrapping_add(l[2]).wrapping_add(r[3]);
    h[1] = h[2].wrapping_add(l[3]).wrapping_add(r[4]);
    h[2] = h[3].wrapping_add(l[4]).wrapping_add(r[0]);
    h[3] = h[4].wrapping_add(l[0]).wrapping_add(r[1]);
    h[4] = h[0].wrapping_add(l[1]).wrapping_add(r[2]);
    h[0] = t;
}
