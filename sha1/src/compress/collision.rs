#![allow(clippy::many_single_char_names, clippy::too_many_arguments)]

use crate::{ubc_check::Testt, DetectionState, BLOCK_SIZE};

const K: [u32; 4] = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6];

#[inline]
fn mix(w: &mut [u32; 80], t: usize) -> u32 {
    (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).rotate_left(1)
}

#[inline]
fn f1(b: u32, c: u32, d: u32) -> u32 {
    d ^ b & (c ^ d)
}

#[inline]
fn f2(b: u32, c: u32, d: u32) -> u32 {
    b ^ c ^ d
}

#[inline]
fn f3(b: u32, c: u32, d: u32) -> u32 {
    (b & c).wrapping_add(d & (b ^ c))
}

#[inline]
fn f4(b: u32, c: u32, d: u32) -> u32 {
    b ^ c ^ d
}

#[inline]
fn round1_step(a: u32, b: &mut u32, c: u32, d: u32, e: &mut u32, m: &[u32; 80], t: usize) {
    *e = e.wrapping_add(
        a.rotate_left(5)
            .wrapping_add(f1(*b, c, d))
            .wrapping_add(K[0])
            .wrapping_add(m[t]),
    );
    *b = b.rotate_left(30);
}

#[inline]
fn round2_step(a: u32, b: &mut u32, c: u32, d: u32, e: &mut u32, m: &[u32; 80], t: usize) {
    *e = e.wrapping_add(
        a.rotate_left(5)
            .wrapping_add(f2(*b, c, d))
            .wrapping_add(K[1])
            .wrapping_add(m[t]),
    );
    *b = b.rotate_left(30);
}

#[inline]
fn round3_step(a: u32, b: &mut u32, c: u32, d: u32, e: &mut u32, m: &[u32; 80], t: usize) {
    *e = e.wrapping_add(
        a.rotate_left(5)
            .wrapping_add(f3(*b, c, d))
            .wrapping_add(K[2])
            .wrapping_add(m[t]),
    );
    *b = b.rotate_left(30);
}

#[inline]
fn round4_step(a: u32, b: &mut u32, c: u32, d: u32, e: &mut u32, m: &[u32; 80], t: usize) {
    *e = e.wrapping_add(
        a.rotate_left(5)
            .wrapping_add(f4(*b, c, d))
            .wrapping_add(K[3])
            .wrapping_add(m[t]),
    );
    *b = b.rotate_left(30);
}

#[inline]
fn round1_step_bw(a: u32, b: &mut u32, c: u32, d: u32, e: &mut u32, m: &[u32; 80], t: usize) {
    *b = b.rotate_right(30);
    *e = e.wrapping_sub(
        a.rotate_left(5)
            .wrapping_add(f1(*b, c, d))
            .wrapping_add(K[0])
            .wrapping_add(m[t]),
    );
}

#[inline]
fn round2_step_bw(a: u32, b: &mut u32, c: u32, d: u32, e: &mut u32, m: &[u32; 80], t: usize) {
    *b = b.rotate_right(30);
    *e = e.wrapping_sub(
        a.rotate_left(5)
            .wrapping_add(f2(*b, c, d))
            .wrapping_add(K[1])
            .wrapping_add(m[t]),
    );
}

#[inline]
fn round3_step_bw(a: u32, b: &mut u32, c: u32, d: u32, e: &mut u32, m: &[u32; 80], t: usize) {
    *b = b.rotate_right(30);
    *e = e.wrapping_sub(
        a.rotate_left(5)
            .wrapping_add(f3(*b, c, d))
            .wrapping_add(K[2])
            .wrapping_add(m[t]),
    );
}

#[inline]
fn round4_step_bw(a: u32, b: &mut u32, c: u32, d: u32, e: &mut u32, m: &[u32; 80], t: usize) {
    *b = b.rotate_right(30);
    *e = e.wrapping_sub(
        a.rotate_left(5)
            .wrapping_add(f4(*b, c, d))
            .wrapping_add(K[3])
            .wrapping_add(m[t]),
    );
}

#[inline]
fn full_round1_step_load(
    a: u32,
    b: &mut u32,
    c: u32,
    d: u32,
    e: &mut u32,
    m: &[u32; 16],
    w: &mut [u32; 80],
    t: usize,
    temp: &mut u32,
) {
    *temp = m[t];
    w[t] = *temp;
    *e = e.wrapping_add(
        temp.wrapping_add(a.rotate_left(5))
            .wrapping_add(f1(*b, c, d))
            .wrapping_add(K[0]),
    );
    *b = b.rotate_left(30);
}

#[inline]
fn full_round1_step_expand(
    a: u32,
    b: &mut u32,
    c: u32,
    d: u32,
    e: &mut u32,
    w: &mut [u32; 80],
    t: usize,
    temp: &mut u32,
) {
    *temp = mix(w, t);
    w[t] = *temp;
    *e = e.wrapping_add(
        temp.wrapping_add(a.rotate_left(5))
            .wrapping_add(f1(*b, c, d))
            .wrapping_add(K[0]),
    );
    *b = b.rotate_left(30);
}

#[inline]
fn full_round2_step(
    a: u32,
    b: &mut u32,
    c: u32,
    d: u32,
    e: &mut u32,
    w: &mut [u32; 80],
    t: usize,
    temp: &mut u32,
) {
    *temp = mix(w, t);
    w[t] = *temp;
    *e = e.wrapping_add(
        temp.wrapping_add(a.rotate_left(5))
            .wrapping_add(f2(*b, c, d))
            .wrapping_add(K[1]),
    );
    *b = b.rotate_left(30);
}

#[inline]
fn full_round3_step(
    a: u32,
    b: &mut u32,
    c: u32,
    d: u32,
    e: &mut u32,
    w: &mut [u32; 80],
    t: usize,
    temp: &mut u32,
) {
    *temp = mix(w, t);
    w[t] = *temp;
    *e = e.wrapping_add(
        temp.wrapping_add(a.rotate_left(5))
            .wrapping_add(f3(*b, c, d))
            .wrapping_add(K[2]),
    );
    *b = b.rotate_left(30);
}

#[inline]
fn full_round4_step(
    a: u32,
    b: &mut u32,
    c: u32,
    d: u32,
    e: &mut u32,
    w: &mut [u32; 80],
    t: usize,
    temp: &mut u32,
) {
    *temp = mix(w, t);
    w[t] = *temp;
    *e = e.wrapping_add(
        temp.wrapping_add(a.rotate_left(5))
            .wrapping_add(f4(*b, c, d))
            .wrapping_add(K[3]),
    );
    *b = b.rotate_left(30);
}

fn compression_w(ihv: &mut [u32; 5], w: &mut [u32; 80]) {
    let [mut a, mut b, mut c, mut d, mut e] = ihv;

    round1_step(a, &mut b, c, d, &mut e, w, 0);
    round1_step(e, &mut a, b, c, &mut d, w, 1);
    round1_step(d, &mut e, a, b, &mut c, w, 2);
    round1_step(c, &mut d, e, a, &mut b, w, 3);
    round1_step(b, &mut c, d, e, &mut a, w, 4);
    round1_step(a, &mut b, c, d, &mut e, w, 5);
    round1_step(e, &mut a, b, c, &mut d, w, 6);
    round1_step(d, &mut e, a, b, &mut c, w, 7);
    round1_step(c, &mut d, e, a, &mut b, w, 8);
    round1_step(b, &mut c, d, e, &mut a, w, 9);
    round1_step(a, &mut b, c, d, &mut e, w, 10);
    round1_step(e, &mut a, b, c, &mut d, w, 11);
    round1_step(d, &mut e, a, b, &mut c, w, 12);
    round1_step(c, &mut d, e, a, &mut b, w, 13);
    round1_step(b, &mut c, d, e, &mut a, w, 14);
    round1_step(a, &mut b, c, d, &mut e, w, 15);
    round1_step(e, &mut a, b, c, &mut d, w, 16);
    round1_step(d, &mut e, a, b, &mut c, w, 17);
    round1_step(c, &mut d, e, a, &mut b, w, 18);
    round1_step(b, &mut c, d, e, &mut a, w, 19);

    round2_step(a, &mut b, c, d, &mut e, w, 20);
    round2_step(e, &mut a, b, c, &mut d, w, 21);
    round2_step(d, &mut e, a, b, &mut c, w, 22);
    round2_step(c, &mut d, e, a, &mut b, w, 23);
    round2_step(b, &mut c, d, e, &mut a, w, 24);
    round2_step(a, &mut b, c, d, &mut e, w, 25);
    round2_step(e, &mut a, b, c, &mut d, w, 26);
    round2_step(d, &mut e, a, b, &mut c, w, 27);
    round2_step(c, &mut d, e, a, &mut b, w, 28);
    round2_step(b, &mut c, d, e, &mut a, w, 29);
    round2_step(a, &mut b, c, d, &mut e, w, 30);
    round2_step(e, &mut a, b, c, &mut d, w, 31);
    round2_step(d, &mut e, a, b, &mut c, w, 32);
    round2_step(c, &mut d, e, a, &mut b, w, 33);
    round2_step(b, &mut c, d, e, &mut a, w, 34);
    round2_step(a, &mut b, c, d, &mut e, w, 35);
    round2_step(e, &mut a, b, c, &mut d, w, 36);
    round2_step(d, &mut e, a, b, &mut c, w, 37);
    round2_step(c, &mut d, e, a, &mut b, w, 38);
    round2_step(b, &mut c, d, e, &mut a, w, 39);

    round3_step(a, &mut b, c, d, &mut e, w, 40);
    round3_step(e, &mut a, b, c, &mut d, w, 41);
    round3_step(d, &mut e, a, b, &mut c, w, 42);
    round3_step(c, &mut d, e, a, &mut b, w, 43);
    round3_step(b, &mut c, d, e, &mut a, w, 44);
    round3_step(a, &mut b, c, d, &mut e, w, 45);
    round3_step(e, &mut a, b, c, &mut d, w, 46);
    round3_step(d, &mut e, a, b, &mut c, w, 47);
    round3_step(c, &mut d, e, a, &mut b, w, 48);
    round3_step(b, &mut c, d, e, &mut a, w, 49);
    round3_step(a, &mut b, c, d, &mut e, w, 50);
    round3_step(e, &mut a, b, c, &mut d, w, 51);
    round3_step(d, &mut e, a, b, &mut c, w, 52);
    round3_step(c, &mut d, e, a, &mut b, w, 53);
    round3_step(b, &mut c, d, e, &mut a, w, 54);
    round3_step(a, &mut b, c, d, &mut e, w, 55);
    round3_step(e, &mut a, b, c, &mut d, w, 56);
    round3_step(d, &mut e, a, b, &mut c, w, 57);
    round3_step(c, &mut d, e, a, &mut b, w, 58);
    round3_step(b, &mut c, d, e, &mut a, w, 59);

    round4_step(a, &mut b, c, d, &mut e, w, 60);
    round4_step(e, &mut a, b, c, &mut d, w, 61);
    round4_step(d, &mut e, a, b, &mut c, w, 62);
    round4_step(c, &mut d, e, a, &mut b, w, 63);
    round4_step(b, &mut c, d, e, &mut a, w, 64);
    round4_step(a, &mut b, c, d, &mut e, w, 65);
    round4_step(e, &mut a, b, c, &mut d, w, 66);
    round4_step(d, &mut e, a, b, &mut c, w, 67);
    round4_step(c, &mut d, e, a, &mut b, w, 68);
    round4_step(b, &mut c, d, e, &mut a, w, 69);
    round4_step(a, &mut b, c, d, &mut e, w, 70);
    round4_step(e, &mut a, b, c, &mut d, w, 71);
    round4_step(d, &mut e, a, b, &mut c, w, 72);
    round4_step(c, &mut d, e, a, &mut b, w, 73);
    round4_step(b, &mut c, d, e, &mut a, w, 74);
    round4_step(a, &mut b, c, d, &mut e, w, 75);
    round4_step(e, &mut a, b, c, &mut d, w, 76);
    round4_step(d, &mut e, a, b, &mut c, w, 77);
    round4_step(c, &mut d, e, a, &mut b, w, 78);
    round4_step(b, &mut c, d, e, &mut a, w, 79);

    ihv[0] = ihv[0].wrapping_add(a);
    ihv[1] = ihv[1].wrapping_add(b);
    ihv[2] = ihv[2].wrapping_add(c);
    ihv[3] = ihv[3].wrapping_add(d);
    ihv[4] = ihv[4].wrapping_add(e);
}

fn compression_states(
    ihv: &mut [u32; 5],
    m: &[u32; 16],
    w: &mut [u32; 80],
    state_58: &mut [u32; 5],
    state_65: &mut [u32; 5],
) {
    let [mut a, mut b, mut c, mut d, mut e] = ihv;
    let mut temp: u32 = 0;

    full_round1_step_load(a, &mut b, c, d, &mut e, m, w, 0, &mut temp);
    full_round1_step_load(e, &mut a, b, c, &mut d, m, w, 1, &mut temp);
    full_round1_step_load(d, &mut e, a, b, &mut c, m, w, 2, &mut temp);
    full_round1_step_load(c, &mut d, e, a, &mut b, m, w, 3, &mut temp);
    full_round1_step_load(b, &mut c, d, e, &mut a, m, w, 4, &mut temp);
    full_round1_step_load(a, &mut b, c, d, &mut e, m, w, 5, &mut temp);
    full_round1_step_load(e, &mut a, b, c, &mut d, m, w, 6, &mut temp);
    full_round1_step_load(d, &mut e, a, b, &mut c, m, w, 7, &mut temp);
    full_round1_step_load(c, &mut d, e, a, &mut b, m, w, 8, &mut temp);
    full_round1_step_load(b, &mut c, d, e, &mut a, m, w, 9, &mut temp);
    full_round1_step_load(a, &mut b, c, d, &mut e, m, w, 10, &mut temp);
    full_round1_step_load(e, &mut a, b, c, &mut d, m, w, 11, &mut temp);
    full_round1_step_load(d, &mut e, a, b, &mut c, m, w, 12, &mut temp);
    full_round1_step_load(c, &mut d, e, a, &mut b, m, w, 13, &mut temp);
    full_round1_step_load(b, &mut c, d, e, &mut a, m, w, 14, &mut temp);
    full_round1_step_load(a, &mut b, c, d, &mut e, m, w, 15, &mut temp);

    full_round1_step_expand(e, &mut a, b, c, &mut d, w, 16, &mut temp);
    full_round1_step_expand(d, &mut e, a, b, &mut c, w, 17, &mut temp);
    full_round1_step_expand(c, &mut d, e, a, &mut b, w, 18, &mut temp);
    full_round1_step_expand(b, &mut c, d, e, &mut a, w, 19, &mut temp);

    full_round2_step(a, &mut b, c, d, &mut e, w, 20, &mut temp);
    full_round2_step(e, &mut a, b, c, &mut d, w, 21, &mut temp);
    full_round2_step(d, &mut e, a, b, &mut c, w, 22, &mut temp);
    full_round2_step(c, &mut d, e, a, &mut b, w, 23, &mut temp);
    full_round2_step(b, &mut c, d, e, &mut a, w, 24, &mut temp);
    full_round2_step(a, &mut b, c, d, &mut e, w, 25, &mut temp);
    full_round2_step(e, &mut a, b, c, &mut d, w, 26, &mut temp);
    full_round2_step(d, &mut e, a, b, &mut c, w, 27, &mut temp);
    full_round2_step(c, &mut d, e, a, &mut b, w, 28, &mut temp);
    full_round2_step(b, &mut c, d, e, &mut a, w, 29, &mut temp);
    full_round2_step(a, &mut b, c, d, &mut e, w, 30, &mut temp);
    full_round2_step(e, &mut a, b, c, &mut d, w, 31, &mut temp);
    full_round2_step(d, &mut e, a, b, &mut c, w, 32, &mut temp);
    full_round2_step(c, &mut d, e, a, &mut b, w, 33, &mut temp);
    full_round2_step(b, &mut c, d, e, &mut a, w, 34, &mut temp);
    full_round2_step(a, &mut b, c, d, &mut e, w, 35, &mut temp);
    full_round2_step(e, &mut a, b, c, &mut d, w, 36, &mut temp);
    full_round2_step(d, &mut e, a, b, &mut c, w, 37, &mut temp);
    full_round2_step(c, &mut d, e, a, &mut b, w, 38, &mut temp);
    full_round2_step(b, &mut c, d, e, &mut a, w, 39, &mut temp);

    full_round3_step(a, &mut b, c, d, &mut e, w, 40, &mut temp);
    full_round3_step(e, &mut a, b, c, &mut d, w, 41, &mut temp);
    full_round3_step(d, &mut e, a, b, &mut c, w, 42, &mut temp);
    full_round3_step(c, &mut d, e, a, &mut b, w, 43, &mut temp);
    full_round3_step(b, &mut c, d, e, &mut a, w, 44, &mut temp);
    full_round3_step(a, &mut b, c, d, &mut e, w, 45, &mut temp);
    full_round3_step(e, &mut a, b, c, &mut d, w, 46, &mut temp);
    full_round3_step(d, &mut e, a, b, &mut c, w, 47, &mut temp);
    full_round3_step(c, &mut d, e, a, &mut b, w, 48, &mut temp);
    full_round3_step(b, &mut c, d, e, &mut a, w, 49, &mut temp);
    full_round3_step(a, &mut b, c, d, &mut e, w, 50, &mut temp);
    full_round3_step(e, &mut a, b, c, &mut d, w, 51, &mut temp);
    full_round3_step(d, &mut e, a, b, &mut c, w, 52, &mut temp);
    full_round3_step(c, &mut d, e, a, &mut b, w, 53, &mut temp);
    full_round3_step(b, &mut c, d, e, &mut a, w, 54, &mut temp);
    full_round3_step(a, &mut b, c, d, &mut e, w, 55, &mut temp);
    full_round3_step(e, &mut a, b, c, &mut d, w, 56, &mut temp);
    full_round3_step(d, &mut e, a, b, &mut c, w, 57, &mut temp);

    // Store state58
    state_58[0] = a;
    state_58[1] = b;
    state_58[2] = c;
    state_58[3] = d;
    state_58[4] = e;

    full_round3_step(c, &mut d, e, a, &mut b, w, 58, &mut temp);
    full_round3_step(b, &mut c, d, e, &mut a, w, 59, &mut temp);

    full_round4_step(a, &mut b, c, d, &mut e, w, 60, &mut temp);
    full_round4_step(e, &mut a, b, c, &mut d, w, 61, &mut temp);
    full_round4_step(d, &mut e, a, b, &mut c, w, 62, &mut temp);
    full_round4_step(c, &mut d, e, a, &mut b, w, 63, &mut temp);
    full_round4_step(b, &mut c, d, e, &mut a, w, 64, &mut temp);

    // Store state65
    state_65[0] = a;
    state_65[1] = b;
    state_65[2] = c;
    state_65[3] = d;
    state_65[4] = e;

    full_round4_step(a, &mut b, c, d, &mut e, w, 65, &mut temp);
    full_round4_step(e, &mut a, b, c, &mut d, w, 66, &mut temp);
    full_round4_step(d, &mut e, a, b, &mut c, w, 67, &mut temp);
    full_round4_step(c, &mut d, e, a, &mut b, w, 68, &mut temp);
    full_round4_step(b, &mut c, d, e, &mut a, w, 69, &mut temp);
    full_round4_step(a, &mut b, c, d, &mut e, w, 70, &mut temp);
    full_round4_step(e, &mut a, b, c, &mut d, w, 71, &mut temp);
    full_round4_step(d, &mut e, a, b, &mut c, w, 72, &mut temp);
    full_round4_step(c, &mut d, e, a, &mut b, w, 73, &mut temp);
    full_round4_step(b, &mut c, d, e, &mut a, w, 74, &mut temp);
    full_round4_step(a, &mut b, c, d, &mut e, w, 75, &mut temp);
    full_round4_step(e, &mut a, b, c, &mut d, w, 76, &mut temp);
    full_round4_step(d, &mut e, a, b, &mut c, w, 77, &mut temp);
    full_round4_step(c, &mut d, e, a, &mut b, w, 78, &mut temp);
    full_round4_step(b, &mut c, d, e, &mut a, w, 79, &mut temp);

    ihv[0] = ihv[0].wrapping_add(a);
    ihv[1] = ihv[1].wrapping_add(b);
    ihv[2] = ihv[2].wrapping_add(c);
    ihv[3] = ihv[3].wrapping_add(d);
    ihv[4] = ihv[4].wrapping_add(e);
}

fn recompress_fast_58(
    ihvin: &mut [u32; 5],
    ihvout: &mut [u32; 5],
    me2: &[u32; 80],
    state: &[u32; 5],
) {
    let [mut a, mut b, mut c, mut d, mut e] = state;

    round3_step_bw(d, &mut e, a, b, &mut c, me2, 57);
    round3_step_bw(e, &mut a, b, c, &mut d, me2, 56);
    round3_step_bw(a, &mut b, c, d, &mut e, me2, 55);
    round3_step_bw(b, &mut c, d, e, &mut a, me2, 54);
    round3_step_bw(c, &mut d, e, a, &mut b, me2, 53);
    round3_step_bw(d, &mut e, a, b, &mut c, me2, 52);
    round3_step_bw(e, &mut a, b, c, &mut d, me2, 51);
    round3_step_bw(a, &mut b, c, d, &mut e, me2, 50);
    round3_step_bw(b, &mut c, d, e, &mut a, me2, 49);
    round3_step_bw(c, &mut d, e, a, &mut b, me2, 48);
    round3_step_bw(d, &mut e, a, b, &mut c, me2, 47);
    round3_step_bw(e, &mut a, b, c, &mut d, me2, 46);
    round3_step_bw(a, &mut b, c, d, &mut e, me2, 45);
    round3_step_bw(b, &mut c, d, e, &mut a, me2, 44);
    round3_step_bw(c, &mut d, e, a, &mut b, me2, 43);
    round3_step_bw(d, &mut e, a, b, &mut c, me2, 42);
    round3_step_bw(e, &mut a, b, c, &mut d, me2, 41);
    round3_step_bw(a, &mut b, c, d, &mut e, me2, 40);

    round2_step_bw(b, &mut c, d, e, &mut a, me2, 39);
    round2_step_bw(c, &mut d, e, a, &mut b, me2, 38);
    round2_step_bw(d, &mut e, a, b, &mut c, me2, 37);
    round2_step_bw(e, &mut a, b, c, &mut d, me2, 36);
    round2_step_bw(a, &mut b, c, d, &mut e, me2, 35);
    round2_step_bw(b, &mut c, d, e, &mut a, me2, 34);
    round2_step_bw(c, &mut d, e, a, &mut b, me2, 33);
    round2_step_bw(d, &mut e, a, b, &mut c, me2, 32);
    round2_step_bw(e, &mut a, b, c, &mut d, me2, 31);
    round2_step_bw(a, &mut b, c, d, &mut e, me2, 30);
    round2_step_bw(b, &mut c, d, e, &mut a, me2, 29);
    round2_step_bw(c, &mut d, e, a, &mut b, me2, 28);
    round2_step_bw(d, &mut e, a, b, &mut c, me2, 27);
    round2_step_bw(e, &mut a, b, c, &mut d, me2, 26);
    round2_step_bw(a, &mut b, c, d, &mut e, me2, 25);
    round2_step_bw(b, &mut c, d, e, &mut a, me2, 24);
    round2_step_bw(c, &mut d, e, a, &mut b, me2, 23);
    round2_step_bw(d, &mut e, a, b, &mut c, me2, 22);
    round2_step_bw(e, &mut a, b, c, &mut d, me2, 21);
    round2_step_bw(a, &mut b, c, d, &mut e, me2, 20);

    round1_step_bw(b, &mut c, d, e, &mut a, me2, 19);
    round1_step_bw(c, &mut d, e, a, &mut b, me2, 18);
    round1_step_bw(d, &mut e, a, b, &mut c, me2, 17);
    round1_step_bw(e, &mut a, b, c, &mut d, me2, 16);
    round1_step_bw(a, &mut b, c, d, &mut e, me2, 15);
    round1_step_bw(b, &mut c, d, e, &mut a, me2, 14);
    round1_step_bw(c, &mut d, e, a, &mut b, me2, 13);
    round1_step_bw(d, &mut e, a, b, &mut c, me2, 12);
    round1_step_bw(e, &mut a, b, c, &mut d, me2, 11);
    round1_step_bw(a, &mut b, c, d, &mut e, me2, 10);
    round1_step_bw(b, &mut c, d, e, &mut a, me2, 9);
    round1_step_bw(c, &mut d, e, a, &mut b, me2, 8);
    round1_step_bw(d, &mut e, a, b, &mut c, me2, 7);
    round1_step_bw(e, &mut a, b, c, &mut d, me2, 6);
    round1_step_bw(a, &mut b, c, d, &mut e, me2, 5);
    round1_step_bw(b, &mut c, d, e, &mut a, me2, 4);
    round1_step_bw(c, &mut d, e, a, &mut b, me2, 3);
    round1_step_bw(d, &mut e, a, b, &mut c, me2, 2);
    round1_step_bw(e, &mut a, b, c, &mut d, me2, 1);
    round1_step_bw(a, &mut b, c, d, &mut e, me2, 0);

    ihvin[0] = a;
    ihvin[1] = b;
    ihvin[2] = c;
    ihvin[3] = d;
    ihvin[4] = e;

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];

    round3_step(c, &mut d, e, a, &mut b, me2, 58);
    round3_step(b, &mut c, d, e, &mut a, me2, 59);

    round4_step(a, &mut b, c, d, &mut e, me2, 60);
    round4_step(e, &mut a, b, c, &mut d, me2, 61);
    round4_step(d, &mut e, a, b, &mut c, me2, 62);
    round4_step(c, &mut d, e, a, &mut b, me2, 63);
    round4_step(b, &mut c, d, e, &mut a, me2, 64);
    round4_step(a, &mut b, c, d, &mut e, me2, 65);
    round4_step(e, &mut a, b, c, &mut d, me2, 66);
    round4_step(d, &mut e, a, b, &mut c, me2, 67);
    round4_step(c, &mut d, e, a, &mut b, me2, 68);
    round4_step(b, &mut c, d, e, &mut a, me2, 69);
    round4_step(a, &mut b, c, d, &mut e, me2, 70);
    round4_step(e, &mut a, b, c, &mut d, me2, 71);
    round4_step(d, &mut e, a, b, &mut c, me2, 72);
    round4_step(c, &mut d, e, a, &mut b, me2, 73);
    round4_step(b, &mut c, d, e, &mut a, me2, 74);
    round4_step(a, &mut b, c, d, &mut e, me2, 75);
    round4_step(e, &mut a, b, c, &mut d, me2, 76);
    round4_step(d, &mut e, a, b, &mut c, me2, 77);
    round4_step(c, &mut d, e, a, &mut b, me2, 78);
    round4_step(b, &mut c, d, e, &mut a, me2, 79);

    ihvout[0] = ihvin[0].wrapping_add(a);
    ihvout[1] = ihvin[1].wrapping_add(b);
    ihvout[2] = ihvin[2].wrapping_add(c);
    ihvout[3] = ihvin[3].wrapping_add(d);
    ihvout[4] = ihvin[4].wrapping_add(e);
}

fn recompress_fast_65(
    ihvin: &mut [u32; 5],
    ihvout: &mut [u32; 5],
    me2: &[u32; 80],
    state: &[u32; 5],
) {
    let [mut a, mut b, mut c, mut d, mut e] = state;

    round4_step_bw(b, &mut c, d, e, &mut a, me2, 64);
    round4_step_bw(c, &mut d, e, a, &mut b, me2, 63);
    round4_step_bw(d, &mut e, a, b, &mut c, me2, 62);
    round4_step_bw(e, &mut a, b, c, &mut d, me2, 61);
    round4_step_bw(a, &mut b, c, d, &mut e, me2, 60);

    round3_step_bw(b, &mut c, d, e, &mut a, me2, 59);
    round3_step_bw(c, &mut d, e, a, &mut b, me2, 58);
    round3_step_bw(d, &mut e, a, b, &mut c, me2, 57);
    round3_step_bw(e, &mut a, b, c, &mut d, me2, 56);
    round3_step_bw(a, &mut b, c, d, &mut e, me2, 55);
    round3_step_bw(b, &mut c, d, e, &mut a, me2, 54);
    round3_step_bw(c, &mut d, e, a, &mut b, me2, 53);
    round3_step_bw(d, &mut e, a, b, &mut c, me2, 52);
    round3_step_bw(e, &mut a, b, c, &mut d, me2, 51);
    round3_step_bw(a, &mut b, c, d, &mut e, me2, 50);
    round3_step_bw(b, &mut c, d, e, &mut a, me2, 49);
    round3_step_bw(c, &mut d, e, a, &mut b, me2, 48);
    round3_step_bw(d, &mut e, a, b, &mut c, me2, 47);
    round3_step_bw(e, &mut a, b, c, &mut d, me2, 46);
    round3_step_bw(a, &mut b, c, d, &mut e, me2, 45);
    round3_step_bw(b, &mut c, d, e, &mut a, me2, 44);
    round3_step_bw(c, &mut d, e, a, &mut b, me2, 43);
    round3_step_bw(d, &mut e, a, b, &mut c, me2, 42);
    round3_step_bw(e, &mut a, b, c, &mut d, me2, 41);
    round3_step_bw(a, &mut b, c, d, &mut e, me2, 40);

    round2_step_bw(b, &mut c, d, e, &mut a, me2, 39);
    round2_step_bw(c, &mut d, e, a, &mut b, me2, 38);
    round2_step_bw(d, &mut e, a, b, &mut c, me2, 37);
    round2_step_bw(e, &mut a, b, c, &mut d, me2, 36);
    round2_step_bw(a, &mut b, c, d, &mut e, me2, 35);
    round2_step_bw(b, &mut c, d, e, &mut a, me2, 34);
    round2_step_bw(c, &mut d, e, a, &mut b, me2, 33);
    round2_step_bw(d, &mut e, a, b, &mut c, me2, 32);
    round2_step_bw(e, &mut a, b, c, &mut d, me2, 31);
    round2_step_bw(a, &mut b, c, d, &mut e, me2, 30);
    round2_step_bw(b, &mut c, d, e, &mut a, me2, 29);
    round2_step_bw(c, &mut d, e, a, &mut b, me2, 28);
    round2_step_bw(d, &mut e, a, b, &mut c, me2, 27);
    round2_step_bw(e, &mut a, b, c, &mut d, me2, 26);
    round2_step_bw(a, &mut b, c, d, &mut e, me2, 25);
    round2_step_bw(b, &mut c, d, e, &mut a, me2, 24);
    round2_step_bw(c, &mut d, e, a, &mut b, me2, 23);
    round2_step_bw(d, &mut e, a, b, &mut c, me2, 22);
    round2_step_bw(e, &mut a, b, c, &mut d, me2, 21);
    round2_step_bw(a, &mut b, c, d, &mut e, me2, 20);

    round1_step_bw(b, &mut c, d, e, &mut a, me2, 19);
    round1_step_bw(c, &mut d, e, a, &mut b, me2, 18);
    round1_step_bw(d, &mut e, a, b, &mut c, me2, 17);
    round1_step_bw(e, &mut a, b, c, &mut d, me2, 16);
    round1_step_bw(a, &mut b, c, d, &mut e, me2, 15);
    round1_step_bw(b, &mut c, d, e, &mut a, me2, 14);
    round1_step_bw(c, &mut d, e, a, &mut b, me2, 13);
    round1_step_bw(d, &mut e, a, b, &mut c, me2, 12);
    round1_step_bw(e, &mut a, b, c, &mut d, me2, 11);
    round1_step_bw(a, &mut b, c, d, &mut e, me2, 10);
    round1_step_bw(b, &mut c, d, e, &mut a, me2, 9);
    round1_step_bw(c, &mut d, e, a, &mut b, me2, 8);
    round1_step_bw(d, &mut e, a, b, &mut c, me2, 7);
    round1_step_bw(e, &mut a, b, c, &mut d, me2, 6);
    round1_step_bw(a, &mut b, c, d, &mut e, me2, 5);
    round1_step_bw(b, &mut c, d, e, &mut a, me2, 4);
    round1_step_bw(c, &mut d, e, a, &mut b, me2, 3);
    round1_step_bw(d, &mut e, a, b, &mut c, me2, 2);
    round1_step_bw(e, &mut a, b, c, &mut d, me2, 1);
    round1_step_bw(a, &mut b, c, d, &mut e, me2, 0);

    ihvin[0] = a;
    ihvin[1] = b;
    ihvin[2] = c;
    ihvin[3] = d;
    ihvin[4] = e;

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];

    round4_step(a, &mut b, c, d, &mut e, me2, 65);
    round4_step(e, &mut a, b, c, &mut d, me2, 66);
    round4_step(d, &mut e, a, b, &mut c, me2, 67);
    round4_step(c, &mut d, e, a, &mut b, me2, 68);
    round4_step(b, &mut c, d, e, &mut a, me2, 69);
    round4_step(a, &mut b, c, d, &mut e, me2, 70);
    round4_step(e, &mut a, b, c, &mut d, me2, 71);
    round4_step(d, &mut e, a, b, &mut c, me2, 72);
    round4_step(c, &mut d, e, a, &mut b, me2, 73);
    round4_step(b, &mut c, d, e, &mut a, me2, 74);
    round4_step(a, &mut b, c, d, &mut e, me2, 75);
    round4_step(e, &mut a, b, c, &mut d, me2, 76);
    round4_step(d, &mut e, a, b, &mut c, me2, 77);
    round4_step(c, &mut d, e, a, &mut b, me2, 78);
    round4_step(b, &mut c, d, e, &mut a, me2, 79);

    ihvout[0] = ihvin[0].wrapping_add(a);
    ihvout[1] = ihvin[1].wrapping_add(b);
    ihvout[2] = ihvin[2].wrapping_add(c);
    ihvout[3] = ihvin[3].wrapping_add(d);
    ihvout[4] = ihvin[4].wrapping_add(e);
}

fn recompression_step(
    step: Testt,
    ihvin: &mut [u32; 5],
    ihvout: &mut [u32; 5],
    me2: &[u32; 80],
    state: &[u32; 5],
) {
    match step {
        Testt::T58 => {
            recompress_fast_58(ihvin, ihvout, me2, state);
        }
        Testt::T65 => {
            recompress_fast_65(ihvin, ihvout, me2, state);
        }
    }
}

#[inline]
pub fn compress(state: &mut [u32; 5], ctx: &mut DetectionState, blocks: &[[u8; BLOCK_SIZE]]) {
    let mut block_u32 = [0u32; BLOCK_SIZE / 4];
    // since LLVM can't properly use aliasing yet it will make
    // unnecessary state stores without this copy
    let mut state_cpy = *state;

    for block in blocks.iter() {
        if ctx.config.detect_collision {
            ctx.ihv1.copy_from_slice(&state_cpy);
        }

        for (o, chunk) in block_u32.iter_mut().zip(block.chunks_exact(4)) {
            *o = u32::from_be_bytes(chunk.try_into().unwrap());
        }

        let DetectionState {
            config,
            m1,
            state_58,
            state_65,
            ..
        } = ctx;

        compression_states(&mut state_cpy, &block_u32, m1, state_58, state_65);

        if config.detect_collision {
            let ubc_mask = if ctx.config.ubc_check {
                crate::ubc_check::ubc_check(&ctx.m1)
            } else {
                0xFFFFFFFF
            };

            if ubc_mask != 0 {
                let mut ihvtmp = [0u32; 5];
                for dv_type in &crate::ubc_check::SHA1_DVS {
                    if ubc_mask & (1 << dv_type.maskb) != 0 {
                        for ((m2, m1), dm) in
                            ctx.m2.iter_mut().zip(ctx.m1.iter()).zip(dv_type.dm.iter())
                        {
                            *m2 = m1 ^ dm;
                        }
                        let DetectionState {
                            ihv2,
                            m2,
                            state_58,
                            state_65,
                            ..
                        } = ctx;

                        recompression_step(
                            dv_type.testt,
                            ihv2,
                            &mut ihvtmp,
                            m2,
                            match dv_type.testt {
                                Testt::T58 => state_58,
                                Testt::T65 => state_65,
                            },
                        );

                        // to verify SHA-1 collision detection code with collisions for reduced-step SHA-1
                        if (0
                            == ((ihvtmp[0] ^ state_cpy[0])
                                | (ihvtmp[1] ^ state_cpy[1])
                                | (ihvtmp[2] ^ state_cpy[2])
                                | (ihvtmp[3] ^ state_cpy[3])
                                | (ihvtmp[4] ^ state_cpy[4])))
                            || (ctx.config.reduced_round_collision
                                && 0 == ((ctx.ihv1[0] ^ ctx.ihv2[0])
                                    | (ctx.ihv1[1] ^ ctx.ihv2[1])
                                    | (ctx.ihv1[2] ^ ctx.ihv2[2])
                                    | (ctx.ihv1[3] ^ ctx.ihv2[3])
                                    | (ctx.ihv1[4] ^ ctx.ihv2[4])))
                        {
                            ctx.found_collision = true;

                            if ctx.config.safe_hash {
                                compression_w(&mut state_cpy, &mut ctx.m1);
                                compression_w(&mut state_cpy, &mut ctx.m1);
                            }
                            break;
                        }
                    }
                }
            }
        }
    }
    *state = state_cpy;
}

const SHA1_PADDING: [u8; 64] = [
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,
];

/// returns: 0 = no collision detected,
/// otherwise = collision found => warn user for active attack
#[inline]
pub fn finalize(
    state: &mut [u32; 5],
    total: u64,
    last_block: &[u8],
    ctx: &mut DetectionState,
) -> bool {
    let mut total = total + last_block.len() as u64;
    let last = last_block.len();
    let needs_two_blocks = last >= 56;

    let mut buffer = [0u8; BLOCK_SIZE];
    buffer[..last].copy_from_slice(last_block);
    let left = BLOCK_SIZE - last;

    if needs_two_blocks {
        let padn = 120 - last;
        let (pad0, pad1) = SHA1_PADDING[..padn].split_at(left);
        buffer[last..].copy_from_slice(pad0);
        compress(state, ctx, &[buffer]);
        buffer[..pad1.len()].copy_from_slice(pad1);
    } else {
        let padn = 56 - last;
        buffer[last..56].copy_from_slice(&SHA1_PADDING[..padn]);
    }

    total <<= 3;

    buffer[56] = (total >> 56) as u8;
    buffer[57] = (total >> 48) as u8;
    buffer[58] = (total >> 40) as u8;
    buffer[59] = (total >> 32) as u8;
    buffer[60] = (total >> 24) as u8;
    buffer[61] = (total >> 16) as u8;
    buffer[62] = (total >> 8) as u8;
    buffer[63] = total as u8;

    compress(state, ctx, &[buffer]);

    ctx.found_collision
}
