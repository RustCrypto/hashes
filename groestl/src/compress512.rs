#![allow(clippy::needless_range_loop)]
use crate::table::TABLE;
use core::{convert::TryInto, u64};
type Block = super::Block<super::GroestlShortVarCore>;

pub(crate) const COLS: usize = 8;
const ROUNDS: u64 = 10;

#[inline(always)]
fn column(x: &[u64; COLS], c: [usize; 8]) -> u64 {
    let mut t = 0;
    for i in 0..8 {
        let sl = 8 * (7 - i);
        let idx = ((x[c[i]] >> sl) & 0xFF) as usize;
        t ^= TABLE[i][idx];
    }
    t
}

#[inline(always)]
fn rndq(mut x: [u64; COLS], r: u64) -> [u64; COLS] {
    for i in 0..COLS {
        x[i] ^= u64::MAX.wrapping_sub((i as u64) << 4) ^ r;
    }
    [
        column(&x, [1, 3, 5, 7, 0, 2, 4, 6]),
        column(&x, [2, 4, 6, 0, 1, 3, 5, 7]),
        column(&x, [3, 5, 7, 1, 2, 4, 6, 0]),
        column(&x, [4, 6, 0, 2, 3, 5, 7, 1]),
        column(&x, [5, 7, 1, 3, 4, 6, 0, 2]),
        column(&x, [6, 0, 2, 4, 5, 7, 1, 3]),
        column(&x, [7, 1, 3, 5, 6, 0, 2, 4]),
        column(&x, [0, 2, 4, 6, 7, 1, 3, 5]),
    ]
}

#[inline(always)]
fn rndp(mut x: [u64; COLS], r: u64) -> [u64; COLS] {
    for i in 0..COLS {
        x[i] ^= ((i as u64) << 60) ^ r;
    }
    [
        column(&x, [0, 1, 2, 3, 4, 5, 6, 7]),
        column(&x, [1, 2, 3, 4, 5, 6, 7, 0]),
        column(&x, [2, 3, 4, 5, 6, 7, 0, 1]),
        column(&x, [3, 4, 5, 6, 7, 0, 1, 2]),
        column(&x, [4, 5, 6, 7, 0, 1, 2, 3]),
        column(&x, [5, 6, 7, 0, 1, 2, 3, 4]),
        column(&x, [6, 7, 0, 1, 2, 3, 4, 5]),
        column(&x, [7, 0, 1, 2, 3, 4, 5, 6]),
    ]
}

pub(crate) fn compress(h: &mut [u64; COLS], block: &Block) {
    let mut q = [0u64; COLS];
    for (chunk, v) in block.chunks_exact(8).zip(q.iter_mut()) {
        *v = u64::from_be_bytes(chunk.try_into().unwrap());
    }
    let mut p = [0u64; COLS];
    for i in 0..COLS {
        p[i] = h[i] ^ q[i];
    }
    for i in 0..ROUNDS {
        q = rndq(q, i);
    }
    for i in 0..ROUNDS {
        p = rndp(p, i << 56);
    }
    for i in 0..COLS {
        h[i] ^= q[i] ^ p[i];
    }
}

pub(crate) fn p(h: &[u64; COLS]) -> [u64; COLS] {
    let mut p = *h;
    for i in 0..ROUNDS {
        p = rndp(p, i << 56);
    }
    for i in 0..COLS {
        p[i] ^= h[i];
    }
    p
}
