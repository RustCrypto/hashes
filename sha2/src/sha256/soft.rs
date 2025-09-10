use crate::consts::K32;

#[rustfmt::skip]
macro_rules! repeat64 {
    ($i:ident, $b:block) => {
        let $i = 0; $b; let $i = 1; $b; let $i = 2; $b; let $i = 3; $b;
        let $i = 4; $b; let $i = 5; $b; let $i = 6; $b; let $i = 7; $b;
        let $i = 8; $b; let $i = 9; $b; let $i = 10; $b; let $i = 11; $b;
        let $i = 12; $b; let $i = 13; $b; let $i = 14; $b; let $i = 15; $b;
        let $i = 16; $b; let $i = 17; $b; let $i = 18; $b; let $i = 19; $b;
        let $i = 20; $b; let $i = 21; $b; let $i = 22; $b; let $i = 23; $b;
        let $i = 24; $b; let $i = 25; $b; let $i = 26; $b; let $i = 27; $b;
        let $i = 28; $b; let $i = 29; $b; let $i = 30; $b; let $i = 31; $b;
        let $i = 32; $b; let $i = 33; $b; let $i = 34; $b; let $i = 35; $b;
        let $i = 36; $b; let $i = 37; $b; let $i = 38; $b; let $i = 39; $b;
        let $i = 40; $b; let $i = 41; $b; let $i = 42; $b; let $i = 43; $b;
        let $i = 44; $b; let $i = 45; $b; let $i = 46; $b; let $i = 47; $b;
        let $i = 48; $b; let $i = 49; $b; let $i = 50; $b; let $i = 51; $b;
        let $i = 52; $b; let $i = 53; $b; let $i = 54; $b; let $i = 55; $b;
        let $i = 56; $b; let $i = 57; $b; let $i = 58; $b; let $i = 59; $b;
        let $i = 60; $b; let $i = 61; $b; let $i = 62; $b; let $i = 63; $b;
    };
}

/// Read round constant
fn rk(i: usize) -> u32 {
    // `read_volatile` forces compiler to read round constants from the static
    // instead of inlining them, which improves codegen and performance on some platforms.
    // On x86 targets 32-bit constants can be encoded using immediate argument on the `add`
    // instruction, so it's more efficient to inline them.
    cfg_if::cfg_if! {
        if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
            use core::ptr::read as r;
        } else {
            use core::ptr::read_volatile as r;
        }
    }

    unsafe {
        let p = K32.as_ptr().add(i);
        r(p)
    }
}

/// Process a block with the SHA-256 algorithm.
fn compress_block(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut block = super::to_u32s(block);
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    repeat64!(i, {
        let w = if i < 16 {
            block[i]
        } else {
            let w15 = block[(i - 15) % 16];
            let s0 = (w15.rotate_right(7)) ^ (w15.rotate_right(18)) ^ (w15 >> 3);
            let w2 = block[(i - 2) % 16];
            let s1 = (w2.rotate_right(17)) ^ (w2.rotate_right(19)) ^ (w2 >> 10);
            block[i % 16] = block[i % 16]
                .wrapping_add(s0)
                .wrapping_add(block[(i - 7) % 16])
                .wrapping_add(s1);
            block[i % 16]
        };

        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = s1
            .wrapping_add(ch)
            .wrapping_add(rk(i))
            .wrapping_add(w)
            .wrapping_add(h);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
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
    });

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

pub(super) fn compress(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
    for block in blocks {
        compress_block(state, block);
    }
}
