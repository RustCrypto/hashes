use crate::consts::K32;

#[cfg(target_arch = "riscv32")]
use core::arch::riscv32::*;
#[cfg(target_arch = "riscv64")]
use core::arch::riscv64::*;

#[cfg(not(target_feature = "zknh"))]
compile_error!("riscv-zknh backend requires enabled zknh target feature");

#[inline(always)]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

#[inline(always)]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

/// Forcefully read the round constant to prevent its reconstruction on stack.
fn read_rk<const IDX: usize>() -> u32 {
    assert!(IDX < K32.len());
    let res;
    unsafe {
        core::arch::asm!(
            "lw {dst}, 4*{IDX}({p})",
            IDX = const IDX,
            p = in(reg) &K32,
            dst = out(reg) res,
            // note: the `pure` option is intentionally not used to prevent
            // caching of the round constant on stack
            options(preserves_flags, nostack, readonly)
        );
    }
    res
}

macro_rules! round {
    (
        $a: ident, $b: ident, $c: ident, $d: ident,
        $e: ident, $f: ident, $g: ident, $h: ident,
        $k: expr, $w: expr
    ) => {
        // SAFETY: we have checked that the zknh target feature
        // required by the intrinsics is enabled
        $h = $h
            .wrapping_add(unsafe { sha256sum1($e) })
            .wrapping_add(ch($e, $f, $g))
            .wrapping_add(read_rk::<$k>())
            .wrapping_add($w);
        $d = $d.wrapping_add($h);
        $h = $h
            .wrapping_add(unsafe { sha256sum0($a) })
            .wrapping_add(maj($a, $b, $c))
    };
}

macro_rules! schedule {
    ($m0: ident, $m1: ident, $m9: ident, $me: ident) => {
        // SAFETY: we have checked that the zknh target feature
        // required by the intrinsics is enabled
        $m0 = $m0
            .wrapping_add(unsafe { sha256sig1($me) })
            .wrapping_add($m9)
            .wrapping_add(unsafe { sha256sig0($m1) });
    };
}

fn compress_block(state: &mut [u32; 8], block: [u32; 16]) {
    #[rustfmt::skip]
    let [
        mut m0, mut m1, mut m2, mut m3, mut m4, mut m5, mut m6, mut m7,
        mut m8, mut m9, mut ma, mut mb, mut mc, mut md, mut me, mut mf,
    ] = block;
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    round!(a, b, c, d, e, f, g, h, 0, m0);
    round!(h, a, b, c, d, e, f, g, 1, m1);
    round!(g, h, a, b, c, d, e, f, 2, m2);
    round!(f, g, h, a, b, c, d, e, 3, m3);
    round!(e, f, g, h, a, b, c, d, 4, m4);
    round!(d, e, f, g, h, a, b, c, 5, m5);
    round!(c, d, e, f, g, h, a, b, 6, m6);
    round!(b, c, d, e, f, g, h, a, 7, m7);
    round!(a, b, c, d, e, f, g, h, 8, m8);
    round!(h, a, b, c, d, e, f, g, 9, m9);
    round!(g, h, a, b, c, d, e, f, 10, ma);
    round!(f, g, h, a, b, c, d, e, 11, mb);
    round!(e, f, g, h, a, b, c, d, 12, mc);
    round!(d, e, f, g, h, a, b, c, 13, md);
    round!(c, d, e, f, g, h, a, b, 14, me);
    round!(b, c, d, e, f, g, h, a, 15, mf);

    schedule!(m0, m1, m9, me);
    schedule!(m1, m2, ma, mf);
    schedule!(m2, m3, mb, m0);
    schedule!(m3, m4, mc, m1);
    schedule!(m4, m5, md, m2);
    schedule!(m5, m6, me, m3);
    schedule!(m6, m7, mf, m4);
    schedule!(m7, m8, m0, m5);
    schedule!(m8, m9, m1, m6);
    schedule!(m9, ma, m2, m7);
    schedule!(ma, mb, m3, m8);
    schedule!(mb, mc, m4, m9);
    schedule!(mc, md, m5, ma);
    schedule!(md, me, m6, mb);
    schedule!(me, mf, m7, mc);
    schedule!(mf, m0, m8, md);

    round!(a, b, c, d, e, f, g, h, 16, m0);
    round!(h, a, b, c, d, e, f, g, 17, m1);
    round!(g, h, a, b, c, d, e, f, 18, m2);
    round!(f, g, h, a, b, c, d, e, 19, m3);
    round!(e, f, g, h, a, b, c, d, 20, m4);
    round!(d, e, f, g, h, a, b, c, 21, m5);
    round!(c, d, e, f, g, h, a, b, 22, m6);
    round!(b, c, d, e, f, g, h, a, 23, m7);
    round!(a, b, c, d, e, f, g, h, 24, m8);
    round!(h, a, b, c, d, e, f, g, 25, m9);
    round!(g, h, a, b, c, d, e, f, 26, ma);
    round!(f, g, h, a, b, c, d, e, 27, mb);
    round!(e, f, g, h, a, b, c, d, 28, mc);
    round!(d, e, f, g, h, a, b, c, 29, md);
    round!(c, d, e, f, g, h, a, b, 30, me);
    round!(b, c, d, e, f, g, h, a, 31, mf);

    schedule!(m0, m1, m9, me);
    schedule!(m1, m2, ma, mf);
    schedule!(m2, m3, mb, m0);
    schedule!(m3, m4, mc, m1);
    schedule!(m4, m5, md, m2);
    schedule!(m5, m6, me, m3);
    schedule!(m6, m7, mf, m4);
    schedule!(m7, m8, m0, m5);
    schedule!(m8, m9, m1, m6);
    schedule!(m9, ma, m2, m7);
    schedule!(ma, mb, m3, m8);
    schedule!(mb, mc, m4, m9);
    schedule!(mc, md, m5, ma);
    schedule!(md, me, m6, mb);
    schedule!(me, mf, m7, mc);
    schedule!(mf, m0, m8, md);

    round!(a, b, c, d, e, f, g, h, 32, m0);
    round!(h, a, b, c, d, e, f, g, 33, m1);
    round!(g, h, a, b, c, d, e, f, 34, m2);
    round!(f, g, h, a, b, c, d, e, 35, m3);
    round!(e, f, g, h, a, b, c, d, 36, m4);
    round!(d, e, f, g, h, a, b, c, 37, m5);
    round!(c, d, e, f, g, h, a, b, 38, m6);
    round!(b, c, d, e, f, g, h, a, 39, m7);
    round!(a, b, c, d, e, f, g, h, 40, m8);
    round!(h, a, b, c, d, e, f, g, 41, m9);
    round!(g, h, a, b, c, d, e, f, 42, ma);
    round!(f, g, h, a, b, c, d, e, 43, mb);
    round!(e, f, g, h, a, b, c, d, 44, mc);
    round!(d, e, f, g, h, a, b, c, 45, md);
    round!(c, d, e, f, g, h, a, b, 46, me);
    round!(b, c, d, e, f, g, h, a, 47, mf);

    schedule!(m0, m1, m9, me);
    schedule!(m1, m2, ma, mf);
    schedule!(m2, m3, mb, m0);
    schedule!(m3, m4, mc, m1);
    schedule!(m4, m5, md, m2);
    schedule!(m5, m6, me, m3);
    schedule!(m6, m7, mf, m4);
    schedule!(m7, m8, m0, m5);
    schedule!(m8, m9, m1, m6);
    schedule!(m9, ma, m2, m7);
    schedule!(ma, mb, m3, m8);
    schedule!(mb, mc, m4, m9);
    schedule!(mc, md, m5, ma);
    schedule!(md, me, m6, mb);
    schedule!(me, mf, m7, mc);
    schedule!(mf, m0, m8, md);

    round!(a, b, c, d, e, f, g, h, 48, m0);
    round!(h, a, b, c, d, e, f, g, 49, m1);
    round!(g, h, a, b, c, d, e, f, 50, m2);
    round!(f, g, h, a, b, c, d, e, 51, m3);
    round!(e, f, g, h, a, b, c, d, 52, m4);
    round!(d, e, f, g, h, a, b, c, 53, m5);
    round!(c, d, e, f, g, h, a, b, 54, m6);
    round!(b, c, d, e, f, g, h, a, 55, m7);
    round!(a, b, c, d, e, f, g, h, 56, m8);
    round!(h, a, b, c, d, e, f, g, 57, m9);
    round!(g, h, a, b, c, d, e, f, 58, ma);
    round!(f, g, h, a, b, c, d, e, 59, mb);
    round!(e, f, g, h, a, b, c, d, 60, mc);
    round!(d, e, f, g, h, a, b, c, 61, md);
    round!(c, d, e, f, g, h, a, b, 62, me);
    round!(b, c, d, e, f, g, h, a, 63, mf);

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

pub fn compress(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
    for block_u8 in blocks {
        let mut block = [0u32; 16];
        for (dst, src) in block.iter_mut().zip(block_u8.chunks_exact(4)) {
            *dst = u32::from_be_bytes(src.try_into().unwrap());
        }
        compress_block(state, block);
    }
}
