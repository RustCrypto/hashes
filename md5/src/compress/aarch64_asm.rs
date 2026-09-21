//! Aarch64 assembly backend

use crate::consts::RC as K;

#[allow(clippy::inline_always)] // hot per-block call site; must inline into Md5::update
#[allow(clippy::too_many_lines)] // 64 unrolled MD5 rounds; splitting defeats the unroll
#[allow(clippy::many_single_char_names)] // a/b/c/d/m are standard MD5 register names
#[allow(clippy::cast_ptr_alignment)] // read_unaligned() is used immediately after the cast
#[inline(always)]
fn compress_block(state: &mut [u32; 4], block: &[u8; 64]) {
    // Per-round on-demand input loads via a closure.  Letting each round
    // pull its input word individually allows LLVM to interleave the LDR
    // with the prior round's arithmetic, hiding L1 load-use latency —
    // unlike a front-loaded `[u32; 16]` array which forces all 8 LDPs
    // to retire before round 1 starts.
    let m = block.as_ptr().cast::<u32>();
    let mi = |i: usize| -> u32 {
        // SAFETY: block is 64 bytes, i in 0..16
        u32::from_le(unsafe { m.add(i).read_unaligned() })
    };

    let (a0, b0, c0, d0) = (state[0], state[1], state[2], state[3]);
    let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);

    // Per-round `asm!` for rotate: forces LLVM to materialize the accumulator
    // in a concrete 32-bit register at each round boundary, which guides
    // register allocation more tightly than giving LLVM full freedom via
    // `rotate_left()`.  The `pure, nomem, nostack` options tell LLVM the
    // result depends only on the input, so it can still schedule the surrounding
    // arithmetic freely within each round.
    macro_rules! ror {
        ($x:expr, $r:expr) => {{
            let mut v: u32 = $x;
            unsafe {
                core::arch::asm!(
                    "ror {v:w}, {v:w}, #{n}",
                    v = inout(reg) v,
                    n = const (32u32 - $r),
                    options(pure, nomem, nostack),
                );
            }
            v
        }};
    }

    // F(b,c,d) = D ^ (B & (C^D))
    macro_rules! f {
        ($a:ident, $b:ident, $c:ident, $d:ident, $m:expr, $k:expr, $r:expr) => {
            $a = $a
                .wrapping_add($d ^ ($b & ($c ^ $d)))
                .wrapping_add($m)
                .wrapping_add($k);
            $a = ror!($a, $r).wrapping_add($b);
        };
    }
    // G(b,c,d) = (~D & C) + (D & B)   — maps to BIC + AND on AArch64
    macro_rules! g {
        ($a:ident, $b:ident, $c:ident, $d:ident, $m:expr, $k:expr, $r:expr) => {
            $a = $a
                .wrapping_add((!$d & $c).wrapping_add($d & $b))
                .wrapping_add($m)
                .wrapping_add($k);
            $a = ror!($a, $r).wrapping_add($b);
        };
    }
    // H(b,c,d) = B ^ C ^ D
    macro_rules! h {
        ($a:ident, $b:ident, $c:ident, $d:ident, $m:expr, $k:expr, $r:expr) => {
            $a = $a
                .wrapping_add($b ^ $c ^ $d)
                .wrapping_add($m)
                .wrapping_add($k);
            $a = ror!($a, $r).wrapping_add($b);
        };
    }
    // I(b,c,d) = C ^ (B | ~D)   — maps to ORN on AArch64
    macro_rules! i {
        ($a:ident, $b:ident, $c:ident, $d:ident, $m:expr, $k:expr, $r:expr) => {
            $a = $a
                .wrapping_add($c ^ ($b | !$d))
                .wrapping_add($m)
                .wrapping_add($k);
            $a = ror!($a, $r).wrapping_add($b);
        };
    }

    f!(a, b, c, d, mi(0), K[0], 7);
    f!(d, a, b, c, mi(1), K[1], 12);
    f!(c, d, a, b, mi(2), K[2], 17);
    f!(b, c, d, a, mi(3), K[3], 22);
    f!(a, b, c, d, mi(4), K[4], 7);
    f!(d, a, b, c, mi(5), K[5], 12);
    f!(c, d, a, b, mi(6), K[6], 17);
    f!(b, c, d, a, mi(7), K[7], 22);
    f!(a, b, c, d, mi(8), K[8], 7);
    f!(d, a, b, c, mi(9), K[9], 12);
    f!(c, d, a, b, mi(10), K[10], 17);
    f!(b, c, d, a, mi(11), K[11], 22);
    f!(a, b, c, d, mi(12), K[12], 7);
    f!(d, a, b, c, mi(13), K[13], 12);
    f!(c, d, a, b, mi(14), K[14], 17);
    f!(b, c, d, a, mi(15), K[15], 22);

    g!(a, b, c, d, mi(1), K[16], 5);
    g!(d, a, b, c, mi(6), K[17], 9);
    g!(c, d, a, b, mi(11), K[18], 14);
    g!(b, c, d, a, mi(0), K[19], 20);
    g!(a, b, c, d, mi(5), K[20], 5);
    g!(d, a, b, c, mi(10), K[21], 9);
    g!(c, d, a, b, mi(15), K[22], 14);
    g!(b, c, d, a, mi(4), K[23], 20);
    g!(a, b, c, d, mi(9), K[24], 5);
    g!(d, a, b, c, mi(14), K[25], 9);
    g!(c, d, a, b, mi(3), K[26], 14);
    g!(b, c, d, a, mi(8), K[27], 20);
    g!(a, b, c, d, mi(13), K[28], 5);
    g!(d, a, b, c, mi(2), K[29], 9);
    g!(c, d, a, b, mi(7), K[30], 14);
    g!(b, c, d, a, mi(12), K[31], 20);

    h!(a, b, c, d, mi(5), K[32], 4);
    h!(d, a, b, c, mi(8), K[33], 11);
    h!(c, d, a, b, mi(11), K[34], 16);
    h!(b, c, d, a, mi(14), K[35], 23);
    h!(a, b, c, d, mi(1), K[36], 4);
    h!(d, a, b, c, mi(4), K[37], 11);
    h!(c, d, a, b, mi(7), K[38], 16);
    h!(b, c, d, a, mi(10), K[39], 23);
    h!(a, b, c, d, mi(13), K[40], 4);
    h!(d, a, b, c, mi(0), K[41], 11);
    h!(c, d, a, b, mi(3), K[42], 16);
    h!(b, c, d, a, mi(6), K[43], 23);
    h!(a, b, c, d, mi(9), K[44], 4);
    h!(d, a, b, c, mi(12), K[45], 11);
    h!(c, d, a, b, mi(15), K[46], 16);
    h!(b, c, d, a, mi(2), K[47], 23);

    i!(a, b, c, d, mi(0), K[48], 6);
    i!(d, a, b, c, mi(7), K[49], 10);
    i!(c, d, a, b, mi(14), K[50], 15);
    i!(b, c, d, a, mi(5), K[51], 21);
    i!(a, b, c, d, mi(12), K[52], 6);
    i!(d, a, b, c, mi(3), K[53], 10);
    i!(c, d, a, b, mi(10), K[54], 15);
    i!(b, c, d, a, mi(1), K[55], 21);
    i!(a, b, c, d, mi(8), K[56], 6);
    i!(d, a, b, c, mi(15), K[57], 10);
    i!(c, d, a, b, mi(6), K[58], 15);
    i!(b, c, d, a, mi(13), K[59], 21);
    i!(a, b, c, d, mi(4), K[60], 6);
    i!(d, a, b, c, mi(11), K[61], 10);
    i!(c, d, a, b, mi(2), K[62], 15);
    i!(b, c, d, a, mi(9), K[63], 21);

    state[0] = a0.wrapping_add(a);
    state[1] = b0.wrapping_add(b);
    state[2] = c0.wrapping_add(c);
    state[3] = d0.wrapping_add(d);
}

#[inline]
pub(super) fn compress(state: &mut [u32; 4], blocks: &[[u8; 64]]) {
    for block in blocks {
        compress_block(state, block);
    }
}
