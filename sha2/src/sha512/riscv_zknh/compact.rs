use super::{sha512sig0, sha512sig1, sha512sum0, sha512sum1};
use crate::consts::K64;

#[target_feature(enable = "zknh")]
pub(super) fn compress_block(state: &mut [u64; 8], mut block: [u64; 16]) {
    let mut s = *state;

    for r in 0..80 {
        round(&mut s, &block, r);
        if r < 64 {
            schedule(&mut block, r)
        }
    }

    for i in 0..8 {
        state[i] = state[i].wrapping_add(s[i]);
    }
}

#[target_feature(enable = "zknh")]
fn schedule(block: &mut [u64; 16], r: usize) {
    block[r % 16] = block[r % 16]
        .wrapping_add(sha512sig1(block[(r + 14) % 16]))
        .wrapping_add(block[(r + 9) % 16])
        .wrapping_add(sha512sig0(block[(r + 1) % 16]));
}

#[target_feature(enable = "zknh")]
fn round(state: &mut [u64; 8], block: &[u64; 16], r: usize) {
    let n = K64.len() - r;
    #[allow(clippy::identity_op)]
    let a = (n + 0) % 8;
    let b = (n + 1) % 8;
    let c = (n + 2) % 8;
    let d = (n + 3) % 8;
    let e = (n + 4) % 8;
    let f = (n + 5) % 8;
    let g = (n + 6) % 8;
    let h = (n + 7) % 8;

    state[h] = state[h]
        .wrapping_add(sha512sum1(state[e]))
        .wrapping_add(ch(state[e], state[f], state[g]))
        .wrapping_add(K64[r])
        .wrapping_add(block[r % 16]);
    state[d] = state[d].wrapping_add(state[h]);
    state[h] = state[h]
        .wrapping_add(sha512sum0(state[a]))
        .wrapping_add(maj(state[a], state[b], state[c]))
}

#[inline(always)]
fn ch(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (!x & z)
}

#[inline(always)]
fn maj(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (x & z) ^ (y & z)
}

/// This function returns `k[R]`, but prevents compiler from inlining the indexed value
fn opaque_load<const R: usize>(k: &[u64]) -> u64 {
    assert!(R < k.len());
    #[cfg(target_arch = "riscv64")]
    unsafe {
        let dst;
        core::arch::asm!(
            "ld {dst}, 8 * {R}({k})",
            R = const R,
            k = in(reg) k.as_ptr(),
            dst = out(reg) dst,
            options(pure, readonly, nostack, preserves_flags),
        );
        dst
    }
    #[cfg(target_arch = "riscv32")]
    unsafe {
        let [hi, lo]: [u32; 2];
        core::arch::asm!(
            "lw {lo}, 8 * {R}({k})",
            "lw {hi}, 8 * {R} + 4({k})",
            R = const R,
            k = in(reg) k.as_ptr(),
            lo = out(reg) lo,
            hi = out(reg) hi,
            options(pure, readonly, nostack, preserves_flags),
        );
        ((hi as u64) << 32) | (lo as u64)
    }
}
