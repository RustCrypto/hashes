use super::{sha256sig0, sha256sig1, sha256sum0, sha256sum1};
use crate::consts::K32;

#[target_feature(enable = "zknh")]
pub(super) fn compress_block(state: &mut [u32; 8], mut block: [u32; 16]) {
    let mut s = *state;

    for r in 0..64 {
        round(&mut s, &block, r);
        if r < 48 {
            schedule(&mut block, r)
        }
    }

    for i in 0..8 {
        state[i] = state[i].wrapping_add(s[i]);
    }
}

#[target_feature(enable = "zknh")]
fn schedule(block: &mut [u32; 16], r: usize) {
    block[r % 16] = block[r % 16]
        .wrapping_add(sha256sig1(block[(r + 14) % 16]))
        .wrapping_add(block[(r + 9) % 16])
        .wrapping_add(sha256sig0(block[(r + 1) % 16]));
}

#[target_feature(enable = "zknh")]
fn round(state: &mut [u32; 8], block: &[u32; 16], r: usize) {
    let n = K32.len() - r;
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
        .wrapping_add(sha256sum1(state[e]))
        .wrapping_add(ch(state[e], state[f], state[g]))
        .wrapping_add(K32[r])
        .wrapping_add(block[r % 16]);
    state[d] = state[d].wrapping_add(state[h]);
    state[h] = state[h]
        .wrapping_add(sha256sum0(state[a]))
        .wrapping_add(maj(state[a], state[b], state[c]))
}

#[inline(always)]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

#[inline(always)]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

/// This function returns `k[R]`, but prevents the compiler from inlining the indexed value
pub(super) fn opaque_load<const R: usize>(k: &[u32]) -> u32 {
    assert!(R < k.len());
    let dst;

    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!(
            "lwu {dst}, 4*{R}({k})",
            R = const R,
            k = in(reg) k.as_ptr(),
            dst = out(reg) dst,
            options(pure, readonly, nostack, preserves_flags),
        );
    }

    #[cfg(target_arch = "riscv32")]
    unsafe {
        core::arch::asm!(
            "lwu {dst}, 4*{R}({k})",
            R = const R,
            k = in(reg) k.as_ptr(),
            dst = out(reg) dst,
            options(pure, readonly, nostack, preserves_flags),
        );
    }

    dst
}
