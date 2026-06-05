use super::{sha512sig0, sha512sig1, sha512sum0, sha512sum1};
use crate::consts::K64;

#[target_feature(enable = "zknh")]
pub(super) fn compress_block(state: &mut [u64; 8], mut block: [u64; 16]) {
    let s = &mut state.clone();
    let b = &mut block;

    for i in 0..4 {
        let k = &K64[16 * i..];
        round_schedule::<0>(s, b, k);
        round_schedule::<1>(s, b, k);
        round_schedule::<2>(s, b, k);
        round_schedule::<3>(s, b, k);
        round_schedule::<4>(s, b, k);
        round_schedule::<5>(s, b, k);
        round_schedule::<6>(s, b, k);
        round_schedule::<7>(s, b, k);
        round_schedule::<8>(s, b, k);
        round_schedule::<9>(s, b, k);
        round_schedule::<10>(s, b, k);
        round_schedule::<11>(s, b, k);
        round_schedule::<12>(s, b, k);
        round_schedule::<13>(s, b, k);
        round_schedule::<14>(s, b, k);
        round_schedule::<15>(s, b, k);
    }

    let k = &K64[64..];
    round::<0>(s, b, k);
    round::<1>(s, b, k);
    round::<2>(s, b, k);
    round::<3>(s, b, k);
    round::<4>(s, b, k);
    round::<5>(s, b, k);
    round::<6>(s, b, k);
    round::<7>(s, b, k);
    round::<8>(s, b, k);
    round::<9>(s, b, k);
    round::<10>(s, b, k);
    round::<11>(s, b, k);
    round::<12>(s, b, k);
    round::<13>(s, b, k);
    round::<14>(s, b, k);
    round::<15>(s, b, k);

    for i in 0..8 {
        state[i] = state[i].wrapping_add(s[i]);
    }
}

#[target_feature(enable = "zknh")]
fn round_schedule<const R: usize>(state: &mut [u64; 8], block: &mut [u64; 16], k: &[u64]) {
    round::<R>(state, block, k);

    block[R] = block[R]
        .wrapping_add(sha512sig1(block[(R + 14) % 16]))
        .wrapping_add(block[(R + 9) % 16])
        .wrapping_add(sha512sig0(block[(R + 1) % 16]));
}

#[target_feature(enable = "zknh")]
fn round<const R: usize>(state: &mut [u64; 8], block: &[u64; 16], k: &[u64]) {
    let n = K64.len() - R;
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
        .wrapping_add(opaque_load::<R>(k))
        .wrapping_add(block[R]);
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
