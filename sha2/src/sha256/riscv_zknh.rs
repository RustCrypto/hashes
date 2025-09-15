use crate::consts::K32;

#[cfg(target_arch = "riscv32")]
use core::arch::riscv32::*;
#[cfg(target_arch = "riscv64")]
use core::arch::riscv64::*;

#[cfg(not(all(
    target_feature = "zknh",
    any(target_feature = "zbb", target_feature = "zbkb")
)))]
compile_error!("riscv-zknh backend requires zknh and zbkb (or zbb) target features");

#[inline(always)]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

#[inline(always)]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn round<const R: usize>(state: &mut [u32; 8], block: &[u32; 16], k: &[u32]) {
    let n = K32.len() - R;
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
        .wrapping_add(unsafe { sha256sum1(state[e]) })
        .wrapping_add(ch(state[e], state[f], state[g]))
        .wrapping_add(super::riscv_zknh_utils::opaque_load::<R>(k))
        .wrapping_add(block[R]);
    state[d] = state[d].wrapping_add(state[h]);
    state[h] = state[h]
        .wrapping_add(unsafe { sha256sum0(state[a]) })
        .wrapping_add(maj(state[a], state[b], state[c]))
}

fn round_schedule<const R: usize>(state: &mut [u32; 8], block: &mut [u32; 16], k: &[u32]) {
    round::<R>(state, block, k);

    block[R] = block[R]
        .wrapping_add(unsafe { sha256sig1(block[(R + 14) % 16]) })
        .wrapping_add(block[(R + 9) % 16])
        .wrapping_add(unsafe { sha256sig0(block[(R + 1) % 16]) });
}

#[inline(always)]
fn compress_block(state: &mut [u32; 8], mut block: [u32; 16]) {
    let s = &mut state.clone();
    let b = &mut block;

    for i in 0..3 {
        let k = &K32[16 * i..];
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

    let k = &K32[48..];
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

pub(super) fn compress(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
    for block in blocks.iter().map(super::riscv_zknh_utils::load_block) {
        compress_block(state, block);
    }
}
