use crate::consts::K32;

#[cfg(target_arch = "riscv32")]
use core::arch::riscv32::*;
#[cfg(target_arch = "riscv64")]
use core::arch::riscv64::*;

#[cfg(not(all(
    target_feature = "zknh",
    any(target_feature = "zbb", target_feature = "zbkb")
)))]
compile_error!("riscv-zknh-compact backend requires zknh and zbkb (or zbb) target features");

#[inline(always)]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

#[inline(always)]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline(always)]
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
        .wrapping_add(unsafe { sha256sum1(state[e]) })
        .wrapping_add(ch(state[e], state[f], state[g]))
        .wrapping_add(K32[r])
        .wrapping_add(block[r % 16]);
    state[d] = state[d].wrapping_add(state[h]);
    state[h] = state[h]
        .wrapping_add(unsafe { sha256sum0(state[a]) })
        .wrapping_add(maj(state[a], state[b], state[c]))
}

#[inline(always)]
fn schedule(block: &mut [u32; 16], r: usize) {
    block[r % 16] = block[r % 16]
        .wrapping_add(unsafe { sha256sig1(block[(r + 14) % 16]) })
        .wrapping_add(block[(r + 9) % 16])
        .wrapping_add(unsafe { sha256sig0(block[(r + 1) % 16]) });
}

#[inline(always)]
fn compress_block(state: &mut [u32; 8], mut block: [u32; 16]) {
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

pub(super) fn compress(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
    for block in blocks.iter().map(super::riscv_zknh_utils::load_block) {
        compress_block(state, block);
    }
}
