use crate::consts::K64;

#[cfg(target_arch = "riscv32")]
use core::arch::riscv32::*;
#[cfg(target_arch = "riscv64")]
use core::arch::riscv64::*;

#[cfg(not(all(
    target_feature = "zknh",
    any(target_feature = "zbb", target_feature = "zbkb")
)))]
compile_error!("riscv-zknh-compact backend requires zknh and zbkb (or zbb) target features");

#[cfg(target_arch = "riscv32")]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn sha512sum0(x: u64) -> u64 {
    let a = sha512sum0r((x >> 32) as u32, x as u32);
    let b = sha512sum0r(x as u32, (x >> 32) as u32);
    ((a as u64) << 32) | (b as u64)
}

#[cfg(target_arch = "riscv32")]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn sha512sum1(x: u64) -> u64 {
    let a = sha512sum1r((x >> 32) as u32, x as u32);
    let b = sha512sum1r(x as u32, (x >> 32) as u32);
    ((a as u64) << 32) | (b as u64)
}

#[cfg(target_arch = "riscv32")]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn sha512sig0(x: u64) -> u64 {
    let a = sha512sig0h((x >> 32) as u32, x as u32);
    let b = sha512sig0l(x as u32, (x >> 32) as u32);
    ((a as u64) << 32) | (b as u64)
}

#[cfg(target_arch = "riscv32")]
#[allow(unsafe_op_in_unsafe_fn)]
unsafe fn sha512sig1(x: u64) -> u64 {
    let a = sha512sig1h((x >> 32) as u32, x as u32);
    let b = sha512sig1l(x as u32, (x >> 32) as u32);
    ((a as u64) << 32) | (b as u64)
}

#[inline(always)]
fn ch(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (!x & z)
}

#[inline(always)]
fn maj(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline(always)]
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
        .wrapping_add(unsafe { sha512sum1(state[e]) })
        .wrapping_add(ch(state[e], state[f], state[g]))
        .wrapping_add(K64[r])
        .wrapping_add(block[r % 16]);
    state[d] = state[d].wrapping_add(state[h]);
    state[h] = state[h]
        .wrapping_add(unsafe { sha512sum0(state[a]) })
        .wrapping_add(maj(state[a], state[b], state[c]))
}

#[inline(always)]
fn schedule(block: &mut [u64; 16], r: usize) {
    block[r % 16] = block[r % 16]
        .wrapping_add(unsafe { sha512sig1(block[(r + 14) % 16]) })
        .wrapping_add(block[(r + 9) % 16])
        .wrapping_add(unsafe { sha512sig0(block[(r + 1) % 16]) });
}

#[inline(always)]
fn compress_block(state: &mut [u64; 8], mut block: [u64; 16]) {
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

pub(super) fn compress(state: &mut [u64; 8], blocks: &[[u8; 128]]) {
    for block in blocks.iter().map(super::riscv_zknh_utils::load_block) {
        compress_block(state, block);
    }
}
