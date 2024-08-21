use crate::consts::K64;

#[cfg(target_arch = "riscv32")]
use core::arch::riscv32::*;
#[cfg(target_arch = "riscv64")]
use core::arch::riscv64::*;

#[cfg(not(target_feature = "zknh"))]
compile_error!("riscv-zknh backend requires enabled zknh target feature");

#[cfg(target_arch = "riscv32")]
unsafe fn sha512sum0(x: u64) -> u64 {
    let a = sha512sum0r((x >> 32) as u32, x as u32);
    let b = sha512sum0r(x as u32, (x >> 32) as u32);
    ((a as u64) << 32) | (b as u64)
}

#[cfg(target_arch = "riscv32")]
unsafe fn sha512sum1(x: u64) -> u64 {
    let a = sha512sum1r((x >> 32) as u32, x as u32);
    let b = sha512sum1r(x as u32, (x >> 32) as u32);
    ((a as u64) << 32) | (b as u64)
}

#[cfg(target_arch = "riscv32")]
unsafe fn sha512sig0(x: u64) -> u64 {
    let a = sha512sig0h((x >> 32) as u32, x as u32);
    let b = sha512sig0l(x as u32, (x >> 32) as u32);
    ((a as u64) << 32) | (b as u64)
}

#[cfg(target_arch = "riscv32")]
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

fn round<const R: usize>(state: &mut [u64; 8], block: &[u64; 16]) {
    let n = K64.len() - R;
    let a = n % 8;
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
        // Force reading of constants from the static to prevent bad codegen
        .wrapping_add(unsafe { core::ptr::read_volatile(&K64[R]) })
        .wrapping_add(block[R % 16]);
    state[d] = state[d].wrapping_add(state[h]);
    state[h] = state[h]
        .wrapping_add(unsafe { sha512sum0(state[a]) })
        .wrapping_add(maj(state[a], state[b], state[c]))
}

fn round_schedule<const R: usize>(state: &mut [u64; 8], block: &mut [u64; 16]) {
    round::<R>(state, block);

    block[R % 16] = block[R % 16]
        .wrapping_add(unsafe { sha512sig1(block[(R + 14) % 16]) })
        .wrapping_add(block[(R + 9) % 16])
        .wrapping_add(unsafe { sha512sig0(block[(R + 1) % 16]) });
}

fn compress_block(state: &mut [u64; 8], mut block: [u64; 16]) {
    let s = &mut state.clone();
    let b = &mut block;

    round_schedule::<0>(s, b);
    round_schedule::<1>(s, b);
    round_schedule::<2>(s, b);
    round_schedule::<3>(s, b);
    round_schedule::<4>(s, b);
    round_schedule::<5>(s, b);
    round_schedule::<6>(s, b);
    round_schedule::<7>(s, b);
    round_schedule::<8>(s, b);
    round_schedule::<9>(s, b);
    round_schedule::<10>(s, b);
    round_schedule::<11>(s, b);
    round_schedule::<12>(s, b);
    round_schedule::<13>(s, b);
    round_schedule::<14>(s, b);
    round_schedule::<15>(s, b);
    round_schedule::<16>(s, b);
    round_schedule::<17>(s, b);
    round_schedule::<18>(s, b);
    round_schedule::<19>(s, b);
    round_schedule::<20>(s, b);
    round_schedule::<21>(s, b);
    round_schedule::<22>(s, b);
    round_schedule::<23>(s, b);
    round_schedule::<24>(s, b);
    round_schedule::<25>(s, b);
    round_schedule::<26>(s, b);
    round_schedule::<27>(s, b);
    round_schedule::<28>(s, b);
    round_schedule::<29>(s, b);
    round_schedule::<30>(s, b);
    round_schedule::<31>(s, b);
    round_schedule::<32>(s, b);
    round_schedule::<33>(s, b);
    round_schedule::<34>(s, b);
    round_schedule::<35>(s, b);
    round_schedule::<36>(s, b);
    round_schedule::<37>(s, b);
    round_schedule::<38>(s, b);
    round_schedule::<39>(s, b);
    round_schedule::<40>(s, b);
    round_schedule::<41>(s, b);
    round_schedule::<42>(s, b);
    round_schedule::<43>(s, b);
    round_schedule::<44>(s, b);
    round_schedule::<45>(s, b);
    round_schedule::<46>(s, b);
    round_schedule::<47>(s, b);
    round_schedule::<48>(s, b);
    round_schedule::<49>(s, b);
    round_schedule::<50>(s, b);
    round_schedule::<51>(s, b);
    round_schedule::<52>(s, b);
    round_schedule::<53>(s, b);
    round_schedule::<54>(s, b);
    round_schedule::<55>(s, b);
    round_schedule::<56>(s, b);
    round_schedule::<57>(s, b);
    round_schedule::<58>(s, b);
    round_schedule::<59>(s, b);
    round_schedule::<60>(s, b);
    round_schedule::<61>(s, b);
    round_schedule::<62>(s, b);
    round_schedule::<63>(s, b);
    round::<64>(s, b);
    round::<65>(s, b);
    round::<66>(s, b);
    round::<67>(s, b);
    round::<68>(s, b);
    round::<69>(s, b);
    round::<70>(s, b);
    round::<71>(s, b);
    round::<72>(s, b);
    round::<73>(s, b);
    round::<74>(s, b);
    round::<75>(s, b);
    round::<76>(s, b);
    round::<77>(s, b);
    round::<78>(s, b);
    round::<79>(s, b);

    for i in 0..8 {
        state[i] = state[i].wrapping_add(s[i]);
    }
}

pub fn compress(state: &mut [u64; 8], blocks: &[[u8; 128]]) {
    for block in blocks.iter().map(super::to_u64s) {
        compress_block(state, block);
    }
}
