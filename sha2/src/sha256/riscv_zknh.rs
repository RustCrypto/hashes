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

#[allow(clippy::identity_op)]
fn round<const R: usize>(state: &mut [u32; 8], block: &[u32; 16]) {
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
        // Force reading of constants from the static to prevent bad codegen
        .wrapping_add(unsafe { core::ptr::read_volatile(&K32[R]) })
        .wrapping_add(block[R % 16]);
    state[d] = state[d].wrapping_add(state[h]);
    state[h] = state[h]
        .wrapping_add(unsafe { sha256sum0(state[a]) })
        .wrapping_add(maj(state[a], state[b], state[c]))
}

fn round_schedule<const R: usize>(state: &mut [u32; 8], block: &mut [u32; 16]) {
    round::<R>(state, block);

    block[R % 16] = block[R % 16]
        .wrapping_add(unsafe { sha256sig1(block[(R + 14) % 16]) })
        .wrapping_add(block[(R + 9) % 16])
        .wrapping_add(unsafe { sha256sig0(block[(R + 1) % 16]) });
}

fn compress_block(state: &mut [u32; 8], mut block: [u32; 16]) {
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
    round::<48>(s, b);
    round::<49>(s, b);
    round::<50>(s, b);
    round::<51>(s, b);
    round::<52>(s, b);
    round::<53>(s, b);
    round::<54>(s, b);
    round::<55>(s, b);
    round::<56>(s, b);
    round::<57>(s, b);
    round::<58>(s, b);
    round::<59>(s, b);
    round::<60>(s, b);
    round::<61>(s, b);
    round::<62>(s, b);
    round::<63>(s, b);

    for i in 0..8 {
        state[i] = state[i].wrapping_add(s[i]);
    }
}

pub fn compress(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
    for block in blocks.iter().map(super::to_u32s) {
        compress_block(state, block);
    }
}
