//! RISC-V backend which uses the Zknh extension and fully unrolls round loop.
//!
//! Generated assembly:
//! RV32: https://rust.godbolt.org/z/jv9jxqs9n
//! RV64: https://rust.godbolt.org/z/E6M7b9zWx
use super::{sha256sig0, sha256sig1, sha256sum0, sha256sum1};
use crate::consts::K32;

#[target_feature(enable = "zknh")]
pub(crate) fn compress(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
    for block in blocks {
        compress_block(state, block);
    }
}

#[inline]
#[target_feature(enable = "zknh")]
fn compress_block(state: &mut [u32; 8], block: &[u8; 64]) {
    let s = &mut state.clone();
    let msg = &mut [0u32; 16];

    load_round::<0x00>(s, block, msg);
    load_round::<0x01>(s, block, msg);
    load_round::<0x02>(s, block, msg);
    load_round::<0x03>(s, block, msg);
    load_round::<0x04>(s, block, msg);
    load_round::<0x05>(s, block, msg);
    load_round::<0x06>(s, block, msg);
    load_round::<0x07>(s, block, msg);
    load_round::<0x08>(s, block, msg);
    load_round::<0x09>(s, block, msg);
    load_round::<0x0a>(s, block, msg);
    load_round::<0x0b>(s, block, msg);
    load_round::<0x0c>(s, block, msg);
    load_round::<0x0d>(s, block, msg);
    load_round::<0x0e>(s, block, msg);
    load_round::<0x0f>(s, block, msg);

    schedule_round::<0x10>(s, msg);
    schedule_round::<0x11>(s, msg);
    schedule_round::<0x12>(s, msg);
    schedule_round::<0x13>(s, msg);
    schedule_round::<0x14>(s, msg);
    schedule_round::<0x15>(s, msg);
    schedule_round::<0x16>(s, msg);
    schedule_round::<0x17>(s, msg);
    schedule_round::<0x18>(s, msg);
    schedule_round::<0x19>(s, msg);
    schedule_round::<0x1a>(s, msg);
    schedule_round::<0x1b>(s, msg);
    schedule_round::<0x1c>(s, msg);
    schedule_round::<0x1d>(s, msg);
    schedule_round::<0x1e>(s, msg);
    schedule_round::<0x1f>(s, msg);

    schedule_round::<0x20>(s, msg);
    schedule_round::<0x21>(s, msg);
    schedule_round::<0x22>(s, msg);
    schedule_round::<0x23>(s, msg);
    schedule_round::<0x24>(s, msg);
    schedule_round::<0x25>(s, msg);
    schedule_round::<0x26>(s, msg);
    schedule_round::<0x27>(s, msg);
    schedule_round::<0x28>(s, msg);
    schedule_round::<0x29>(s, msg);
    schedule_round::<0x2a>(s, msg);
    schedule_round::<0x2b>(s, msg);
    schedule_round::<0x2c>(s, msg);
    schedule_round::<0x2d>(s, msg);
    schedule_round::<0x2e>(s, msg);
    schedule_round::<0x2f>(s, msg);

    schedule_round::<0x30>(s, msg);
    schedule_round::<0x31>(s, msg);
    schedule_round::<0x32>(s, msg);
    schedule_round::<0x33>(s, msg);
    schedule_round::<0x34>(s, msg);
    schedule_round::<0x35>(s, msg);
    schedule_round::<0x36>(s, msg);
    schedule_round::<0x37>(s, msg);
    schedule_round::<0x38>(s, msg);
    schedule_round::<0x39>(s, msg);
    schedule_round::<0x3a>(s, msg);
    schedule_round::<0x3b>(s, msg);
    schedule_round::<0x3c>(s, msg);
    schedule_round::<0x3d>(s, msg);
    schedule_round::<0x3e>(s, msg);
    schedule_round::<0x3f>(s, msg);

    state[0] = state[0].wrapping_add(s[0]);
    state[1] = state[1].wrapping_add(s[1]);
    state[2] = state[2].wrapping_add(s[2]);
    state[3] = state[3].wrapping_add(s[3]);
    state[4] = state[4].wrapping_add(s[4]);
    state[5] = state[5].wrapping_add(s[5]);
    state[6] = state[6].wrapping_add(s[6]);
    state[7] = state[7].wrapping_add(s[7]);
}

#[inline]
#[target_feature(enable = "zknh")]
fn load_round<const R: usize>(state: &mut [u32; 8], block: &[u8; 64], msg: &mut [u32; 16]) {
    let chunk = block.as_chunks().0[R];
    let w = u32::from_be_bytes(chunk);
    msg[R] = w;
    round::<R>(state, w);
}

#[inline]
#[target_feature(enable = "zknh")]
fn schedule_round<const R: usize>(state: &mut [u32; 8], msg: &mut [u32; 16]) {
    let w = msg[R % 16]
        .wrapping_add(sha256sig1(msg[(R + 14) % 16]))
        .wrapping_add(msg[(R + 9) % 16])
        .wrapping_add(sha256sig0(msg[(R + 1) % 16]));
    msg[R % 16] = w;
    round::<R>(state, w);
}

#[inline]
#[target_feature(enable = "zknh")]
fn round<const R: usize>(state: &mut [u32; 8], w: u32) {
    let [a, b, c, d, e, f, g, h] = *state;

    let s1 = sha256sum1(e);
    let ch = (e & f) ^ ((!e) & g);
    let t1 = add_rk::<R>(s1)
        .wrapping_add(ch)
        .wrapping_add(w)
        .wrapping_add(h);
    let s0 = sha256sum0(a);
    let maj = (a & b) ^ (a & c) ^ (b & c);
    let t2 = s0.wrapping_add(maj);

    *state = [t1.wrapping_add(t2), a, b, c, d.wrapping_add(t1), e, f, g];
}

// We intentionally add round constant instead of simply loading it
// to prevent the compiler from applying unnecessary optimizations
#[inline(always)]
fn add_rk<const R: usize>(mut w: u32) -> u32 {
    const { assert!(R < K32.len()) };

    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!(
            "lwu {rk}, 4*{R}({rk_ptr})",
            "addw {w}, {w}, {rk}",
            R = const R,
            rk_ptr = in(reg) K32.as_ptr(),
            rk = out(reg) _,
            w = inout(reg) w,
            options(pure, readonly, nostack, preserves_flags),
        );
    }

    #[cfg(target_arch = "riscv32")]
    unsafe {
        core::arch::asm!(
            "lw {rk}, 4*{R}({rk_ptr})",
            "add {w}, {w}, {rk}",
            R = const R,
            rk_ptr = in(reg) K32.as_ptr(),
            rk = out(reg) _,
            w = inout(reg) w,
            options(pure, readonly, nostack, preserves_flags),
        );
    }

    w
}
