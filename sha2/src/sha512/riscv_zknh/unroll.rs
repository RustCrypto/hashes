//! RISC-V backend which uses the Zknh extension and fully unrolls round loop.
//!
//! Generated assembly:
//! RV32: https://rust.godbolt.org/z/8v9x5fo8q
//! RV64: https://rust.godbolt.org/z/3nffnb15T
use super::{sha512sig0, sha512sig1, sha512sum0, sha512sum1};
use crate::consts::K64;

#[target_feature(enable = "zknh")]
pub(crate) fn compress(state: &mut [u64; 8], blocks: &[[u8; 128]]) {
    for block in blocks {
        compress_block(state, block);
    }
}

#[inline(always)]
#[target_feature(enable = "zknh")]
fn compress_block(state: &mut [u64; 8], block: &[u8; 128]) {
    let s = &mut state.clone();
    let msg = &mut [0u64; 16];

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

    schedule_round::<0x40>(s, msg);
    schedule_round::<0x41>(s, msg);
    schedule_round::<0x42>(s, msg);
    schedule_round::<0x43>(s, msg);
    schedule_round::<0x44>(s, msg);
    schedule_round::<0x45>(s, msg);
    schedule_round::<0x46>(s, msg);
    schedule_round::<0x47>(s, msg);
    schedule_round::<0x48>(s, msg);
    schedule_round::<0x49>(s, msg);
    schedule_round::<0x4a>(s, msg);
    schedule_round::<0x4b>(s, msg);
    schedule_round::<0x4c>(s, msg);
    schedule_round::<0x4d>(s, msg);
    schedule_round::<0x4e>(s, msg);
    schedule_round::<0x4f>(s, msg);

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
fn load_round<const R: usize>(state: &mut [u64; 8], block: &[u8; 128], msg: &mut [u64; 16]) {
    let chunk = block.as_chunks().0[R];
    let w = u64::from_be_bytes(chunk);
    msg[R] = w;
    round::<R>(state, w);
}

#[inline]
#[target_feature(enable = "zknh")]
fn schedule_round<const R: usize>(state: &mut [u64; 8], msg: &mut [u64; 16]) {
    let w = msg[R % 16]
        .wrapping_add(sha512sig1(msg[(R + 14) % 16]))
        .wrapping_add(msg[(R + 9) % 16])
        .wrapping_add(sha512sig0(msg[(R + 1) % 16]));
    msg[R % 16] = w;
    round::<R>(state, w);
}

#[inline]
#[target_feature(enable = "zknh")]
fn round<const R: usize>(state: &mut [u64; 8], w: u64) {
    let [a, b, c, d, e, f, g, h] = *state;

    let s1 = sha512sum1(e);
    let ch = (e & f) ^ ((!e) & g);
    let t1 = add_rk::<R>(s1)
        .wrapping_add(ch)
        .wrapping_add(w)
        .wrapping_add(h);
    let s0 = sha512sum0(a);
    let maj = (a & b) ^ (a & c) ^ (b & c);
    let t2 = s0.wrapping_add(maj);

    state[7] = g;
    state[6] = f;
    state[5] = e;
    state[4] = d.wrapping_add(t1);
    state[3] = c;
    state[2] = b;
    state[1] = a;
    state[0] = t1.wrapping_add(t2);
}

// We intentionally add round constant instead of simply loading it
// to prevent the compiler from applying unnecessary optimizations
#[inline(always)]
fn add_rk<const R: usize>(mut w: u64) -> u64 {
    const { assert!(R < K64.len()) };

    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!(
            "ld {rk}, 8*{R}({rk_ptr})",
            "add {w}, {w}, {rk}",
            R = const R,
            rk_ptr = in(reg) K64.as_ptr(),
            rk = out(reg) _,
            w = inout(reg) w,
            options(pure, readonly, nostack, preserves_flags),
        );
    }

    #[cfg(target_arch = "riscv32")]
    unsafe {
        let mut w_lo = w as u32;
        let mut w_hi = (w >> 32) as u32;

        core::arch::asm!(
            "lw {rk_lo}, 8 * {R}({rk_ptr})",
            "lw {rk_hi}, 8 * {R} + 4({rk_ptr})",

            "add {w_lo}, {w_lo}, {rk_lo}",
            "sltu {rk_lo}, {w_lo}, {rk_lo}",
            "add {w_hi}, {w_hi}, {rk_hi}",
            "add {w_hi}, {w_hi}, {rk_lo}",
            R = const R,
            rk_ptr = in(reg) K64.as_ptr(),
            rk_lo = out(reg) _,
            rk_hi = out(reg) _,
            w_lo = out(reg) w_lo,
            w_hi = inout(reg) w_hi,
            options(pure, readonly, nostack, preserves_flags),
        );
        w = (u64::from(w_hi) << 32) | u64::from(w_lo);
    }
    w
}
