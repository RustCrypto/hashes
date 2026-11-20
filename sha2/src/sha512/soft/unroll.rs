//! Portable software backend.
//!
//! Generated assembly: https://rust.godbolt.org/z/9aP1xEvP4
use super::{ch, maj, sig0, sig1, sum0, sum1};
use crate::consts::K64;

pub(crate) fn compress(state: &mut [u64; 8], blocks: &[[u8; 128]]) {
    for block in blocks {
        compress_block(state, block);
    }
}

#[inline(always)]
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
fn load_round<const R: usize>(state: &mut [u64; 8], block: &[u8; 128], msg: &mut [u64; 16]) {
    let chunk = block.as_chunks().0[R];
    let w = u64::from_be_bytes(chunk);
    msg[R] = w;
    round::<R>(state, w);
}

#[inline]
fn schedule_round<const R: usize>(state: &mut [u64; 8], msg: &mut [u64; 16]) {
    let w = msg[R % 16]
        .wrapping_add(sig1(msg[(R + 14) % 16]))
        .wrapping_add(msg[(R + 9) % 16])
        .wrapping_add(sig0(msg[(R + 1) % 16]));
    msg[R % 16] = w;
    round::<R>(state, w);
}

#[inline]
fn round<const R: usize>(state: &mut [u64; 8], w: u64) {
    let [a, b, c, d, e, f, g, h] = *state;

    let t1 = sum1(e)
        .wrapping_add(load_rk::<R>())
        .wrapping_add(ch(e, f, g))
        .wrapping_add(w)
        .wrapping_add(h);
    let t2 = sum0(a).wrapping_add(maj(a, b, c));

    state[7] = g;
    state[6] = f;
    state[5] = e;
    state[4] = d.wrapping_add(t1);
    state[3] = c;
    state[2] = b;
    state[1] = a;
    state[0] = t1.wrapping_add(t2);
}

#[inline(always)]
fn load_rk<const R: usize>() -> u64 {
    // `read_volatile` forces the compiler to read round constants from the static
    // instead of unnecessarily inlining values or materializaing them on the stack.
    // It generally results in a smaller binary and improves performance.
    const { assert!(R < K64.len()) };
    unsafe { core::ptr::read_volatile(K64.as_ptr().add(R)) }
}
