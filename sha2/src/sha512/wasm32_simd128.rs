#![allow(clippy::many_single_char_names, unsafe_op_in_unsafe_fn)]

use core::arch::wasm32::*;
use core::mem::size_of;

use crate::consts::K64;

pub(super) fn compress(state: &mut [u64; 8], blocks: &[[u8; 128]]) {
    let mut ms = [u64x2(0, 0); 8];
    let mut x = [u64x2(0, 0); 8];

    for block in blocks {
        unsafe {
            let mut current_state = *state;
            load_data(&mut x, &mut ms, block.as_ptr().cast());
            rounds_0_63(&mut current_state, &mut x, &mut ms);
            rounds_64_79(&mut current_state, &ms);
            accumulate_state(state, &current_state);
        }
    }
}

#[inline(always)]
unsafe fn load_data(x: &mut [v128; 8], ms: &mut MsgSchedule, data: *const v128) {
    macro_rules! unrolled_iterations {
        ($($i:literal),*) => {$(
            x[$i] = v128_load(data.add($i).cast());
            x[$i] = i8x16_shuffle::<7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8>(x[$i], x[$i]);

            let y = i64x2_add(
                x[$i],
                v128_load(K64.as_ptr().add(2 * $i).cast()),
            );

            ms[$i] = y;
        )*};
    }

    unrolled_iterations!(0, 1, 2, 3, 4, 5, 6, 7);
}

#[inline(always)]
unsafe fn rounds_0_63(current_state: &mut State, x: &mut [v128; 8], ms: &mut MsgSchedule) {
    let mut k64_idx: usize = SHA512_BLOCK_WORDS_NUM;

    for _ in 0..4 {
        for j in 0..8 {
            let k64 = v128_load(K64.as_ptr().add(k64_idx).cast());
            let y = sha512_update_x(x, k64);

            {
                let ms = ms[j];
                sha_round(current_state, u64x2_extract_lane::<0>(ms));
                sha_round(current_state, u64x2_extract_lane::<1>(ms));
            }

            ms[j] = y;
            k64_idx += 2;
        }
    }
}

#[inline(always)]
fn rounds_64_79(current_state: &mut State, ms: &MsgSchedule) {
    for j in 0..8 {
        let ms = ms[j];
        sha_round(current_state, u64x2_extract_lane::<0>(ms));
        sha_round(current_state, u64x2_extract_lane::<1>(ms));
    }
}

#[inline(always)]
fn sha_round(s: &mut State, x: u64) {
    macro_rules! big_sigma0 {
        ($a:expr) => {
            $a.rotate_right(28) ^ $a.rotate_right(34) ^ $a.rotate_right(39)
        };
    }
    macro_rules! big_sigma1 {
        ($a:expr) => {
            $a.rotate_right(14) ^ $a.rotate_right(18) ^ $a.rotate_right(41)
        };
    }
    macro_rules! bool3ary_202 {
        ($a:expr, $b:expr, $c:expr) => {
            $c ^ ($a & ($b ^ $c))
        };
    } // Choose, MD5F, SHA1C
    macro_rules! bool3ary_232 {
        ($a:expr, $b:expr, $c:expr) => {
            ($a & $b) ^ ($a & $c) ^ ($b & $c)
        };
    } // Majority, SHA1M

    macro_rules! rotate_state {
        ($s:ident) => {{
            let tmp = $s[7];
            $s[7] = $s[6];
            $s[6] = $s[5];
            $s[5] = $s[4];
            $s[4] = $s[3];
            $s[3] = $s[2];
            $s[2] = $s[1];
            $s[1] = $s[0];
            $s[0] = tmp;
        }};
    }

    let t = x
        .wrapping_add(s[7])
        .wrapping_add(big_sigma1!(s[4]))
        .wrapping_add(bool3ary_202!(s[4], s[5], s[6]));

    s[7] = t
        .wrapping_add(big_sigma0!(s[0]))
        .wrapping_add(bool3ary_232!(s[0], s[1], s[2]));
    s[3] = s[3].wrapping_add(t);

    rotate_state!(s);
}

#[inline(always)]
fn accumulate_state(dst: &mut State, src: &State) {
    for i in 0..SHA512_HASH_WORDS_NUM {
        dst[i] = dst[i].wrapping_add(src[i]);
    }
}

#[inline(always)]
unsafe fn sha512_update_x(x: &mut [v128; 8], k64: v128) -> v128 {
    let mut t0 = u64x2_shuffle::<1, 2>(x[0], x[1]);
    let mut t3 = u64x2_shuffle::<1, 2>(x[4], x[5]);
    let mut t2 = u64x2_shr(t0, 1);
    x[0] = i64x2_add(x[0], t3);
    t3 = u64x2_shr(t0, 7);
    let mut t1 = u64x2_shl(t0, 64 - 8);
    t0 = v128_xor(t3, t2);
    t2 = u64x2_shr(t2, 8 - 1);
    t0 = v128_xor(t0, t1);
    t1 = u64x2_shl(t1, 8 - 1);
    t0 = v128_xor(t0, t2);
    t0 = v128_xor(t0, t1);
    t3 = u64x2_shr(x[7], 6);
    t2 = u64x2_shl(x[7], 64 - 61);
    x[0] = i64x2_add(x[0], t0);
    t1 = u64x2_shr(x[7], 19);
    t3 = v128_xor(t3, t2);
    t2 = u64x2_shl(t2, 61 - 19);
    t3 = v128_xor(t3, t1);
    t1 = u64x2_shr(t1, 61 - 19);
    t3 = v128_xor(t3, t2);
    t3 = v128_xor(t3, t1);
    x[0] = i64x2_add(x[0], t3);
    let temp = x[0];
    x[0] = x[1];
    x[1] = x[2];
    x[2] = x[3];
    x[3] = x[4];
    x[4] = x[5];
    x[5] = x[6];
    x[6] = x[7];
    x[7] = temp;
    i64x2_add(x[7], k64)
}

type State = [u64; SHA512_HASH_WORDS_NUM];
type MsgSchedule = [v128; SHA512_BLOCK_WORDS_NUM / 2];

const SHA512_BLOCK_BYTE_LEN: usize = 128;
const SHA512_HASH_BYTE_LEN: usize = 64;
const SHA512_HASH_WORDS_NUM: usize = SHA512_HASH_BYTE_LEN / size_of::<u64>();
const SHA512_BLOCK_WORDS_NUM: usize = SHA512_BLOCK_BYTE_LEN / size_of::<u64>();
