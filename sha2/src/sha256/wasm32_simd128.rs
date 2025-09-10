#![allow(clippy::many_single_char_names, unsafe_op_in_unsafe_fn)]
use core::arch::wasm32::*;
use core::mem::size_of;

use crate::consts::K32;

pub(super) fn compress(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
    assert_eq!(SHA256_HASH_WORDS_NUM, 8);
    assert_eq!(SHA256_BLOCK_WORDS_NUM, 16);
    let mut ms = [u64x2(0, 0); 4];
    let mut x = [u64x2(0, 0); 4];

    for block in blocks {
        unsafe {
            let mut current_state = *state;
            load_data(&mut x, &mut ms, block.as_ptr().cast());
            rounds_0_47(&mut current_state, &mut x, &mut ms);
            rounds_48_63(&mut current_state, &ms);
            accumulate_state(state, &current_state);
        }
    }
}

#[inline(always)]
unsafe fn load_data(x: &mut [v128; 4], ms: &mut MsgSchedule, data: *const v128) {
    macro_rules! unrolled_iterations {
        ($($i:literal),*) => {$(
            x[$i] = v128_load(data.add($i).cast());
            x[$i] = i8x16_shuffle::<3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12>(x[$i], x[$i]);

            let y = i32x4_add(
                x[$i],
                v128_load(K32.as_ptr().add(4 * $i).cast()),
            );

            ms[$i] = y;
        )*};
    }

    unrolled_iterations!(0, 1, 2, 3);
}

#[inline(always)]
unsafe fn rounds_0_47(current_state: &mut State, x: &mut [v128; 4], ms: &mut MsgSchedule) {
    let mut k32_idx: usize = SHA256_BLOCK_WORDS_NUM;

    for _ in 0..3 {
        for j in 0..4 {
            let k32 = v128_load(K32.as_ptr().add(k32_idx).cast());
            let y = sha256_update_x(x, k32);

            {
                let ms = ms[j];
                sha_round(current_state, u32x4_extract_lane::<0>(ms));
                sha_round(current_state, u32x4_extract_lane::<1>(ms));
                sha_round(current_state, u32x4_extract_lane::<2>(ms));
                sha_round(current_state, u32x4_extract_lane::<3>(ms));
            }

            ms[j] = y;
            k32_idx += 4;
        }
    }
}

#[inline(always)]
fn rounds_48_63(current_state: &mut State, ms: &MsgSchedule) {
    for j in 0..4 {
        let ms = ms[j];
        sha_round(current_state, u32x4_extract_lane::<0>(ms));
        sha_round(current_state, u32x4_extract_lane::<1>(ms));
        sha_round(current_state, u32x4_extract_lane::<2>(ms));
        sha_round(current_state, u32x4_extract_lane::<3>(ms));
    }
}

#[inline(always)]
fn sha_round(s: &mut State, x: u32) {
    macro_rules! big_sigma0 {
        ($a:expr) => {
            $a.rotate_right(2) ^ $a.rotate_right(13) ^ $a.rotate_right(22)
        };
    }
    macro_rules! big_sigma1 {
        ($a:expr) => {
            $a.rotate_right(6) ^ $a.rotate_right(11) ^ $a.rotate_right(25)
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
    for i in 0..SHA256_HASH_WORDS_NUM {
        dst[i] = dst[i].wrapping_add(src[i]);
    }
}

#[inline(always)]
unsafe fn sha256_update_x(x: &mut [v128; 4], k32: v128) -> v128 {
    const SIGMA0_0: u32 = 7;
    const SIGMA0_1: u32 = 18;
    const SIGMA0_2: u32 = 3;
    const SIGMA1_0: u32 = 17;
    const SIGMA1_1: u32 = 19;
    const SIGMA1_2: u32 = 10;
    const SHA256_WORD_BIT_LEN: u32 = 8 * size_of::<u32>() as u32;
    const ZERO: v128 = u64x2(0, 0);

    let mut t0 = u32x4_shuffle::<1, 2, 3, 4>(x[0], x[1]);
    let mut t3 = u32x4_shuffle::<1, 2, 3, 4>(x[2], x[3]);
    let mut t2 = u32x4_shr(t0, SIGMA0_0);
    x[0] = u32x4_add(x[0], t3);
    t3 = u32x4_shr(t0, SIGMA0_2);
    let mut t1 = u32x4_shl(t0, SHA256_WORD_BIT_LEN - SIGMA0_1);
    t0 = v128_xor(t3, t2);
    t3 = u32x4_shuffle::<2, 2, 3, 3>(x[3], x[3]);
    t2 = u32x4_shr(t2, SIGMA0_1 - SIGMA0_0);
    t0 = v128_xor(t0, t1);
    t0 = v128_xor(t0, t2);
    t1 = u32x4_shl(t1, SIGMA0_1 - SIGMA0_0);
    t2 = u32x4_shr(t3, SIGMA1_2);
    t3 = u64x2_shr(t3, SIGMA1_0);
    t1 = v128_xor(t0, t1);
    x[0] = u32x4_add(x[0], t1);
    t2 = v128_xor(t2, t3);
    t3 = u64x2_shr(t3, SIGMA1_1 - SIGMA1_0);
    t2 = v128_xor(t2, t3);
    t2 = u32x4_shuffle::<0, 2, 7, 7>(t2, ZERO);
    x[0] = u32x4_add(x[0], t2);
    t3 = u32x4_shuffle::<0, 0, 1, 1>(x[0], x[0]);
    t2 = u32x4_shr(t3, SIGMA1_2);
    t3 = u64x2_shr(t3, SIGMA1_0);
    t2 = v128_xor(t2, t3);
    t3 = u64x2_shr(t3, SIGMA1_1 - SIGMA1_0);
    t2 = v128_xor(t2, t3);
    t2 = u32x4_shuffle::<7, 7, 0, 2>(t2, ZERO);
    x[0] = u32x4_add(x[0], t2);

    let tmp = x[0];
    x[0] = x[1];
    x[1] = x[2];
    x[2] = x[3];
    x[3] = tmp;

    u32x4_add(x[3], k32)
}

type State = [u32; SHA256_HASH_WORDS_NUM];
type MsgSchedule = [v128; SHA256_BLOCK_WORDS_NUM / 4];

const SHA256_BLOCK_BYTE_LEN: usize = 64;
const SHA256_HASH_BYTE_LEN: usize = 32;
const SHA256_HASH_WORDS_NUM: usize = SHA256_HASH_BYTE_LEN / size_of::<u32>();
const SHA256_BLOCK_WORDS_NUM: usize = SHA256_BLOCK_BYTE_LEN / size_of::<u32>();
