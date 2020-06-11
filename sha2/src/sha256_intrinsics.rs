#![allow(clippy::cast_ptr_alignment)] // Safe to cast without alignment checks as the loads and stores do not require alignment.

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

/// Process a block with the SHA-256 algorithm.
/// Based on https://github.com/noloader/SHA-Intrinsics/blob/master/sha256-x86.c
#[inline]
pub unsafe fn compress256(state: &mut [u32; 8], block: &[u8; 64]) {
    // TODO: Process multiple blocks

    let mut state0: __m128i;
    let mut state1: __m128i;

    let mut msg: __m128i;
    let mut tmp: __m128i;

    let mut msg0: __m128i;
    let mut msg1: __m128i;
    let mut msg2: __m128i;
    let mut msg3: __m128i;

    let mut abef_save: __m128i;
    let mut cdgh_save: __m128i;

    #[allow(non_snake_case)]
    let MASK: __m128i = _mm_set_epi64x(
        0x0c0d_0e0f_0809_0a0bu64 as i64,
        0x0405_0607_0001_0203u64 as i64,
    );

    let mut block_offset = 0;
    let mut length = 64;

    // Load initial values
    tmp = _mm_loadu_si128(state.as_ptr().add(0) as *const __m128i);
    state1 = _mm_loadu_si128(state.as_ptr().add(4) as *const __m128i);

    tmp = _mm_shuffle_epi32(tmp, 0xB1); // CDAB
    state1 = _mm_shuffle_epi32(state1, 0x1B); // EFGH
    state0 = _mm_alignr_epi8(tmp, state1, 8); // ABEF
    state1 = _mm_blend_epi16(state1, tmp, 0xF0); // CDGH

    while length >= 64 {
        // Save current state
        abef_save = state0;
        cdgh_save = state1;

        // Rounds 0-3
        msg = _mm_loadu_si128(block.as_ptr().add(block_offset) as *const __m128i);
        msg0 = _mm_shuffle_epi8(msg, MASK);
        msg = _mm_add_epi32(
            msg0,
            _mm_set_epi64x(0xE9B5DBA5B5C0FBCFu64 as i64, 0x71374491428A2F98u64 as i64),
        );
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

        // Rounds 4-7
        msg1 = _mm_loadu_si128(block.as_ptr().add(block_offset + 16) as *const __m128i);
        msg1 = _mm_shuffle_epi8(msg1, MASK);
        msg = _mm_add_epi32(
            msg1,
            _mm_set_epi64x(0xAB1C5ED5923F82A4u64 as i64, 0x59F111F13956C25Bu64 as i64),
        );
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg0 = _mm_sha256msg1_epu32(msg0, msg1);

        // Rounds 8-11
        msg2 = _mm_loadu_si128(block.as_ptr().add(block_offset + 32) as *const __m128i);
        msg2 = _mm_shuffle_epi8(msg2, MASK);
        msg = _mm_add_epi32(
            msg2,
            _mm_set_epi64x(0x550C7DC3243185BEu64 as i64, 0x12835B01D807AA98u64 as i64),
        );
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg1 = _mm_sha256msg1_epu32(msg1, msg2);

        // Rounds 12-15
        msg3 = _mm_loadu_si128(block.as_ptr().add(block_offset + 48) as *const __m128i);
        msg3 = _mm_shuffle_epi8(msg3, MASK);
        msg = _mm_add_epi32(
            msg3,
            _mm_set_epi64x(0xC19BF1749BDC06A7u64 as i64, 0x80DEB1FE72BE5D74u64 as i64),
        );
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg3, msg2, 4);
        msg0 = _mm_add_epi32(msg0, tmp);
        msg0 = _mm_sha256msg2_epu32(msg0, msg3);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg2 = _mm_sha256msg1_epu32(msg2, msg3);

        // Rounds 16-19
        msg = _mm_add_epi32(
            msg0,
            _mm_set_epi64x(0x240CA1CC0FC19DC6u64 as i64, 0xEFBE4786E49B69C1u64 as i64),
        );
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg0, msg3, 4);
        msg1 = _mm_add_epi32(msg1, tmp);
        msg1 = _mm_sha256msg2_epu32(msg1, msg0);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg3 = _mm_sha256msg1_epu32(msg3, msg0);

        // Rounds 20-23
        msg = _mm_add_epi32(
            msg1,
            _mm_set_epi64x(0x76F988DA5CB0A9DCu64 as i64, 0x4A7484AA2DE92C6Fu64 as i64),
        );
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg1, msg0, 4);
        msg2 = _mm_add_epi32(msg2, tmp);
        msg2 = _mm_sha256msg2_epu32(msg2, msg1);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg0 = _mm_sha256msg1_epu32(msg0, msg1);

        // Rounds 24-27
        msg = _mm_add_epi32(
            msg2,
            _mm_set_epi64x(0xBF597FC7B00327C8u64 as i64, 0xA831C66D983E5152u64 as i64),
        );
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg2, msg1, 4);
        msg3 = _mm_add_epi32(msg3, tmp);
        msg3 = _mm_sha256msg2_epu32(msg3, msg2);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg1 = _mm_sha256msg1_epu32(msg1, msg2);

        // Rounds 28-31
        msg = _mm_add_epi32(
            msg3,
            _mm_set_epi64x(0x1429296706CA6351u64 as i64, 0xD5A79147C6E00BF3u64 as i64),
        );
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg3, msg2, 4);
        msg0 = _mm_add_epi32(msg0, tmp);
        msg0 = _mm_sha256msg2_epu32(msg0, msg3);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg2 = _mm_sha256msg1_epu32(msg2, msg3);

        // Rounds 32-35
        msg = _mm_add_epi32(
            msg0,
            _mm_set_epi64x(0x53380D134D2C6DFCu64 as i64, 0x2E1B213827B70A85u64 as i64),
        );
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg0, msg3, 4);
        msg1 = _mm_add_epi32(msg1, tmp);
        msg1 = _mm_sha256msg2_epu32(msg1, msg0);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg3 = _mm_sha256msg1_epu32(msg3, msg0);

        // Rounds 36-39
        msg = _mm_add_epi32(
            msg1,
            _mm_set_epi64x(0x92722C8581C2C92Eu64 as i64, 0x766A0ABB650A7354u64 as i64),
        );
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg1, msg0, 4);
        msg2 = _mm_add_epi32(msg2, tmp);
        msg2 = _mm_sha256msg2_epu32(msg2, msg1);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg0 = _mm_sha256msg1_epu32(msg0, msg1);

        // Rounds 40-43
        msg = _mm_add_epi32(
            msg2,
            _mm_set_epi64x(0xC76C51A3C24B8B70u64 as i64, 0xA81A664BA2BFE8A1u64 as i64),
        );
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg2, msg1, 4);
        msg3 = _mm_add_epi32(msg3, tmp);
        msg3 = _mm_sha256msg2_epu32(msg3, msg2);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg1 = _mm_sha256msg1_epu32(msg1, msg2);

        // Rounds 44-47
        msg = _mm_add_epi32(
            msg3,
            _mm_set_epi64x(0x106AA070F40E3585u64 as i64, 0xD6990624D192E819u64 as i64),
        );
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg3, msg2, 4);
        msg0 = _mm_add_epi32(msg0, tmp);
        msg0 = _mm_sha256msg2_epu32(msg0, msg3);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg2 = _mm_sha256msg1_epu32(msg2, msg3);

        // Rounds 48-51
        msg = _mm_add_epi32(
            msg0,
            _mm_set_epi64x(0x34B0BCB52748774Cu64 as i64, 0x1E376C0819A4C116u64 as i64),
        );
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg0, msg3, 4);
        msg1 = _mm_add_epi32(msg1, tmp);
        msg1 = _mm_sha256msg2_epu32(msg1, msg0);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg3 = _mm_sha256msg1_epu32(msg3, msg0);

        // Rounds 52-55
        msg = _mm_add_epi32(
            msg1,
            _mm_set_epi64x(0x682E6FF35B9CCA4Fu64 as i64, 0x4ED8AA4A391C0CB3u64 as i64),
        );
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg1, msg0, 4);
        msg2 = _mm_add_epi32(msg2, tmp);
        msg2 = _mm_sha256msg2_epu32(msg2, msg1);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

        // Rounds 56-59
        msg = _mm_add_epi32(
            msg2,
            _mm_set_epi64x(0x8CC7020884C87814u64 as i64, 0x78A5636F748F82EEu64 as i64),
        );
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg2, msg1, 4);
        msg3 = _mm_add_epi32(msg3, tmp);
        msg3 = _mm_sha256msg2_epu32(msg3, msg2);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

        // Rounds 60-63
        msg = _mm_add_epi32(
            msg3,
            _mm_set_epi64x(0xC67178F2BEF9A3F7u64 as i64, 0xA4506CEB90BEFFFAu64 as i64),
        );
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

        // Combine state
        state0 = _mm_add_epi32(state0, abef_save);
        state1 = _mm_add_epi32(state1, cdgh_save);

        block_offset += 64;
        length -= 64;
    }

    tmp = _mm_shuffle_epi32(state0, 0x1B); // FEBA
    state1 = _mm_shuffle_epi32(state1, 0xB1); // DCHG
    state0 = _mm_blend_epi16(tmp, state1, 0xF0); // DCBA
    state1 = _mm_alignr_epi8(state1, tmp, 8); // ABEF

    // Save state
    _mm_storeu_si128(state.as_mut_ptr().add(0) as *mut __m128i, state0);
    _mm_storeu_si128(state.as_mut_ptr().add(4) as *mut __m128i, state1);
}
