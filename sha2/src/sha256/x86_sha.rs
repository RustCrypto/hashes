//! SHA-256 `x86`/`x86_64` backend

#![allow(clippy::many_single_char_names, unsafe_op_in_unsafe_fn)]

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
compile_error!("x86-sha backend can be used only on x86 and x86_64 target arches");

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
unsafe fn schedule(v0: __m128i, v1: __m128i, v2: __m128i, v3: __m128i) -> __m128i {
    let t1 = _mm_sha256msg1_epu32(v0, v1);
    let t2 = _mm_alignr_epi8(v3, v2, 4);
    let t3 = _mm_add_epi32(t1, t2);
    _mm_sha256msg2_epu32(t3, v3)
}

#[inline(always)]
unsafe fn rounds4<const I: usize>(abef: &mut __m128i, cdgh: &mut __m128i, rest: __m128i) {
    let k = crate::consts::K32X4[I];
    let kv = _mm_set_epi32(k[0] as i32, k[1] as i32, k[2] as i32, k[3] as i32);
    let t1 = _mm_add_epi32(rest, kv);
    *cdgh = _mm_sha256rnds2_epu32(*cdgh, *abef, t1);
    let t2 = _mm_shuffle_epi32(t1, 0x0E);
    *abef = _mm_sha256rnds2_epu32(*abef, *cdgh, t2);
}

#[inline(always)]
unsafe fn schedule_rounds4<const I: usize>(
    abef: &mut __m128i,
    cdgh: &mut __m128i,
    w0: __m128i,
    w1: __m128i,
    w2: __m128i,
    w3: __m128i,
) -> __m128i {
    let w4 = schedule(w0, w1, w2, w3);
    rounds4::<I>(abef, cdgh, w4);
    w4
}

// we use unaligned loads with `__m128i` pointers
#[allow(clippy::cast_ptr_alignment)]
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
pub(super) unsafe fn compress(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
    #[allow(non_snake_case)]
    let MASK: __m128i = _mm_set_epi64x(
        0x0C0D_0E0F_0809_0A0Bu64 as i64,
        0x0405_0607_0001_0203u64 as i64,
    );

    let state_ptr: *const __m128i = state.as_ptr().cast();
    let dcba = _mm_loadu_si128(state_ptr.add(0));
    let hgfe = _mm_loadu_si128(state_ptr.add(1));

    let cdab = _mm_shuffle_epi32(dcba, 0xB1);
    let efgh = _mm_shuffle_epi32(hgfe, 0x1B);
    let mut abef = _mm_alignr_epi8(cdab, efgh, 8);
    let mut cdgh = _mm_blend_epi16(efgh, cdab, 0xF0);

    for block in blocks {
        let abef_save = abef;
        let cdgh_save = cdgh;

        let block_ptr: *const __m128i = block.as_ptr().cast();
        let mut w0 = _mm_shuffle_epi8(_mm_loadu_si128(block_ptr.add(0)), MASK);
        let mut w1 = _mm_shuffle_epi8(_mm_loadu_si128(block_ptr.add(1)), MASK);
        let mut w2 = _mm_shuffle_epi8(_mm_loadu_si128(block_ptr.add(2)), MASK);
        let mut w3 = _mm_shuffle_epi8(_mm_loadu_si128(block_ptr.add(3)), MASK);
        let mut w4;

        rounds4::<0>(&mut abef, &mut cdgh, w0);
        rounds4::<1>(&mut abef, &mut cdgh, w1);
        rounds4::<2>(&mut abef, &mut cdgh, w2);
        rounds4::<3>(&mut abef, &mut cdgh, w3);
        w4 = schedule_rounds4::<4>(&mut abef, &mut cdgh, w0, w1, w2, w3);
        w0 = schedule_rounds4::<5>(&mut abef, &mut cdgh, w1, w2, w3, w4);
        w1 = schedule_rounds4::<6>(&mut abef, &mut cdgh, w2, w3, w4, w0);
        w2 = schedule_rounds4::<7>(&mut abef, &mut cdgh, w3, w4, w0, w1);
        w3 = schedule_rounds4::<8>(&mut abef, &mut cdgh, w4, w0, w1, w2);
        w4 = schedule_rounds4::<9>(&mut abef, &mut cdgh, w0, w1, w2, w3);
        w0 = schedule_rounds4::<10>(&mut abef, &mut cdgh, w1, w2, w3, w4);
        w1 = schedule_rounds4::<11>(&mut abef, &mut cdgh, w2, w3, w4, w0);
        w2 = schedule_rounds4::<12>(&mut abef, &mut cdgh, w3, w4, w0, w1);
        w3 = schedule_rounds4::<13>(&mut abef, &mut cdgh, w4, w0, w1, w2);
        w4 = schedule_rounds4::<14>(&mut abef, &mut cdgh, w0, w1, w2, w3);
        let _ = schedule_rounds4::<15>(&mut abef, &mut cdgh, w1, w2, w3, w4);

        abef = _mm_add_epi32(abef, abef_save);
        cdgh = _mm_add_epi32(cdgh, cdgh_save);
    }

    let feba = _mm_shuffle_epi32(abef, 0x1B);
    let dchg = _mm_shuffle_epi32(cdgh, 0xB1);
    let dcba = _mm_blend_epi16(feba, dchg, 0xF0);
    let hgef = _mm_alignr_epi8(dchg, feba, 8);

    let state_ptr_mut: *mut __m128i = state.as_mut_ptr().cast();
    _mm_storeu_si128(state_ptr_mut.add(0), dcba);
    _mm_storeu_si128(state_ptr_mut.add(1), hgef);
}
