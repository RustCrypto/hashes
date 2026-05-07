//! SHA-256 `x86`/`x86_64` backend

#![allow(clippy::many_single_char_names, unsafe_op_in_unsafe_fn)]

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
compile_error!("x86-sha backend can be used only on x86 and x86_64 target arches");

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

#[target_feature(enable = "sha")]
unsafe fn rounds4(r: usize, abef: &mut __m128i, cdgh: &mut __m128i, rest: __m128i) {
    use crate::consts::K32;
    let rk = _mm_set_epi32(
        K32[4 * r + 3] as i32,
        K32[4 * r + 2] as i32,
        K32[4 * r + 1] as i32,
        K32[4 * r] as i32,
    );
    let t1 = _mm_add_epi32(rest, rk);
    *cdgh = _mm_sha256rnds2_epu32(*cdgh, *abef, t1);
    let t2 = _mm_shuffle_epi32(t1, 0x0E);
    *abef = _mm_sha256rnds2_epu32(*abef, *cdgh, t2);
}

#[target_feature(enable = "sha,ssse3")]
unsafe fn schedule_rounds16(
    r: usize,
    abef: &mut __m128i,
    cdgh: &mut __m128i,
    w: &mut [__m128i; 4],
) {
    for i in 0..4 {
        let w0 = w[i];
        let w1 = w[(i + 1) % 4];
        let w2 = w[(i + 2) % 4];
        let w3 = w[(i + 3) % 4];

        let t1 = _mm_sha256msg1_epu32(w0, w1);
        let t2 = _mm_alignr_epi8(w3, w2, 4);
        let t3 = _mm_add_epi32(t1, t2);

        w[i] = _mm_sha256msg2_epu32(t3, w3);

        rounds4(r + i, abef, cdgh, w[i]);
    }
}

#[target_feature(enable = "ssse3")]
unsafe fn read_block(block: &[u8; 64]) -> [__m128i; 4] {
    let block_ptr: *const __m128i = block.as_ptr().cast();
    let mask = _mm_set_epi64x(0x0C0D_0E0F_0809_0A0B, 0x0405_0607_0001_0203);
    core::array::from_fn(|i| {
        let w = _mm_loadu_si128(block_ptr.add(i));
        _mm_shuffle_epi8(w, mask)
    })
}

#[target_feature(enable = "sha,sse4.1")]
pub(super) unsafe fn compress(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
    let state_ptr: *mut __m128i = state.as_mut_ptr().cast();
    let dcba = _mm_loadu_si128(state_ptr.add(0));
    let hgfe = _mm_loadu_si128(state_ptr.add(1));

    let cdab = _mm_shuffle_epi32(dcba, 0xB1);
    let efgh = _mm_shuffle_epi32(hgfe, 0x1B);
    let mut abef = _mm_alignr_epi8(cdab, efgh, 8);
    let mut cdgh = _mm_blend_epi16(efgh, cdab, 0xF0);

    for block in blocks {
        let abef_save = abef;
        let cdgh_save = cdgh;

        let mut w = read_block(block);

        rounds4(0, &mut abef, &mut cdgh, w[0]);
        rounds4(1, &mut abef, &mut cdgh, w[1]);
        rounds4(2, &mut abef, &mut cdgh, w[2]);
        rounds4(3, &mut abef, &mut cdgh, w[3]);

        schedule_rounds16(4, &mut abef, &mut cdgh, &mut w);
        schedule_rounds16(8, &mut abef, &mut cdgh, &mut w);
        schedule_rounds16(12, &mut abef, &mut cdgh, &mut w);

        abef = _mm_add_epi32(abef, abef_save);
        cdgh = _mm_add_epi32(cdgh, cdgh_save);
    }

    let feba = _mm_shuffle_epi32(abef, 0x1B);
    let dchg = _mm_shuffle_epi32(cdgh, 0xB1);
    let dcba = _mm_blend_epi16(feba, dchg, 0xF0);
    let hgef = _mm_alignr_epi8(dchg, feba, 8);

    _mm_storeu_si128(state_ptr.add(0), dcba);
    _mm_storeu_si128(state_ptr.add(1), hgef);
}
