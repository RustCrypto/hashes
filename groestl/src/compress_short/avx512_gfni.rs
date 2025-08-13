#![allow(unsafe_code)]

use core::mem::MaybeUninit;

#[cfg(target_arch = "x86")]
use core::arch::x86;

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64 as x86;

use x86::{
    __m512i, _mm512_gf2p8affineinv_epi64_epi8, _mm512_gf2p8mul_epi8, _mm512_loadu_si512,
    _mm512_permutexvar_epi8, _mm512_permutexvar_epi64, _mm512_rorv_epi64, _mm512_set_epi64,
    _mm512_set1_epi64, _mm512_setr_epi64, _mm512_storeu_si512, _mm512_xor_si512,
};

#[inline(always)]
unsafe fn mix_bytes(x: __m512i) -> __m512i {
    unsafe {
        const ROW2: i64 = 0x0202020202020202;
        const ROW3: i64 = 0x0303030303030303;
        const ROW4: i64 = 0x0404040404040404;
        const ROW5: i64 = 0x0505050505050505;
        const ROW7: i64 = 0x0707070707070707;

        let wide0 = _mm512_permutexvar_epi64(_mm512_set1_epi64(0), x);
        let wide1 = _mm512_permutexvar_epi64(_mm512_set1_epi64(1), x);
        let wide2 = _mm512_permutexvar_epi64(_mm512_set1_epi64(2), x);
        let wide3 = _mm512_permutexvar_epi64(_mm512_set1_epi64(3), x);
        let wide4 = _mm512_permutexvar_epi64(_mm512_set1_epi64(4), x);
        let wide5 = _mm512_permutexvar_epi64(_mm512_set1_epi64(5), x);
        let wide6 = _mm512_permutexvar_epi64(_mm512_set1_epi64(6), x);
        let wide7 = _mm512_permutexvar_epi64(_mm512_set1_epi64(7), x);

        _mm512_xor_si512(
            _mm512_xor_si512(
                _mm512_xor_si512(
                    _mm512_gf2p8mul_epi8(
                        wide0,
                        _mm512_setr_epi64(ROW2, ROW7, ROW5, ROW3, ROW5, ROW4, ROW3, ROW2),
                    ),
                    _mm512_gf2p8mul_epi8(
                        wide1,
                        _mm512_setr_epi64(ROW2, ROW2, ROW7, ROW5, ROW3, ROW5, ROW4, ROW3),
                    ),
                ),
                _mm512_xor_si512(
                    _mm512_gf2p8mul_epi8(
                        wide2,
                        _mm512_setr_epi64(ROW3, ROW2, ROW2, ROW7, ROW5, ROW3, ROW5, ROW4),
                    ),
                    _mm512_gf2p8mul_epi8(
                        wide3,
                        _mm512_setr_epi64(ROW4, ROW3, ROW2, ROW2, ROW7, ROW5, ROW3, ROW5),
                    ),
                ),
            ),
            _mm512_xor_si512(
                _mm512_xor_si512(
                    _mm512_gf2p8mul_epi8(
                        wide4,
                        _mm512_setr_epi64(ROW5, ROW4, ROW3, ROW2, ROW2, ROW7, ROW5, ROW3),
                    ),
                    _mm512_gf2p8mul_epi8(
                        wide5,
                        _mm512_setr_epi64(ROW3, ROW5, ROW4, ROW3, ROW2, ROW2, ROW7, ROW5),
                    ),
                ),
                _mm512_xor_si512(
                    _mm512_gf2p8mul_epi8(
                        wide6,
                        _mm512_setr_epi64(ROW5, ROW3, ROW5, ROW4, ROW3, ROW2, ROW2, ROW7),
                    ),
                    _mm512_gf2p8mul_epi8(
                        wide7,
                        _mm512_setr_epi64(ROW7, ROW5, ROW3, ROW5, ROW4, ROW3, ROW2, ROW2),
                    ),
                ),
            ),
        )
    }
}

#[inline(always)]
unsafe fn round256<const R: u8, const P: bool>(x: __m512i) -> __m512i {
    unsafe {
        // AddRoundConstant
        let rc = 0x7060504030201000u64 | (0x0101010101010101u64 * (R as u64));
        let x = _mm512_xor_si512(
            x,
            if P {
                _mm512_setr_epi64(rc as i64, 0, 0, 0, 0, 0, 0, 0)
            } else {
                _mm512_set_epi64(!rc as i64, -1, -1, -1, -1, -1, -1, -1)
            },
        );

        // SubBytes (Rijndael S-box)
        let x = _mm512_gf2p8affineinv_epi64_epi8(
            x,
            _mm512_set1_epi64(0xF1E3C78F1F3E7CF8u64 as i64),
            0b01100011,
        );

        // ShiftBytes
        let x = _mm512_rorv_epi64(
            x,
            if P {
                _mm512_setr_epi64(0, 8, 16, 24, 32, 40, 48, 56)
            } else {
                _mm512_setr_epi64(8, 24, 40, 56, 0, 16, 32, 48)
            },
        );

        // MixBytes
        mix_bytes(x)
    }
}

#[inline(always)]
unsafe fn transpose(x: __m512i) -> __m512i {
    unsafe {
        _mm512_permutexvar_epi8(
            _mm512_setr_epi64(
                0x3830282018100800,
                0x3931292119110901,
                0x3A322A221A120A02,
                0x3B332B231B130B03,
                0x3C342C241C140C04,
                0x3D352D251D150D05,
                0x3E362E261E160E06,
                0x3F372F271F170F07,
            ),
            x,
        )
    }
}

#[inline(always)]
unsafe fn transpose_byteswap(x: __m512i) -> __m512i {
    unsafe {
        // Equivalent to converting 64-bit integers to big-endian, then transposing
        _mm512_permutexvar_epi8(
            _mm512_setr_epi64(
                0x3f372f271f170f07,
                0x3e362e261e160e06,
                0x3d352d251d150d05,
                0x3c342c241c140c04,
                0x3b332b231b130b03,
                0x3a322a221a120a02,
                0x3931292119110901,
                0x3830282018100800,
            ),
            x,
        )
    }
}

#[inline(always)]
unsafe fn byteswap_transpose(x: __m512i) -> __m512i {
    unsafe {
        // Equivalent to transposing, then converting 64-bit integers to big-endian
        _mm512_permutexvar_epi8(
            _mm512_setr_epi64(
                0x0008101820283038,
                0x0109111921293139,
                0x020a121a222a323a,
                0x030b131b232b333b,
                0x040c141c242c343c,
                0x050d151d252d353d,
                0x060e161e262e363e,
                0x070f171f272f373f,
            ),
            x,
        )
    }
}

#[inline(always)]
unsafe fn permute256<const P: bool>(x: __m512i) -> __m512i {
    unsafe {
        let x = round256::<0, P>(x);
        let x = round256::<1, P>(x);
        let x = round256::<2, P>(x);
        let x = round256::<3, P>(x);
        let x = round256::<4, P>(x);
        let x = round256::<5, P>(x);
        let x = round256::<6, P>(x);
        let x = round256::<7, P>(x);
        let x = round256::<8, P>(x);
        round256::<9, P>(x)
    }
}

#[inline(always)]
unsafe fn compress256(h: __m512i, m: &[u8; 64]) -> __m512i {
    unsafe {
        let m = transpose(_mm512_loadu_si512(m.as_ptr() as *const __m512i));
        _mm512_xor_si512(
            _mm512_xor_si512(
                permute256::<true>(_mm512_xor_si512(h, m)),
                permute256::<false>(m),
            ),
            h,
        )
    }
}

#[target_feature(enable = "avx,avx512f,gfni,avx512vbmi")]
pub(crate) unsafe fn compress(h: &mut [u64; super::COLS], blocks: &[[u8; 64]]) {
    unsafe {
        debug_assert_eq!(super::COLS * 64, 512);

        let mut h_ = transpose_byteswap(_mm512_loadu_si512(h.as_ptr() as *const __m512i));
        for m in blocks {
            h_ = compress256(h_, m);
        }
        let h_ = byteswap_transpose(h_);
        _mm512_storeu_si512(h.as_mut_ptr() as *mut __m512i, h_);
    }
}

#[target_feature(enable = "avx,avx512f,gfni,avx512vbmi")]
pub(crate) unsafe fn p(h: &[u64; super::COLS]) -> [u64; super::COLS] {
    unsafe {
        debug_assert_eq!(super::COLS * 64, 512);

        let h_ = transpose_byteswap(_mm512_loadu_si512(h.as_ptr() as *const __m512i));
        let p = permute256::<true>(h_);
        let h_ = byteswap_transpose(_mm512_xor_si512(h_, p));
        let mut h = MaybeUninit::uninit();
        _mm512_storeu_si512(h.as_mut_ptr() as *mut __m512i, h_);
        h.assume_init()
    }
}
