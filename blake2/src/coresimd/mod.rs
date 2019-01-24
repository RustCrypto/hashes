use as_bytes::Safe;

pub trait Vector4 {}

#[cfg(target_feature = "sse2")]
mod sse2 {
    use core::ops::BitXor;
    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;

    #[cfg(not(target_feature = "avx2"))]
    use core::mem;

    #[cfg(not(target_feature = "avx2"))]
    #[allow(non_camel_case_types)]
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct u64x4(__m128i, __m128i);

    #[cfg(not(target_feature = "avx2"))]
    impl u64x4 {
        #[inline(always)]
        pub fn new(a: u64, b: u64, c: u64, d: u64) -> Self {
            unsafe { u64x4(_mm_set_epi64x(b as i64, a as i64), _mm_set_epi64x(d as i64, c as i64)) }
        }

        #[inline(always)]
        pub fn gather(src: &[u64], i0: usize, i1: usize, i2: usize, i3: usize) -> Self {
            Self::new(src[i0], src[i1], src[i2], src[i3])
        }

        #[inline(always)]
        pub fn shuffle_left_1(mut self) -> Self {
            unsafe {
                let epi: &mut [u64; 4] = mem::transmute(&mut self);
                let tmp = epi[0];
                epi[0] = epi[1];
                epi[1] = epi[2];
                epi[2] = epi[3];
                epi[3] = tmp;
                self
            }
        }

        #[inline(always)]
        pub fn shuffle_left_2(self) -> Self { u64x4(self.1, self.0) }

        #[inline(always)]
        pub fn shuffle_left_3(mut self) -> Self {
            unsafe {
                let epi: &mut [u64; 4] = mem::transmute(&mut self);
                let tmp = epi[3];
                epi[3] = epi[2];
                epi[2] = epi[1];
                epi[1] = epi[0];
                epi[0] = tmp;
                self
            }
        }

        #[cfg(not(target_feature = "ssse3"))]
        #[inline(always)]
        pub fn rotate_right_const(self, i: u32) -> Self {
            unsafe {
                match i {
                    16 => u64x4(
                        _mm_or_si128(_mm_slli_epi64(self.0, 48), _mm_srli_epi64(self.0, 16)),
                        _mm_or_si128(_mm_slli_epi64(self.1, 48), _mm_srli_epi64(self.1, 16)),
                    ),
                    24 => u64x4(
                        _mm_or_si128(_mm_slli_epi64(self.0, 40), _mm_srli_epi64(self.0, 24)),
                        _mm_or_si128(_mm_slli_epi64(self.1, 40), _mm_srli_epi64(self.1, 24)),
                    ),
                    32 => u64x4(_mm_shuffle_epi32(self.0, 0b10110001), _mm_shuffle_epi32(self.1, 0b10110001)),
                    63 => u64x4(
                        _mm_or_si128(_mm_slli_epi64(self.0, 1), _mm_srli_epi64(self.0, 63)),
                        _mm_or_si128(_mm_slli_epi64(self.1, 1), _mm_srli_epi64(self.1, 63)),
                    ),
                    _ => unreachable!(),
                }
            }
        }

        #[cfg(target_feature = "ssse3")]
        #[inline(always)]
        pub fn rotate_right_const(self, i: u32) -> Self {
            unsafe {
                let b16 = _mm_set_epi64x(0x09080f0e_0d0c0b0a, 0x01000706_05040302);
                let b24 = _mm_set_epi64x(0x0a09080f_0e0d0c0b, 0x02010007_06050403);
                match i {
                    16 => u64x4(_mm_shuffle_epi8(self.0, b16), _mm_shuffle_epi8(self.1, b16)),
                    24 => u64x4(_mm_shuffle_epi8(self.0, b24), _mm_shuffle_epi8(self.1, b24)),
                    32 => u64x4(_mm_shuffle_epi32(self.0, 0b10110001), _mm_shuffle_epi32(self.1, 0b10110001)),
                    63 => u64x4(
                        _mm_or_si128(_mm_slli_epi64(self.0, 1), _mm_srli_epi64(self.0, 63)),
                        _mm_or_si128(_mm_slli_epi64(self.1, 1), _mm_srli_epi64(self.1, 63)),
                    ),
                    _ => unreachable!(),
                }
            }
        }

        #[inline(always)] pub fn wrapping_add(self, rhs: Self) -> Self {
            unsafe { u64x4(_mm_add_epi64(self.0, rhs.0), _mm_add_epi64(self.1, rhs.1)) }
        }

        #[inline(always)] pub fn to_le(self) -> Self { self }
        #[inline(always)] pub fn from_le(self) -> Self { self }
    }

    #[cfg(not(target_feature = "avx2"))]
    impl BitXor for u64x4 {
        type Output = Self;
        #[inline(always)]
        fn bitxor(self, rhs: Self) -> Self::Output {
            unsafe { u64x4(_mm_xor_si128(self.0, rhs.0), _mm_xor_si128(self.1, rhs.1)) }
        }
    }

    #[allow(non_camel_case_types)]
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct u32x4(__m128i);

    impl u32x4 {
        #[inline(always)]
        pub fn new(a: u32, b: u32, c: u32, d: u32) -> Self {
            unsafe { u32x4(_mm_set_epi32(d as i32, c as i32, b as i32, a as i32)) }
        }

        #[inline(always)]
        pub fn gather(src: &[u32], i0: usize, i1: usize, i2: usize, i3: usize) -> Self {
            Self::new(src[i0], src[i1], src[i2], src[i3])
        }

        #[inline(always)] pub fn shuffle_left_1(self) -> Self { unsafe { u32x4(_mm_shuffle_epi32(self.0, 0b00111001)) } }
        #[inline(always)] pub fn shuffle_left_2(self) -> Self { unsafe { u32x4(_mm_shuffle_epi32(self.0, 0b01001110)) } } 
        #[inline(always)] pub fn shuffle_left_3(self) -> Self { unsafe { u32x4(_mm_shuffle_epi32(self.0, 0b10010011)) } }

        #[cfg(not(target_feature = "ssse3"))]
        #[inline(always)]
        pub fn rotate_right_const(self, i: u32) -> Self {
            unsafe {
                match i {
                    7 => u32x4(_mm_or_si128(_mm_slli_epi32(self.0, 25), _mm_srli_epi32(self.0, 7))),
                    8 => u32x4(_mm_or_si128(_mm_slli_epi32(self.0, 24), _mm_srli_epi32(self.0, 8))),
                    12 => u32x4(_mm_or_si128(_mm_slli_epi32(self.0, 20), _mm_srli_epi32(self.0, 12))),
                    16 => u32x4(_mm_or_si128(_mm_slli_epi32(self.0, 16), _mm_srli_epi32(self.0, 16))),
                    _ => unreachable!(),
                }
            }
        }

        #[cfg(target_feature = "ssse3")]
        #[inline(always)]
        pub fn rotate_right_const(self, i: u32) -> Self {
            unsafe {
                match i {
                    7 => u32x4(_mm_or_si128(_mm_slli_epi32(self.0, 32 - 7), _mm_srli_epi32(self.0, 7))),
                    8 => u32x4(_mm_shuffle_epi8(self.0, _mm_set_epi64x(0x0c0f0e0d_080b0a09, 0x04070605_00030201))),
                    12 => u32x4(_mm_or_si128(_mm_slli_epi32(self.0, 32 - 12), _mm_srli_epi32(self.0, 12))),
                    16 => u32x4(_mm_shuffle_epi8(self.0, _mm_set_epi64x(0x0d0c0f0e_09080b0a, 0x05040706_01000302))),
                    _ => unreachable!(),
                }
            }
        }

        #[inline(always)] pub fn wrapping_add(self, rhs: Self) -> Self { unsafe { u32x4(_mm_add_epi32(self.0, rhs.0)) } }

        #[inline(always)] pub fn to_le(self) -> Self { self }
        #[inline(always)] pub fn from_le(self) -> Self { self }
    }

    impl BitXor for u32x4 {
        type Output = Self;
        #[inline(always)] fn bitxor(self, rhs: Self) -> Self::Output { unsafe { u32x4(_mm_xor_si128(self.0, rhs.0)) } }
    }
}

#[cfg(target_feature = "avx2")]
mod avx2 {
    use core::ops::BitXor;
    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;

    #[allow(non_camel_case_types)]
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct u64x4(__m256i);

    impl u64x4 {
        #[inline(always)]
        pub fn new(a: u64, b: u64, c: u64, d: u64) -> Self {
            unsafe { u64x4(_mm256_set_epi64x(d as i64, c as i64, b as i64, a as i64),) }
        }

        #[inline(always)]
        pub fn gather(src: &[u64], i0: usize, i1: usize, i2: usize, i3: usize) -> Self {
            Self::new(src[i0], src[i1], src[i2], src[i3])
        }

        #[inline(always)] pub fn shuffle_left_1(self) -> Self { u64x4(unsafe { _mm256_permute4x64_epi64(self.0, 0b00111001) }) }
        #[inline(always)] pub fn shuffle_left_2(self) -> Self { u64x4(unsafe { _mm256_permute4x64_epi64(self.0, 0b01001110) }) }
        #[inline(always)] pub fn shuffle_left_3(self) -> Self { u64x4(unsafe { _mm256_permute4x64_epi64(self.0, 0b10010011) }) }

        #[inline(always)]
        pub fn rotate_right_const(self, i: u32) -> Self {
            unsafe {
                let b16 = _mm256_set_epi64x(0x09080f0e0d0c0b0a, 0x0100070605040302, 0x09080f0e0d0c0b0a, 0x0100070605040302);
                let b24 = _mm256_set_epi64x(0x0a09080f0e0d0c0b, 0x0201000706050403, 0x0a09080f0e0d0c0b, 0x0201000706050403);
                match i {
                    16 => u64x4(_mm256_shuffle_epi8(self.0, b16)),
                    24 => u64x4(_mm256_shuffle_epi8(self.0, b24)),
                    32 => u64x4(_mm256_shuffle_epi32(self.0, 0b10110001)),
                    63 => u64x4(_mm256_or_si256(_mm256_slli_epi64(self.0, 1), _mm256_srli_epi64(self.0, 63))),
                    _ => unreachable!(),
                }
            }
        }

        #[inline(always)] pub fn wrapping_add(self, rhs: Self) -> Self { unsafe { u64x4(_mm256_add_epi64(self.0, rhs.0)) } }

        #[inline(always)] pub fn to_le(self) -> Self { self }
        #[inline(always)] pub fn from_le(self) -> Self { self }
    }

    impl BitXor for u64x4 {
        type Output = Self;
        #[inline(always)] fn bitxor(self, rhs: Self) -> Self::Output { u64x4(unsafe { _mm256_xor_si256(self.0, rhs.0) }) }
    }
}

#[cfg(all(target_feature = "sse2", not(target_feature = "avx2")))]
pub use self::sse2::u64x4;
#[cfg(target_feature = "avx2")]
pub use self::avx2::u64x4;

#[cfg(target_feature = "sse2")]
pub use self::sse2::u32x4;

unsafe impl Safe for u64x4 {}
unsafe impl Safe for u32x4 {}
