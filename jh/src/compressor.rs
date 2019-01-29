#![allow(non_upper_case_globals)]

use core::ops::{BitAnd, BitOr, BitXor, BitXorAssign};
use core::ptr;

const E8_BITSLICE_ROUNDCONSTANT: [[u8; 32]; 42] = [
    hex!("72d5dea2df15f8677b84150ab723155781abd6904d5a87f64e9f4fc5c3d12b40"),
    hex!("ea983ae05c45fa9c03c5d29966b2999a660296b4f2bb538ab556141a88dba231"),
    hex!("03a35a5c9a190edb403fb20a87c144101c051980849e951d6f33ebad5ee7cddc"),
    hex!("10ba139202bf6b41dc786515f7bb27d00a2c813937aa78503f1abfd2410091d3"),
    hex!("422d5a0df6cc7e90dd629f9c92c097ce185ca70bc72b44acd1df65d663c6fc23"),
    hex!("976e6c039ee0b81a2105457e446ceca8eef103bb5d8e61fafd9697b294838197"),
    hex!("4a8e8537db03302f2a678d2dfb9f6a958afe7381f8b8696c8ac77246c07f4214"),
    hex!("c5f4158fbdc75ec475446fa78f11bb8052de75b7aee488bc82b8001e98a6a3f4"),
    hex!("8ef48f33a9a36315aa5f5624d5b7f989b6f1ed207c5ae0fd36cae95a06422c36"),
    hex!("ce2935434efe983d533af974739a4ba7d0f51f596f4e81860e9dad81afd85a9f"),
    hex!("a7050667ee34626a8b0b28be6eb9172747740726c680103fe0a07e6fc67e487b"),
    hex!("0d550aa54af8a4c091e3e79f978ef19e8676728150608dd47e9e5a41f3e5b062"),
    hex!("fc9f1fec4054207ae3e41a00cef4c9844fd794f59dfa95d8552e7e1124c354a5"),
    hex!("5bdf7228bdfe6e2878f57fe20fa5c4b205897cefee49d32e447e9385eb28597f"),
    hex!("705f6937b324314a5e8628f11dd6e465c71b770451b920e774fe43e823d4878a"),
    hex!("7d29e8a3927694f2ddcb7a099b30d9c11d1b30fb5bdc1be0da24494ff29c82bf"),
    hex!("a4e7ba31b470bfff0d324405def8bc483baefc3253bbd339459fc3c1e0298ba0"),
    hex!("e5c905fdf7ae090f947034124290f134a271b701e344ed95e93b8e364f2f984a"),
    hex!("88401d63a06cf61547c1444b8752afff7ebb4af1e20ac6304670b6c5cc6e8ce6"),
    hex!("a4d5a456bd4fca00da9d844bc83e18ae7357ce453064d1ade8a6ce68145c2567"),
    hex!("a3da8cf2cb0ee11633e906589a94999a1f60b220c26f847bd1ceac7fa0d18518"),
    hex!("32595ba18ddd19d3509a1cc0aaa5b4469f3d6367e4046bbaf6ca19ab0b56ee7e"),
    hex!("1fb179eaa9282174e9bdf7353b3651ee1d57ac5a7550d3763a46c2fea37d7001"),
    hex!("f735c1af98a4d84278edec209e6b677941836315ea3adba8fac33b4d32832c83"),
    hex!("a7403b1f1c2747f35940f034b72d769ae73e4e6cd2214ffdb8fd8d39dc5759ef"),
    hex!("8d9b0c492b49ebda5ba2d74968f3700d7d3baed07a8d5584f5a5e9f0e4f88e65"),
    hex!("a0b8a2f436103b530ca8079e753eec5a9168949256e8884f5bb05c55f8babc4c"),
    hex!("e3bb3b99f387947b75daf4d6726b1c5d64aeac28dc34b36d6c34a550b828db71"),
    hex!("f861e2f2108d512ae3db643359dd75fc1cacbcf143ce3fa267bbd13c02e843b0"),
    hex!("330a5bca8829a1757f34194db416535c923b94c30e794d1e797475d7b6eeaf3f"),
    hex!("eaa8d4f7be1a39215cf47e094c23275126a32453ba323cd244a3174a6da6d5ad"),
    hex!("b51d3ea6aff2c90883593d98916b3c564cf87ca17286604d46e23ecc086ec7f6"),
    hex!("2f9833b3b1bc765e2bd666a5efc4e62a06f4b6e8bec1d43674ee8215bcef2163"),
    hex!("fdc14e0df453c969a77d5ac4065858267ec1141606e0fa167e90af3d28639d3f"),
    hex!("d2c9f2e3009bd20c5faace30b7d40c30742a5116f2e032980deb30d8e3cef89a"),
    hex!("4bc59e7bb5f17992ff51e66e048668d39b234d57e6966731cce6a6f3170a7505"),
    hex!("b17681d913326cce3c175284f805a262f42bcbb378471547ff46548223936a48"),
    hex!("38df58074e5e6565f2fc7c89fc86508e31702e44d00bca86f04009a23078474e"),
    hex!("65a0ee39d1f73883f75ee937e42c3abd2197b2260113f86fa344edd1ef9fdee7"),
    hex!("8ba0df15762592d93c85f7f612dc42bed8a7ec7cab27b07e538d7ddaaa3ea8de"),
    hex!("aa25ce93bd0269d85af643fd1a7308f9c05fefda174a19a5974d66334cfd216a"),
    hex!("35b49831db411570ea1e0fbbedcd549b9ad063a151974072f6759dbf91476fe2"),
];

#[rustfmt::skip]
macro_rules! unroll7 {
    ($j:ident, $body:block) => {
        { const $j: usize = 0; $body }
        { const $j: usize = 1; $body }
        { const $j: usize = 2; $body }
        { const $j: usize = 3; $body }
        { const $j: usize = 4; $body }
        { const $j: usize = 5; $body }
        { const $j: usize = 6; $body }
    };
}

#[cfg(not(target_feature = "sse2"))]
mod generic {
    use super::*;
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct U128(u64, u64);
    impl U128 {
        #[inline(always)]
        pub fn const_ff() -> Self {
            U128(0xffffffffffffffff, 0xffffffffffffffff)
        }
        #[inline(always)]
        pub fn andnot(self, rhs: Self) -> Self {
            U128(!self.0 & rhs.0, !self.1 & rhs.1)
        }
        #[inline(always)]
        fn swap(self, l: u64, r: u64, i: u32) -> Self {
            U128(
                ((self.0 & l) >> i) | ((self.0 & r) << i),
                ((self.1 & l) >> i) | ((self.1 & r) << i),
            )
        }
        #[inline(always)]
        pub fn swap1(self) -> Self {
            self.swap(0xaaaaaaaaaaaaaaaa, 0x5555555555555555, 1)
        }
        #[inline(always)]
        pub fn swap2(self) -> Self {
            self.swap(0xcccccccccccccccc, 0x3333333333333333, 2)
        }
        #[inline(always)]
        pub fn swap4(self) -> Self {
            self.swap(0xf0f0f0f0f0f0f0f0, 0x0f0f0f0f0f0f0f0f, 4)
        }
        #[inline(always)]
        pub fn swap8(self) -> Self {
            self.swap(0xff00ff00ff00ff00, 0x00ff00ff00ff00ff, 8)
        }
        #[inline(always)]
        pub fn swap16(self) -> Self {
            self.swap(0xffff0000ffff0000, 0x0000ffff0000ffff, 16)
        }
        #[inline(always)]
        pub fn swap32(self) -> Self {
            self.swap(0xffffffff00000000, 0x00000000ffffffff, 32)
        }
        #[inline(always)]
        pub fn swap64(self) -> Self {
            U128(self.1, self.0)
        }
    }
    impl BitXor for U128 {
        type Output = U128;
        #[inline(always)]
        fn bitxor(self, rhs: Self) -> Self::Output {
            U128(self.0 ^ rhs.0, self.1 ^ rhs.1)
        }
    }
    impl BitOr for U128 {
        type Output = Self;
        #[inline(always)]
        fn bitor(self, rhs: Self) -> Self::Output {
            U128(self.0 | rhs.0, self.1 | rhs.1)
        }
    }
    impl BitAnd for U128 {
        type Output = Self;
        #[inline(always)]
        fn bitand(self, rhs: Self) -> Self::Output {
            U128(self.0 & rhs.0, self.1 & rhs.1)
        }
    }
    impl BitXorAssign for U128 {
        #[inline(always)]
        fn bitxor_assign(&mut self, rhs: Self) {
            *self = *self ^ rhs;
        }
    }
}
#[cfg(not(target_feature = "sse2"))]
use generic::*;

#[cfg(target_feature = "sse2")]
mod sse2 {
    use super::*;
    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;
    #[repr(transparent)]
    #[derive(Copy, Clone)]
    pub struct U128(__m128i);
    impl U128 {
        #[inline(always)]
        fn const8(k: u8) -> Self {
            U128(unsafe { _mm_set1_epi8(k as i8) })
        }
        #[cfg(not(all(feature = "avx2", target_feature = "avx2")))]
        #[inline(always)]
        pub fn const_ff() -> Self {
            Self::const8(0xff)
        }
        #[cfg(not(all(feature = "avx2", target_feature = "avx2")))]
        #[inline(always)]
        pub fn andnot(self, rhs: Self) -> Self {
            U128(unsafe { _mm_andnot_si128(self.0, rhs.0) })
        }
        #[inline(always)]
        pub fn swap1(self) -> Self {
            U128(unsafe {
                _mm_or_si128(
                    _mm_srli_epi16((self & U128::const8(0xaa)).0, 1),
                    _mm_slli_epi16((self & U128::const8(0x55)).0, 1),
                )
            })
        }
        #[inline(always)]
        pub fn swap2(self) -> Self {
            U128(unsafe {
                _mm_or_si128(
                    _mm_srli_epi16((self & U128::const8(0xcc)).0, 2),
                    _mm_slli_epi16((self & U128::const8(0x33)).0, 2),
                )
            })
        }
        #[inline(always)]
        pub fn swap4(self) -> Self {
            U128(unsafe {
                _mm_or_si128(
                    _mm_srli_epi16((self & U128::const8(0xf0)).0, 4),
                    _mm_slli_epi16((self & U128::const8(0x0f)).0, 4),
                )
            })
        }
        #[cfg(target_feature = "ssse3")]
        #[inline(always)]
        pub fn swap8(self) -> Self {
            U128(unsafe {
                let k = _mm_set_epi64x(0x0e0f_0c0d_0a0b_0809, 0x0607_0405_0203_0001);
                _mm_shuffle_epi8(self.0, k)
            })
        }
        #[cfg(not(target_feature = "ssse3"))]
        #[inline(always)]
        pub fn swap8(self) -> Self {
            U128(unsafe { _mm_or_si128(_mm_slli_epi16(self.0, 8), _mm_srli_epi16(self.0, 8)) })
        }
        #[cfg(target_feature = "ssse3")]
        #[inline(always)]
        pub fn swap16(self) -> Self {
            U128(unsafe {
                let k = _mm_set_epi64x(0x0d0c_0f0e_0908_0b0a, 0x0504_0706_0100_0302);
                _mm_shuffle_epi8(self.0, k)
            })
        }
        #[cfg(not(target_feature = "ssse3"))]
        #[inline(always)]
        pub fn swap16(self) -> Self {
            U128(unsafe { _mm_or_si128(_mm_slli_epi32(self.0, 16), _mm_srli_epi32(self.0, 16)) })
        }
        #[inline(always)]
        pub fn swap32(self) -> Self {
            U128(unsafe { _mm_shuffle_epi32(self.0, 0b10110001) })
        }
        #[inline(always)]
        pub fn swap64(self) -> Self {
            U128(unsafe { _mm_shuffle_epi32(self.0, 0b01001110) })
        }
        #[cfg(all(feature = "avx2", target_feature = "avx2"))]
        #[inline(always)]
        pub fn from_raw(x: __m128i) -> Self {
            U128(x)
        }
        #[cfg(all(feature = "avx2", target_feature = "avx2"))]
        #[inline(always)]
        pub fn raw(self) -> __m128i {
            self.0
        }
    }
    impl BitXor for U128 {
        type Output = U128;
        #[inline(always)]
        fn bitxor(self, rhs: Self) -> Self::Output {
            U128(unsafe { _mm_xor_si128(self.0, rhs.0) })
        }
    }
    impl BitOr for U128 {
        type Output = Self;
        #[inline(always)]
        fn bitor(self, rhs: Self) -> Self::Output {
            U128(unsafe { _mm_or_si128(self.0, rhs.0) })
        }
    }
    impl BitAnd for U128 {
        type Output = Self;
        #[inline(always)]
        fn bitand(self, rhs: Self) -> Self::Output {
            U128(unsafe { _mm_and_si128(self.0, rhs.0) })
        }
    }
    impl BitXorAssign for U128 {
        #[inline(always)]
        fn bitxor_assign(&mut self, rhs: Self) {
            *self = *self ^ rhs;
        }
    }
}
#[cfg(target_feature = "sse2")]
use sse2::*;

#[cfg(not(all(feature = "avx2", target_feature = "avx2")))]
mod single_channel {
    use super::*;
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct X2(U128, U128);
    impl X2 {
        #[inline(always)]
        pub fn new(a: U128, b: U128) -> Self {
            X2(a, b)
        }
        #[inline(always)]
        pub fn const_ff() -> Self {
            X2(U128::const_ff(), U128::const_ff())
        }
        #[inline(always)]
        pub fn andnot(self, rhs: Self) -> Self {
            X2(self.0.andnot(rhs.0), self.1.andnot(rhs.1))
        }
        #[inline(always)]
        pub fn split(self) -> (U128, U128) {
            (self.0, self.1)
        }
    }
    impl BitXorAssign for X2 {
        #[inline(always)]
        fn bitxor_assign(&mut self, rhs: Self) {
            self.0 = self.0 ^ rhs.0;
            self.1 = self.1 ^ rhs.1;
        }
    }
    impl BitOr for X2 {
        type Output = Self;
        #[inline(always)]
        fn bitor(self, rhs: Self) -> Self::Output {
            X2(self.0 | rhs.0, self.1 | rhs.1)
        }
    }
    impl BitAnd for X2 {
        type Output = Self;
        #[inline(always)]
        fn bitand(self, rhs: Self) -> Self::Output {
            X2(self.0 & rhs.0, self.1 & rhs.1)
        }
    }
}
#[cfg(not(all(feature = "avx2", target_feature = "avx2")))]
use single_channel::X2;

#[cfg(all(feature = "avx2", target_feature = "avx2"))]
mod double_channel {
    use super::*;
    #[cfg(target_arch = "x86")]
    use core::arch::x86::*;
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;
    #[repr(transparent)]
    #[derive(Copy, Clone)]
    pub struct X2(__m256i);
    impl X2 {
        #[inline(always)]
        pub fn new(a: U128, b: U128) -> Self {
            X2(unsafe { _mm256_inserti128_si256(_mm256_castsi128_si256(a.raw()), b.raw(), 1) })
        }
        #[inline(always)]
        pub fn const_ff() -> Self {
            X2(unsafe { _mm256_set1_epi8(0xffu8 as i8) })
        }
        #[inline(always)]
        pub fn andnot(self, rhs: Self) -> Self {
            X2(unsafe { _mm256_andnot_si256(self.0, rhs.0) })
        }
        #[inline(always)]
        pub fn split(self) -> (U128, U128) {
            unsafe {
                (
                    U128::from_raw(_mm256_castsi256_si128(self.0)),
                    U128::from_raw(_mm256_extracti128_si256(self.0, 1)),
                )
            }
        }
    }
    impl BitXorAssign for X2 {
        #[inline(always)]
        fn bitxor_assign(&mut self, rhs: Self) {
            self.0 = unsafe { _mm256_xor_si256(self.0, rhs.0) };
        }
    }
    impl BitOr for X2 {
        type Output = Self;
        #[inline(always)]
        fn bitor(self, rhs: Self) -> Self::Output {
            X2(unsafe { _mm256_or_si256(self.0, rhs.0) })
        }
    }
    impl BitAnd for X2 {
        type Output = Self;
        #[inline(always)]
        fn bitand(self, rhs: Self) -> Self::Output {
            X2(unsafe { _mm256_and_si256(self.0, rhs.0) })
        }
    }
}
#[cfg(all(feature = "avx2", target_feature = "avx2"))]
use double_channel::X2;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct X8(U128, U128, U128, U128, U128, U128, U128, U128);
impl X8 {
    #[inline(always)]
    fn unzip(self) -> (X2, X2, X2, X2) {
        (
            X2::new(self.0, self.1),
            X2::new(self.2, self.3),
            X2::new(self.4, self.5),
            X2::new(self.6, self.7),
        )
    }
    #[inline(always)]
    fn zip((a, b, c, d): (X2, X2, X2, X2)) -> Self {
        let (a, b, c, d) = (a.split(), b.split(), c.split(), d.split());
        X8(a.0, a.1, b.0, b.1, c.0, c.1, d.0, d.1)
    }
}

/// two Sboxes computed in parallel; each Sbox implements S0 and S1, selected by a constant bit
#[inline(always)]
unsafe fn ss(state: X8, mut k: X2) -> X8 {
    let mut m = state.unzip();
    m.3 ^= X2::const_ff();
    m.0 ^= m.2.andnot(k);
    k ^= m.0 & m.1;
    m.0 ^= m.3 & m.2;
    m.3 ^= m.1.andnot(m.2);
    m.1 ^= m.0 & m.2;
    m.2 ^= m.3.andnot(m.0);
    m.0 ^= m.1 | m.3;
    m.3 ^= m.1 & m.2;
    m.2 ^= k;
    m.1 ^= k & m.0;
    X8::zip(m)
}

#[inline(always)]
unsafe fn l(mut y: X8) -> X8 {
    y.1 ^= y.2;
    y.3 ^= y.4;
    y.5 ^= y.6 ^ y.0;
    y.7 ^= y.0;
    y.0 ^= y.3;
    y.2 ^= y.5;
    y.4 ^= y.7 ^ y.1;
    y.6 ^= y.1;
    y
}

pub unsafe fn f8(state: &mut X8, data: *const U128) {
    let mut y = *state;
    y.0 ^= ptr::read_unaligned(data);
    y.1 ^= ptr::read_unaligned(data.offset(1));
    y.2 ^= ptr::read_unaligned(data.offset(2));
    y.3 ^= ptr::read_unaligned(data.offset(3));
    let roundconst: [X2; 42] = core::mem::transmute(E8_BITSLICE_ROUNDCONSTANT);
    for rc in roundconst.chunks_exact(7) {
        unroll7!(j, {
            y = ss(y, rc[j]);
            y = l(y);
            let f = match j {
                0 => U128::swap1,
                1 => U128::swap2,
                2 => U128::swap4,
                3 => U128::swap8,
                4 => U128::swap16,
                5 => U128::swap32,
                6 => U128::swap64,
                _ => unreachable!(),
            };
            y = X8(y.0, f(y.1), y.2, f(y.3), y.4, f(y.5), y.6, f(y.7));
        });
    }
    y.4 ^= ptr::read_unaligned(data);
    y.5 ^= ptr::read_unaligned(data.offset(1));
    y.6 ^= ptr::read_unaligned(data.offset(2));
    y.7 ^= ptr::read_unaligned(data.offset(3));
    *state = y;
}
