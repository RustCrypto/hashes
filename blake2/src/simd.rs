use core::ops::{Add, BitXor, Shl, Shr};

#[cfg(feature = "zeroize")]
use digest::zeroize::Zeroize;

macro_rules! impl_vector4 {
    ($vec:ident, $word:ident) => {
        #[derive(Clone, Copy, Debug)]
        #[repr(C)]
        pub(crate) struct $vec(
            pub(crate) $word,
            pub(crate) $word,
            pub(crate) $word,
            pub(crate) $word,
        );

        impl $vec {
            #[inline(always)]
            pub(crate) fn new(e0: $word, e1: $word, e2: $word, e3: $word) -> Self {
                Self(e0, e1, e2, e3)
            }

            #[inline(always)]
            pub(crate) fn gather(
                src: &[$word],
                i0: usize,
                i1: usize,
                i2: usize,
                i3: usize,
            ) -> Self {
                $vec::new(src[i0], src[i1], src[i2], src[i3])
            }

            #[cfg(target_endian = "little")]
            #[inline(always)]
            #[allow(clippy::wrong_self_convention)]
            pub(crate) fn from_le(self) -> Self {
                self
            }

            #[cfg(not(target_endian = "little"))]
            #[inline(always)]
            pub(crate) fn from_le(self) -> Self {
                $vec::new(
                    $word::from_le(self.0),
                    $word::from_le(self.1),
                    $word::from_le(self.2),
                    $word::from_le(self.3),
                )
            }

            #[cfg(target_endian = "little")]
            #[inline(always)]
            pub(crate) fn to_le(self) -> Self {
                self
            }

            #[cfg(not(target_endian = "little"))]
            #[inline(always)]
            pub(crate) fn to_le(self) -> Self {
                $vec::new(
                    self.0.to_le(),
                    self.1.to_le(),
                    self.2.to_le(),
                    self.3.to_le(),
                )
            }

            #[inline(always)]
            pub(crate) fn wrapping_add(self, rhs: Self) -> Self {
                self + rhs
            }

            #[inline(always)]
            pub(crate) fn rotate_right_const(self, n: u32) -> Self {
                $vec::new(
                    self.0.rotate_right(n),
                    self.1.rotate_right(n),
                    self.2.rotate_right(n),
                    self.3.rotate_right(n),
                )
            }

            #[inline(always)]
            pub(crate) fn shuffle_left_1(self) -> Self {
                $vec::new(self.1, self.2, self.3, self.0)
            }

            #[inline(always)]
            pub(crate) fn shuffle_left_2(self) -> Self {
                $vec::new(self.2, self.3, self.0, self.1)
            }

            #[inline(always)]
            pub(crate) fn shuffle_left_3(self) -> Self {
                $vec::new(self.3, self.0, self.1, self.2)
            }

            #[inline(always)]
            pub(crate) fn shuffle_right_1(self) -> Self {
                self.shuffle_left_3()
            }
            #[inline(always)]
            pub(crate) fn shuffle_right_2(self) -> Self {
                self.shuffle_left_2()
            }
            #[inline(always)]
            pub(crate) fn shuffle_right_3(self) -> Self {
                self.shuffle_left_1()
            }

            #[inline(always)]
            pub(crate) fn as_bytes(&self) -> &[u8] {
                let p = self as *const Self as *const u8;
                unsafe { core::slice::from_raw_parts(p, core::mem::size_of::<Self>()) }
            }
        }

        impl Add for $vec {
            type Output = Self;

            #[inline(always)]
            fn add(self, rhs: Self) -> Self::Output {
                $vec::new(
                    self.0.wrapping_add(rhs.0),
                    self.1.wrapping_add(rhs.1),
                    self.2.wrapping_add(rhs.2),
                    self.3.wrapping_add(rhs.3),
                )
            }
        }

        impl BitXor for $vec {
            type Output = Self;

            #[inline(always)]
            fn bitxor(self, rhs: Self) -> Self::Output {
                $vec::new(
                    self.0 ^ rhs.0,
                    self.1 ^ rhs.1,
                    self.2 ^ rhs.2,
                    self.3 ^ rhs.3,
                )
            }
        }

        impl Shl<$vec> for $vec {
            type Output = Self;

            #[inline(always)]
            fn shl(self, rhs: Self) -> Self::Output {
                $vec::new(
                    self.0 << rhs.0,
                    self.1 << rhs.1,
                    self.2 << rhs.2,
                    self.3 << rhs.3,
                )
            }
        }

        impl Shr<$vec> for $vec {
            type Output = Self;

            #[inline(always)]
            fn shr(self, rhs: Self) -> Self::Output {
                $vec::new(
                    self.0 >> rhs.0,
                    self.1 >> rhs.1,
                    self.2 >> rhs.2,
                    self.3 >> rhs.3,
                )
            }
        }

        #[cfg(feature = "zeroize")]
        impl Zeroize for $vec {
            fn zeroize(&mut self) {
                self.0.zeroize();
                self.1.zeroize();
                self.2.zeroize();
                self.3.zeroize();
            }
        }
    };
}

impl_vector4!(u32x4, u32);
impl_vector4!(u64x4, u64);
