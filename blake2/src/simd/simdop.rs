// Copyright 2015 blake2-rfc Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crate::simd::simdty::{u32x4, u64x4};

use core::ops::{Add, BitXor, Shl, Shr};

macro_rules! impl_ops {
    ($vec:ident) => {
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
    };
}

impl_ops!(u32x4);
impl_ops!(u64x4);
