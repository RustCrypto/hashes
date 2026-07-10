// Copyright 2015 blake2-rfc Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

macro_rules! simd_opt {
    ($vec:ident) => {
        pub mod $vec {
            use crate::simd::simdty::$vec;

            #[inline(always)]
            pub fn rotate_right_const(vec: $vec, n: u32) -> $vec {
                $vec::new(
                    vec.0.rotate_right(n),
                    vec.1.rotate_right(n),
                    vec.2.rotate_right(n),
                    vec.3.rotate_right(n),
                )
            }
        }
    };
}

simd_opt!(u32x4);
simd_opt!(u64x4);
