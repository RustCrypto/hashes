#![feature(test)]
extern crate test;

use simd::{vec128_storage, x86_64, Machine};
use test::Bencher;

macro_rules! mach_bench {
    ($MachName:ident, $feature:expr, $enable:expr) => {
        #[allow(non_snake_case)]
        #[bench]
        pub fn $MachName(b: &mut Bencher) {
            if !$enable {
                return;
            }
            let m = unsafe { x86_64::$MachName::instance() };
            let mut state = [vec128_storage::default(); 8];
            let input = [0; 64];
            #[target_feature(enable = $feature)]
            unsafe fn runner<M: Machine>(
                m: M,
                state: &mut [vec128_storage; 8],
                input: *const [u8; 64],
            ) {
                for _ in 0..160 {
                    jh::f8_impl(m, state, input as *const _);
                }
            }
            b.iter(|| unsafe { runner(m, &mut state, &input) });
            b.bytes = 10240;
        }
    };
}

mach_bench!(SSE2, "sse2", is_x86_feature_detected!("sse2"));
mach_bench!(SSSE3, "ssse3", is_x86_feature_detected!("ssse3"));
mach_bench!(SSE41, "sse4.1", is_x86_feature_detected!("sse4.1"));
mach_bench!(AVX, "avx", is_x86_feature_detected!("avx"));
mach_bench!(AVX2, "avx2", is_x86_feature_detected!("avx2"));
