pub(crate) const COLS: usize = 8;

mod soft;

cfg_if::cfg_if! {
    if #[cfg(any(not(any(target_arch = "x86_64", target_arch = "x86")), groestl_force_soft))] {
        pub(crate) use soft::*;
    } else {
        mod avx512_gfni;

        cpufeatures::new!(cpuid_avx512_gfni, "avx", "avx512f", "avx512vbmi", "gfni");

        #[inline(always)]
        pub(crate) fn compress(h: &mut [u64; COLS], blocks: &[[u8; 64]]) {
            if cpuid_avx512_gfni::get() {
                #[allow(unsafe_code)]
                unsafe { avx512_gfni::compress(h, blocks); }
            } else {
                soft::compress(h, blocks);
            }
        }

        #[inline(always)]
        pub(crate) fn p(h: &[u64; COLS]) -> [u64; COLS] {
            if cpuid_avx512_gfni::get() {
                #[allow(unsafe_code)]
                unsafe { avx512_gfni::p(h) }
            } else {
                soft::p(h)
            }
        }
    }
}
