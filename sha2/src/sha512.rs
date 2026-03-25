cfg_if::cfg_if! {
    if #[cfg(any(sha2_backend = "soft", sha2_256_backend = "soft"))] {
        mod soft;
        use soft::compress;
    } else if #[cfg(any(sha2_backend = "riscv-zknh", sha2_256_backend = "riscv-zknh"))] {
        mod riscv_zknh;

        #[cfg(not(all(
            target_feature = "zknh",
            any(target_feature = "zbb", target_feature = "zbkb")
        )))]
        compile_error!("riscv-zknh backend requires zknh and zbkb (or zbb) target features");

        fn compress(state: &mut [u64; 8], blocks: &[[u8; 128]]) {
            // SAFETY: we checked above that the required target features are enabled
            unsafe { riscv_zknh::compress(state, blocks) }
        }
    } else if #[cfg(sha2_512_backend = "x86-avx2")] {
        mod x86_avx2;

        #[cfg(not(target_feature = "avx2"))]
        compile_error!("x86-avx2 backend requires avx2 target feature");

        fn compress(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
            // SAFETY: we checked above that the required target features are enabled
            unsafe { x86_avx2::compress(state, blocks) }
        }
    } else if #[cfg(sha2_512_backend = "aarch64-sha3")]  {
        mod aarch64_sha3;

        #[cfg(not(target_feature = "sha3"))]
        compile_error!("aarch64-sha3 backend requires sha3 target feature");

        fn compress(state: &mut [u64; 8], blocks: &[[u8; 128]]) {
            // SAFETY: we checked above that the required target features are enabled
            unsafe { aarch64_sha3::compress(state, blocks) }
        }
    } else if #[cfg(target_arch = "loongarch64")] {
        mod loongarch64_asm;
        use loongarch64_asm::compress;
    } else if #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))] {
        mod wasm32_simd128;
        use wasm32_simd128::compress;
    } else {
        mod soft;

        cfg_if::cfg_if! {
            if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
                mod x86_avx2;
                cpufeatures::new!(avx2_cpuid, "avx2");
            } else if #[cfg(target_arch = "aarch64")] {
                mod aarch64_sha3;
                cpufeatures::new!(sha3_hwcap, "sha3");
            }
        }

        fn compress(state: &mut [u64; 8], blocks: &[[u8; 128]]) {
            cfg_if::cfg_if! {
                if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
                    if avx2_cpuid::get() {
                        // SAFETY: we checked that required target features are available
                        return unsafe { x86_avx2::compress(state, blocks) };
                    }
                } else if #[cfg(target_arch = "aarch64")] {
                    if sha3_hwcap::get() {
                        // SAFETY: we checked that `sha3` target feature is available
                        return unsafe { aarch64_sha3::compress(state, blocks) };
                    }
                }
            }

            soft::compress(state, blocks);
        }
    }
}

/// Raw SHA-512 compression function.
///
/// This is a low-level "hazmat" API which provides direct access to the core
/// functionality of SHA-512.
pub fn compress512(state: &mut [u64; 8], blocks: &[[u8; 128]]) {
    compress(state, blocks)
}
