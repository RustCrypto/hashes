cfg_if::cfg_if! {
    if #[cfg(sha2_backend = "soft")] {
        mod soft;
        use soft::compress;
    } else if #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        sha2_backend = "x86-shani",
    ))] {
        #[cfg(not(all(
            target_feature = "sha",
            target_feature = "sse2",
            target_feature = "ssse3",
            target_feature = "sse4.1",
        )))]
        compile_error!("x86-shani backend requires sha, sse2, ssse3, sse4.1 target features");

        mod x86_shani;

        fn compress(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
            // SAFETY: we checked above that the required target features are enabled
            unsafe { x86_shani::compress(state, blocks) }
        }
    } else if #[cfg(all(
        any(target_arch = "riscv32", target_arch = "riscv64"),
        any(sha2_backend = "riscv-zknh", sha2_backend = "riscv-zknh-compact"),
    ))] {
        #[cfg(not(all(
            target_feature = "zknh",
            any(target_feature = "zbb", target_feature = "zbkb")
        )))]
        compile_error!("riscv-zknh backend requires zknh and zbkb (or zbb) target features");

        mod riscv_zknh;

        fn compress(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
            // SAFETY: we checked above that the required target features are enabled
            unsafe { riscv_zknh::compress(state, blocks) }
        }
    } else if #[cfg(all(
        target_arch = "aarch64",
        sha2_backend = "aarch64-sha2",
    ))] {
        #[cfg(not(target_feature = "sha2"))]
        compile_error!("aarch64-sha2 backend requires sha2 target feature");

        mod aarch64_sha2;

        fn compress(state: &mut [u64; 8], blocks: &[[u8; 128]]) {
            // SAFETY: we checked above that the required target features are enabled
            unsafe { aarch64_sha2::compress(state, blocks) }
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
                mod x86_shani;
                cpufeatures::new!(shani_cpuid, "sha", "sse2", "ssse3", "sse4.1");
            } else if #[cfg(target_arch = "aarch64")] {
                mod aarch64_sha2;
                cpufeatures::new!(sha2_hwcap, "sha2");
            }
        }

        fn compress(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
            cfg_if::cfg_if! {
                if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
                    if shani_cpuid::get() {
                        // SAFETY: we checked that required target features are available
                        return unsafe { x86_shani::compress(state, blocks) };
                    }
                } else if #[cfg(target_arch = "aarch64")] {
                    if sha2_hwcap::get() {
                        // SAFETY: we checked that `sha2` target feature is available
                        return unsafe { aarch64_sha2::compress(state, blocks) };
                    }
                }
            }

            soft::compress(state, blocks);
        }
    }
}

/// Raw SHA-256 compression function.
///
/// This is a low-level "hazmat" API which provides direct access to the core
/// functionality of SHA-256.
pub fn compress256(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
    compress(state, blocks)
}
