cfg_if::cfg_if! {
    if #[cfg(sha2_backend = "soft")] {
        mod soft;
        use soft::compress;
    } else if #[cfg(sha2_backend = "soft-compact")] {
        mod soft_compact;
        use soft_compact::compress;
    } else if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
        mod soft;
        mod x86_avx2;
        use x86_avx2::compress;
    } else if #[cfg(all(
        any(target_arch = "riscv32", target_arch = "riscv64"),
        sha2_backend = "riscv-zknh"
    ))] {
        mod riscv_zknh;
        mod riscv_zknh_utils;
        use riscv_zknh::compress;
    } else if #[cfg(all(
        any(target_arch = "riscv32", target_arch = "riscv64"),
        sha2_backend = "riscv-zknh-compact"
    ))] {
        mod riscv_zknh_compact;
        mod riscv_zknh_utils;
        use riscv_zknh_compact::compress;
    } else if #[cfg(target_arch = "aarch64")] {
        mod soft;
        mod aarch64_sha2;
        use aarch64_sha2::compress;
    } else if #[cfg(target_arch = "loongarch64")] {
        mod loongarch64_asm;
        use loongarch64_asm::compress;
    } else if #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))] {
        mod wasm32_simd128;
        use wasm32_simd128::compress;
    } else {
        mod soft;
        use soft::compress;
    }
}

#[inline(always)]
#[allow(dead_code)]
fn to_u64s(block: &[u8; 128]) -> [u64; 16] {
    core::array::from_fn(|i| {
        let chunk = block[8 * i..][..8].try_into().unwrap();
        u64::from_be_bytes(chunk)
    })
}

/// Raw SHA-512 compression function.
///
/// This is a low-level "hazmat" API which provides direct access to the core
/// functionality of SHA-512.
pub fn compress512(state: &mut [u64; 8], blocks: &[[u8; 128]]) {
    compress(state, blocks)
}
