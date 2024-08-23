cfg_if::cfg_if! {
    if #[cfg(feature = "force-soft")] {
        mod soft;
        use soft::compress;
    } else if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
        mod soft;
        mod x86;
        use x86::compress;
    } else if #[cfg(all(
        any(target_arch = "riscv32", target_arch = "riscv64"),
        sha2_backend = "riscv-zknh"
    ))] {
        mod riscv_zknh;
        use riscv_zknh::compress;
    } else if #[cfg(all(
        any(target_arch = "riscv32", target_arch = "riscv64"),
        sha2_backend = "riscv-zknh-compact"
    ))] {
        mod riscv_zknh_compact;
        use riscv_zknh_compact::compress;
    } else if #[cfg(target_arch = "aarch64")] {
        mod soft;
        mod aarch64;
        use aarch64::compress;
    } else if #[cfg(target_arch = "loongarch64")] {
        mod loongarch64_asm;
        use loongarch64_asm::compress;
    } else {
        mod soft;
        use soft::compress;
    }
}

#[inline(always)]
#[allow(dead_code)]
fn to_u32s(block: &[u8; 64]) -> [u32; 16] {
    let mut res = [0u32; 16];
    for (src, dst) in block.chunks_exact(4).zip(res.iter_mut()) {
        *dst = u32::from_be_bytes(src.try_into().unwrap());
    }
    res
}

/// Raw SHA-256 compression function.
///
/// This is a low-level "hazmat" API which provides direct access to the core
/// functionality of SHA-256.
#[cfg_attr(docsrs, doc(cfg(feature = "compress")))]
pub fn compress256(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
    compress(state, blocks)
}
