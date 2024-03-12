cfg_if::cfg_if! {
    if #[cfg(feature = "force-soft")] {
        mod soft;
        use soft::compress;
    } else if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
        mod soft;
        mod x86;
        use x86::compress;
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

/// Raw SHA-512 compression function.
///
/// This is a low-level "hazmat" API which provides direct access to the core
/// functionality of SHA-512.
#[cfg_attr(docsrs, doc(cfg(feature = "compress")))]
pub fn compress512(state: &mut [u64; 8], blocks: &[[u8; 128]]) {
    compress(state, blocks)
}
