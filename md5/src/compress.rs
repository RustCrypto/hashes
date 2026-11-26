cfg_if::cfg_if! {
    if #[cfg(md5_backend = "soft")] {
        mod soft;
        use soft::compress as compress_inner;
    } else if #[cfg(target_arch = "loongarch64")] {
        mod loongarch64_asm;
        use loongarch64_asm::compress as compress_inner;
    } else if #[cfg(target_arch = "aarch64")] {
        mod aarch64_asm;
        use aarch64_asm::compress as compress_inner;
    } else if #[cfg(target_arch = "x86_64")] {
        mod x86_64_asm;
        use x86_64_asm::compress as compress_inner;
    } else {
        mod soft;
        use soft::compress as compress_inner;
    }
}

/// MD5 compression function
pub fn compress(state: &mut [u32; 4], blocks: &[[u8; 64]]) {
    compress_inner(state, blocks)
}
