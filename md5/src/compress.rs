cfg_if::cfg_if! {
    if #[cfg(feature = "force-soft")] {
        mod soft;
        use soft::compress as compress_inner;
    } else if #[cfg(target_arch = "loongarch64")] {
        mod loongarch64_asm;
        use loongarch64_asm::compress as compress_inner;
    } else {
        mod soft;
        use soft::compress as compress_inner;
    }
}

/// MD5 compression function
pub fn compress(state: &mut [u32; 4], blocks: &[[u8; 64]]) {
    compress_inner(state, blocks)
}
