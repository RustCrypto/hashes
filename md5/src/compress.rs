cfg_if::cfg_if! {
    if #[cfg(feature = "force-soft")] {
        mod soft;
        pub use soft::compress;
    } else if #[cfg(target_arch = "loongarch64")] {
        mod loongarch64_asm;
        pub use loongarch64_asm::compress;
    } else {
        mod soft;
        pub use soft::compress;
    }
}
