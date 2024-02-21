use crate::BLOCK_SIZE;

#[cfg(feature = "collision")]
use crate::DetectionState;

cfg_if::cfg_if! {
    if #[cfg(feature = "force-soft")] {
        mod soft;
        use soft::compress as compress_inner;
    } else if #[cfg(feature = "collision")] {
        mod collision;
        use collision::compress as compress_inner;
        pub(crate) use collision::finalize;
    } else if #[cfg(all(feature = "asm", target_arch = "aarch64"))] {
        mod soft;
        mod aarch64;
        use aarch64::compress as compress_inner;
    } else if #[cfg(target_arch = "loongarch64")] {
        mod loongarch64_asm;
        use loongarch64_asm::compress as compress_inner;
    } else if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
        mod soft;
        mod x86;
        use x86::compress as compress_inner;
    } else {
        mod soft;
        use soft::compress as compress_inner;
    }
}

/// SHA-1 compression function
pub fn compress(
    state: &mut [u32; 5],
    #[cfg(feature = "collision")] detection: &mut DetectionState,
    blocks: &[[u8; BLOCK_SIZE]],
) {
    compress_inner(
        state,
        #[cfg(feature = "collision")]
        detection,
        blocks,
    );
}
