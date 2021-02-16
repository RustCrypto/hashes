use crate::Block;

cfg_if::cfg_if! {
    if #[cfg(feature = "force-soft")] {
        mod soft;
        use soft::compress as compress_inner;
    } else if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
        #[cfg(not(feature = "asm"))]
        mod soft;
        #[cfg(feature = "asm")]
        mod soft {
            pub(crate) use sha1_asm::compress as compress;
        }
        mod x86;
        use x86::compress as compress_inner;
    } else if #[cfg(all(feature = "asm", target_arch = "aarch64", target_os = "linux"))] {
        mod soft;
        mod aarch64;
        use aarch64::compress as compress_inner;
    } else {
        mod soft;
        use soft::compress as compress_inner;
    }
}

/// SHA-1 compression function
#[cfg_attr(docsrs, doc(cfg(feature = "compress")))]
pub fn compress(state: &mut [u32; 5], blocks: &[Block]) {
    // SAFETY: GenericArray<u8, U64> and [u8; 64] have
    // exactly the same memory layout
    #[allow(unsafe_code)]
    let blocks: &[[u8; 64]] = unsafe { &*(blocks as *const _ as *const [[u8; 64]]) };
    compress_inner(state, blocks);
}
