use super::{GenericArray, U128};

cfg_if::cfg_if! {
    if #[cfg(feature = "force-soft")] {
        mod soft;
        use soft::compress;
    } else if #[cfg(all(feature = "asm", any(target_arch = "x86", target_arch = "x86_64")))] {
        use sha2_asm::compress512 as compress;
    } else {
        mod soft;
        use soft::compress;
    }
}

/// SHA-512 compression function.
#[cfg_attr(docsrs, doc(cfg(feature = "compress")))]
pub fn compress512(state: &mut [u64; 8], blocks: &[GenericArray<u8, U128>]) {
    // SAFETY: GenericArray<u8, U64> and [u8; 64] have
    // exactly the same memory layout
    let p = blocks.as_ptr() as *const [u8; 128];
    let blocks = unsafe { core::slice::from_raw_parts(p, blocks.len()) };
    compress(state, blocks)
}
