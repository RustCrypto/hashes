use digest::consts::U64;
use digest::generic_array::GenericArray;

mod aarch64;
#[cfg(any(not(feature = "asm"), feature = "asm-aarch64"))]
mod soft;
mod x86;

type Block = GenericArray<u8, U64>;

cfg_if::cfg_if! {
    if #[cfg(feature = "asm-aarch64")] {
        use aarch64::compress as compress_inner;
    } else if #[cfg(feature = "asm")] {
        // TODO: replace after sha1-asm rework
        fn compress_inner(state: &mut [u32; 5], blocks: &[u8; 64]) {
            for block in blocks {
                sha1_asm::compress(state, block);
            }
        }
    } else if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
        use x86::compress as compress_inner;
    } else {
        use soft::compress as compress_inner;
    }
}

pub fn compress(state: &mut [u32; 5], blocks: &[Block]) {
    // SAFETY: GenericArray<u8, U64> and [u8; 64] have
    // exactly the same memory layout
    #[allow(unsafe_code)]
    let blocks: &[[u8; 64]] = unsafe { core::mem::transmute(blocks) };
    compress_inner(state, blocks);
}
