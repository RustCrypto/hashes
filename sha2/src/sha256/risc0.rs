#[cfg(feature = "alloc")]
extern crate alloc;

use risc0_zkvm_platform::syscall::{sys_sha_buffer, DIGEST_WORDS};

const BLOCK_WORDS: usize = DIGEST_WORDS * 2;

use alloc::vec::Vec;

#[inline(always)]
fn compress_words(state: &mut [u32; DIGEST_WORDS], blocks: &[[u32; BLOCK_WORDS]]) {
    unsafe {
        sys_sha_buffer(
            state,
            state,
            bytemuck::cast_slice(blocks).as_ptr(),
            blocks.len() as u32,
        );
    }
}

/// SHA-256 compress implementation which calls into the RISZ Zero SHA-256 accelerator circuit.
/// Based on https://github.com/risc0/risc0/tree/main/risc0/zkvm/src/guest/sha.rs
#[inline]
pub fn compress(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
    // On little-endian architectures, flip from big-endian to little-endian.
    // RISC Zero expects the state to always be big-endian, wheras this crate uses native-endian.
    for word in state.iter_mut() {
        *word = word.to_be();
    }

    // If aligned, reinterpret the u8 array blocks as u32 array blocks.
    // If unaligned, the data needs to be copied.
    match bytemuck::pod_align_to::<_, [u32; BLOCK_WORDS]>(blocks) {
        (&[], aligned_blocks, &[]) => compress_words(state, aligned_blocks),
        _ => compress_words(
            state,
            &blocks
                .iter()
                .map(|block| bytemuck::pod_read_unaligned(&block[..]))
                .collect::<Vec<_>>(),
        ),
    };

    // On little-endian architectures, flip from big-endian to little-endian.
    for word in state.iter_mut() {
        *word = word.to_be();
    }
}
