extern crate alloc;

const DIGEST_BYTES: usize = 32;
const DIGEST_WORDS: usize = DIGEST_BYTES / 4;
const BLOCK_BYTES: usize = DIGEST_BYTES * 2;
const BLOCK_WORDS: usize = DIGEST_WORDS * 2;

extern "C" {
    fn sys_sha_buffer(
        out_state: *mut [u32; DIGEST_WORDS],
        in_state: *const [u32; DIGEST_WORDS],
        buf: *const u8,
        count: u32,
    );
}

use alloc::vec::Vec;

#[inline(always)]
fn compress_words(state: &mut [u32; DIGEST_WORDS], blocks: &[[u32; BLOCK_WORDS]]) {
    unsafe {
        sys_sha_buffer(
            state,
            state,
            blocks.as_ptr() as *const u8,
            blocks.len() as u32,
        );
    }
}

// When the blocks are unaligned they must be copied in order to align them on a u32 word boundary
// before they can be passed to sys_sha_buffer. This function does this, allocating a new Vec.
fn read_unaligned_blocks(blocks: &[[u8; BLOCK_BYTES]]) -> Vec<[u32; BLOCK_WORDS]> {
    blocks
        .iter()
        .map(|block| unsafe { (block.as_ptr() as *const [u32; BLOCK_WORDS]).read_unaligned() })
        .collect::<Vec<_>>()
}

/// SHA-256 compress implementation which calls into the RISZ Zero SHA-256 accelerator circuit.
/// Based on https://github.com/risc0/risc0/tree/main/risc0/zkvm/src/guest/sha.rs
#[inline]
pub fn compress(state: &mut [u32; DIGEST_WORDS], blocks: &[[u8; BLOCK_BYTES]]) {
    // On little-endian architectures, flip from big-endian to little-endian.
    // RISC Zero expects the state to always be big-endian, wheras this crate uses native-endian.
    for word in state.iter_mut() {
        *word = word.to_be();
    }

    // If aligned, reinterpret the u8 array blocks as u32 array blocks.
    // If unaligned, the data needs to be copied.
    match unsafe { blocks.align_to::<[u32; BLOCK_WORDS]>() } {
        (&[], aligned_blocks, &[]) => compress_words(state, aligned_blocks),
        _ => compress_words(state, &read_unaligned_blocks(&blocks)),
    };

    // On little-endian architectures, flip from big-endian to little-endian.
    for word in state.iter_mut() {
        *word = word.to_be();
    }
}
