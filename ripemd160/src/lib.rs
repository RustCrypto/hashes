//! An implementation of the RIPEMD-160 cryptographic hash.

#![no_std]
extern crate generic_array;
extern crate byte_tools;
extern crate digest;
extern crate block_buffer;

pub use digest::Digest;
use byte_tools::write_u32v_le;
use block_buffer::BlockBuffer;
use generic_array::GenericArray;
use generic_array::typenum::{U20, U64};

mod block;
use block::{process_msg_block, DIGEST_BUF_LEN};

type BlockSize = U64;
type Block = GenericArray<u8, BlockSize>;

/// Structure representing the state of a Ripemd160 computation
#[derive(Clone, Copy)]
pub struct Ripemd160 {
    h: [u32; DIGEST_BUF_LEN],
    len: u64,
    buffer: BlockBuffer<BlockSize>,
}

impl Ripemd160 {
    fn finalize(&mut self) {
        let h = &mut self.h;
        let l = self.len << 3;
        self.buffer.len_padding(l, |b| process_msg_block(h, b));
    }
}

impl Default for Ripemd160 {
    fn default() -> Self {
        Ripemd160 {
            h: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
            len: 0,
            buffer: Default::default(),
        }
    }
}

impl digest::BlockInput for Ripemd160 {
    type BlockSize = BlockSize;
}

impl digest::Input for Ripemd160 {
    fn process(&mut self, input: &[u8]) {
        // Assumes that input.len() can be converted to u64 without overflow
        self.len += input.len() as u64;
        let h = &mut self.h;
        self.buffer.input(input, |b| process_msg_block(h, b));
    }
}


impl digest::FixedOutput for Ripemd160 {
    type OutputSize = U20;

    fn fixed_result(mut self) -> GenericArray<u8, Self::OutputSize> {
        self.finalize();

        let mut out = GenericArray::default();
        write_u32v_le(&mut out[..], &self.h);
        out
    }
}
