//! An implementation of the RIPEMD-160 cryptographic hash.

#![no_std]
extern crate generic_array;
extern crate byte_tools;
extern crate digest;
extern crate digest_buffer;

pub use digest::Digest;
use byte_tools::{write_u32v_le, write_u32_le, add_bytes_to_bits};
use digest_buffer::{DigestBuffer};
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
    length_bits: u64,
    buffer: DigestBuffer<BlockSize>,
}



impl Ripemd160 {
    fn finalize(&mut self) {
        let st_h = &mut self.h;
        self.buffer.standard_padding(8, |d: &Block| {
            process_msg_block(d, &mut *st_h)
        });

        write_u32_le(self.buffer.next(4), self.length_bits as u32);
        write_u32_le(self.buffer.next(4), (self.length_bits >> 32) as u32);
        process_msg_block(self.buffer.full_buffer(), st_h);
    }
}

impl Default for Ripemd160 {
    fn default() -> Self {
        Self {
            h: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
            length_bits: 0,
            buffer: Default::default(),
        }
    }
}

impl digest::Input for Ripemd160 {
    type BlockSize = BlockSize;

    fn digest(&mut self, input: &[u8]) {
        // Assumes that input.len() can be converted to u64 without overflow
        self.length_bits = add_bytes_to_bits(self.length_bits,
                                             input.len() as u64);
        let st_h = &mut self.h;
        self.buffer.input(input, |d: &Block| {
            process_msg_block(d, &mut *st_h);
        });
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
