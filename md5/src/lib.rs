//! The [MD5][1] hash function.
//!
//! [1]: https://en.wikipedia.org/wiki/MD5

#![no_std]
extern crate generic_array;
extern crate byte_tools;
extern crate digest;
extern crate digest_buffer;

pub use digest::Digest;
use byte_tools::{write_u32_le, write_u32v_le};
use digest_buffer::{DigestBuffer};
use generic_array::GenericArray;
use generic_array::typenum::{U16, U64};
use core::mem;

pub const S0: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

type BlockSize = U64;
type Block = GenericArray<u8, BlockSize>;

#[link(name="md5", kind="static")]
extern "C" {
    fn md5_compress(state: &mut [u32; 4], block: &[u8; 64]);
}

#[inline(always)]
fn process_block(state: &mut [u32; 4], block: &Block) {
    unsafe {
        md5_compress(state, mem::transmute(block));
    }
}

/// The MD5 Digest algorithm
#[derive(Copy, Clone)]
pub struct Md5 {
    length_bytes: u64,
    buffer: DigestBuffer<BlockSize>,
    state: [u32; 4],
}

impl Default for Md5 {
    fn default() -> Self {
        Self {
            length_bytes: 0,
            buffer: Default::default(),
            state: S0,
        }
    }
}

impl Md5 {
    fn finalize(&mut self) {
        let self_state = &mut self.state;
        self.buffer.standard_padding(8, |d: &Block| {
            process_block(self_state, d);
        });
        write_u32_le(self.buffer.next(4), (self.length_bytes << 3) as u32);
        write_u32_le(self.buffer.next(4), (self.length_bytes >> 29) as u32);
        process_block(self_state, self.buffer.full_buffer());
    }
}

impl digest::Input for Md5 {
    type BlockSize = BlockSize;

    #[inline]
    fn digest(&mut self, input: &[u8]) {
        // Unlike Sha1 and Sha2, the length value in MD5 is defined as
        // the length of the message mod 2^64 - ie: integer overflow is OK.
        self.length_bytes += input.len() as u64;
        let self_state = &mut self.state;
        self.buffer.input(input, |d: &Block| {
            process_block(self_state, d);
        });
    }
}

impl digest::FixedOutput for Md5 {
    type OutputSize = U16;

    #[inline]
    fn fixed_result(mut self) -> GenericArray<u8, Self::OutputSize> {
        self.finalize();

        let mut out = GenericArray::default();
        write_u32v_le(&mut out, &self.state);
        out
    }
}
