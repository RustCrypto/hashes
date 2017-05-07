//! An implementation of the SHA-1 cryptographic hash algorithm.
//!
//! # Example
//! ```rust
//! use sha1_asm::{Sha1, Digest};
//!
//! // create a Sha1 object
//! let mut sh = Sha1::default();
//! 
//! // write input message
//! sh.input(b"hello world");
//!
//! // read hash digest in the form of GenericArray which is in this case
//! // equivalent to [u8; 20]
//! let output = sh.result();
//! assert_eq!(output[..], [0x2a, 0xae, 0x6c, 0x35, 0xc9, 0x4f, 0xcf, 0xb4, 0x15, 0xdb,
//!                         0xe9, 0x5f, 0x40, 0x8b, 0x9c, 0xe9, 0x1e, 0xe8, 0x46, 0xed]);
//! ```

#![no_std]
extern crate generic_array;
extern crate byte_tools;
extern crate digest;
extern crate digest_buffer;

pub use digest::Digest;
use byte_tools::{write_u32_be, write_u32v_be, add_bytes_to_bits};
use digest_buffer::DigestBuffer;
use generic_array::GenericArray;
use generic_array::typenum::{U20, U64};
use core::mem;

const STATE_LEN: usize = 5;
pub const H: [u32; STATE_LEN] = [
    0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
];

type BlockSize = U64;
type Block = GenericArray<u8, BlockSize>;


#[link(name="sha1", kind="static")]
extern "C" {
    fn sha1_compress(state: &mut [u32; 5], block: &[u8; 64]);
}

#[inline(always)]
fn process_block(state: &mut [u32; 5], block: &Block) {
    unsafe {
        sha1_compress(state, mem::transmute(block));
    }
}


/// Structure representing the state of a Sha1 computation
#[derive(Clone)]
pub struct Sha1 {
    h: [u32; STATE_LEN],
    length_bits: u64,
    buffer: DigestBuffer<BlockSize>,
}

impl Sha1 {
    fn finalize(&mut self) {
        let st_h = &mut self.h;
        self.buffer
            .standard_padding(8, |d| process_block(&mut *st_h, d));
        write_u32_be(self.buffer.next(4), (self.length_bits >> 32) as u32);
        write_u32_be(self.buffer.next(4), self.length_bits as u32);
        process_block(st_h, self.buffer.full_buffer());
    }
}

impl Default for Sha1 {
    fn default() -> Self {
        Sha1{ h: H, length_bits: 0u64, buffer: Default::default() }
    }
}

impl digest::Input for Sha1 {
    type BlockSize = BlockSize;

    #[inline]
    fn digest(&mut self, msg: &[u8]) {
        // Assumes that msg.len() can be converted to u64 without overflow
        self.length_bits = add_bytes_to_bits(self.length_bits, msg.len() as u64);
        let st_h = &mut self.h;
        self.buffer.input(msg, |d| {
            process_block(st_h, d);
        });
    }
}

impl digest::FixedOutput for Sha1 {
    type OutputSize = U20;

    #[inline]
    fn fixed_result(mut self) -> GenericArray<u8, Self::OutputSize> {
        self.finalize();

        let mut out = GenericArray::default();
        write_u32v_be(&mut out[..], &self.h);
        out
    }
}
