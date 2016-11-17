//! An implementation of the RIPEMD-160 cryptographic hash.
//!
//! First create a `Ripemd160` object using the `Ripemd160` constructor,
//! then feed it input using the `input` or `input_str` methods, which
//! may be called any number of times.
//!
//! After the entire input has been fed to the hash read the result using
//! the `result` or `result_str` methods.
//!
//! The `Ripemd160` object may be reused to create multiple hashes by
//! calling the `reset` method.

#![no_std]
extern crate generic_array;
extern crate byte_tools;
extern crate digest;
extern crate digest_buffer;

pub use digest::Digest;
use byte_tools::{write_u32_le, add_bytes_to_bits};
use digest_buffer::{DigestBuffer};
use generic_array::GenericArray;
use generic_array::typenum::{U20, U64};

mod block;
use block::{process_msg_block, DIGEST_BUF_LEN};

type BlockSize = U64;

/// Structure representing the state of a Ripemd160 computation
#[derive(Clone, Copy)]
pub struct Ripemd160 {
    h: [u32; DIGEST_BUF_LEN],
    length_bits: u64,
    buffer: DigestBuffer<BlockSize>,
}



impl Ripemd160 {
    pub fn new() -> Ripemd160 {
        Ripemd160 {
            h: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
            length_bits: 0,
            buffer: Default::default(),
        }
    }

    fn finalize(&mut self) {
        let st_h = &mut self.h;
        self.buffer.standard_padding(8, |d: &[u8]| {
            process_msg_block(d, &mut *st_h)
        });

        write_u32_le(self.buffer.next(4), self.length_bits as u32);
        write_u32_le(self.buffer.next(4), (self.length_bits >> 32) as u32);
        process_msg_block(self.buffer.full_buffer(), st_h);
    }
}

impl Default for Ripemd160 {
    fn default() -> Self { Ripemd160::new() }
}

impl Digest for Ripemd160 {
    type OutputSize = U20;
    type BlockSize = BlockSize;

    fn input(&mut self, input: &[u8]) {
        // Assumes that input.len() can be converted to u64 without overflow
        self.length_bits = add_bytes_to_bits(self.length_bits,
                                             input.len() as u64);
        let st_h = &mut self.h;
        self.buffer.input(input, |d: &[u8]| {
            process_msg_block(d, &mut *st_h);
        });
    }

    fn result(mut self) -> GenericArray<u8, Self::OutputSize> {
        self.finalize();

        let mut out = GenericArray::new();
        write_u32_le(&mut out[0..4], self.h[0]);
        write_u32_le(&mut out[4..8], self.h[1]);
        write_u32_le(&mut out[8..12], self.h[2]);
        write_u32_le(&mut out[12..16], self.h[3]);
        write_u32_le(&mut out[16..20], self.h[4]);
        out
    }
}
