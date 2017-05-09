//! An implementation of the SHA-1 cryptographic hash algorithm.

//! To use this module, first create a `Sha1` object using the `Sha1` constructor,
//! then feed it an input message using the `input` or `input_str` methods,
//! which may be called any number of times; they will buffer the input until
//! there is enough to call the block algorithm.
//!
//! After the entire input has been fed to the hash read the result using
//! the `result` or `result_str` methods. The first will return bytes, and
//! the second will return a `String` object of the same bytes represented
//! in hexadecimal form.
//! 
//! The `Sha1` object may be reused to create multiple hashes by calling
//! the `reset()` method. These traits are implemented by all hash digest
//! algorithms that implement the `Digest` trait. An example of use is:
//! 
//! ```rust
//! use sha_1::{Sha1, Digest};
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
//!
//! # Mathematics
//!
//! The mathematics of the SHA-1 algorithm are quite interesting. In its
//! definition, The SHA-1 algorithm uses:
//!
//! * 1 binary operation on bit-arrays:
//!   * "exclusive or" (XOR)
//! * 2 binary operations on integers:
//!   * "addition" (ADD)
//!   * "rotate left" (ROL)
//! * 3 ternary operations on bit-arrays:
//!   * "choose" (CH)
//!   * "parity" (PAR)
//!   * "majority" (MAJ)
//!
//! Some of these functions are commonly found in all hash digest
//! algorithms, but some, like "parity" is only found in SHA-1.

#![no_std]
extern crate generic_array;
extern crate byte_tools;
extern crate digest;
extern crate digest_buffer;

#[cfg(not(feature = "asm"))]
extern crate fake_simd as simd;

#[cfg(feature = "asm")]
extern crate sha1_asm as utils;
#[cfg(not(feature = "asm"))]
mod utils;

use utils::compress;

pub use digest::Digest;
use byte_tools::{write_u32_be, write_u32v_be, add_bytes_to_bits};
use digest_buffer::DigestBuffer;
use generic_array::GenericArray;
use generic_array::typenum::{U20, U64};

mod consts;
use consts::{STATE_LEN, H};

type BlockSize = U64;

/// Structure representing the state of a SHA-1 computation
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
            .standard_padding(8, |d| compress(&mut *st_h, d));
        write_u32_be(self.buffer.next(4), (self.length_bits >> 32) as u32);
        write_u32_be(self.buffer.next(4), self.length_bits as u32);
        compress(st_h, self.buffer.full_buffer());
    }
}

impl Default for Sha1 {
    fn default() -> Self {
        Sha1{ h: H, length_bits: 0u64, buffer: Default::default() }
    }
}

impl digest::Input for Sha1 {
    type BlockSize = BlockSize;

    fn digest(&mut self, msg: &[u8]) {
        // Assumes that msg.len() can be converted to u64 without overflow
        self.length_bits = add_bytes_to_bits(self.length_bits, msg.len() as u64);
        let st_h = &mut self.h;
        self.buffer.input(msg, |d| {
            compress(st_h, d);
        });
    }
}

impl digest::FixedOutput for Sha1 {
    type OutputSize = U20;

    fn fixed_result(mut self) -> GenericArray<u8, Self::OutputSize> {
        self.finalize();

        let mut out = GenericArray::default();
        write_u32v_be(&mut out[..], &self.h);
        out
    }
}
