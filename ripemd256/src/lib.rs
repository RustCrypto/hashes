//! An implementation of the [RIPEMD-256][1] cryptographic hash.
//!
//! # Usage
//!
//! ```rust
//! use hex_literal::hex;
//! use ripemd256::{Ripemd256, Digest};
//!
//! // create a RIPEMD-256 hasher instance
//! let mut hasher = Ripemd256::new();
//!
//! // process input message
//! hasher.update(b"Hello world!");
//!
//! // acquire hash digest in the form of GenericArray,
//! // which in this case is equivalent to [u8; 32]
//! let expected = hex!("2700f1122c7bd5df165b0615efbbbc54f551aef2401738811a5aea19ccb9233a");
//! let result = hasher.finalize();
//! assert_eq!(&result[..], &expected[..]);
//! ```
//!
//! [1]: https://en.wikipedia.org/wiki/RIPEMD

#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "std")]
extern crate std;

mod block;

pub use digest::{self, Digest};

use block::{process_msg_block, DIGEST_BUF_LEN, H0};
use block_buffer::BlockBuffer;
use digest::{
    consts::{U32, U64},
    BlockInput, FixedOutputDirty, Reset, Update,
};

/// Structure representing the state of a Ripemd256 computation
#[derive(Clone)]
pub struct Ripemd256 {
    h: [u32; DIGEST_BUF_LEN],
    len: u64,
    buffer: BlockBuffer<U64>,
}

impl Default for Ripemd256 {
    fn default() -> Self {
        Ripemd256 {
            h: H0,
            len: 0,
            buffer: Default::default(),
        }
    }
}

impl BlockInput for Ripemd256 {
    type BlockSize = U64;
}

impl Update for Ripemd256 {
    fn update(&mut self, input: impl AsRef<[u8]>) {
        let input = input.as_ref();
        // Assumes that input.len() can be converted to u64 without overflow
        self.len += input.len() as u64;
        let h = &mut self.h;
        self.buffer.input_block(input, |b| process_msg_block(h, b));
    }
}

impl FixedOutputDirty for Ripemd256 {
    type OutputSize = U32;

    fn finalize_into_dirty(&mut self, out: &mut digest::Output<Self>) {
        let h = &mut self.h;
        let l = self.len << 3;
        self.buffer.len64_padding_le(l, |b| process_msg_block(h, b));
        for (chunk, v) in out.chunks_exact_mut(4).zip(self.h.iter()) {
            chunk.copy_from_slice(&v.to_le_bytes());
        }
    }
}

impl Reset for Ripemd256 {
    fn reset(&mut self) {
        self.buffer.reset();
        self.len = 0;
        self.h = H0;
    }
}

opaque_debug::implement!(Ripemd256);
digest::impl_write!(Ripemd256);
