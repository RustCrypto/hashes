//! An implementation of the [RIPEMD-320][1] cryptographic hash.
//!
//! # Usage
//!
//! ```rust
//! use hex_literal::hex;
//! use ripemd320::{Ripemd320, Digest};
//!
//! // create a RIPEMD-320 hasher instance
//! let mut hasher = Ripemd320::new();
//!
//! // process input message
//! hasher.update(b"Hello world!");
//!
//! // acquire hash digest in the form of GenericArray,
//! // which in this case is equivalent to [u8; 40]
//! let expected = hex!("f1c1c231d301abcf2d7daae0269ff3e7bc68e623ad723aa068d316b056d26b7d1bb6f0cc0f28336d");
//! let result = hasher.finalize();
//! assert_eq!(&result[..], &expected[..]);
//! ```
//!
//! Also see [RustCrypto/hashes][2] readme.
//!
//! [1]: https://en.wikipedia.org/wiki/RIPEMD
//! [2]: https://github.com/RustCrypto/hashes

#![no_std]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "std")]
extern crate std;

mod block;

pub use digest::{self, Digest};

use crate::block::{process_msg_block, DIGEST_BUF_LEN, H0};

use block_buffer::BlockBuffer;
use digest::consts::{U40, U64};
use digest::{BlockInput, FixedOutputDirty, Reset, Update};

/// Structure representing the state of a ripemd320 computation
#[derive(Clone)]
pub struct Ripemd320 {
    h: [u32; DIGEST_BUF_LEN],
    len: u64,
    buffer: BlockBuffer<U64>,
}

impl Default for Ripemd320 {
    fn default() -> Self {
        Ripemd320 {
            h: H0,
            len: 0,
            buffer: Default::default(),
        }
    }
}

impl BlockInput for Ripemd320 {
    type BlockSize = U64;
}

impl Update for Ripemd320 {
    fn update(&mut self, input: impl AsRef<[u8]>) {
        let input = input.as_ref();
        // Assumes that input.len() can be converted to u64 without overflow
        self.len += input.len() as u64;
        let h = &mut self.h;
        self.buffer.input_block(input, |b| process_msg_block(h, b));
    }
}

impl FixedOutputDirty for Ripemd320 {
    type OutputSize = U40;

    fn finalize_into_dirty(&mut self, out: &mut digest::Output<Self>) {
        let h = &mut self.h;
        let l = self.len << 3;
        self.buffer.len64_padding_le(l, |b| process_msg_block(h, b));
        for (chunk, v) in out.chunks_exact_mut(4).zip(self.h.iter()) {
            chunk.copy_from_slice(&v.to_le_bytes());
        }
    }
}

impl Reset for Ripemd320 {
    fn reset(&mut self) {
        self.buffer.reset();
        self.len = 0;
        self.h = H0;
    }
}

opaque_debug::implement!(Ripemd320);
digest::impl_write!(Ripemd320);
