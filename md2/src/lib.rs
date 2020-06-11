//! An implementation of the [MD2][1] cryptographic hash algorithm.
//!
//! # Usage
//!
//! ```rust
//! use md2::{Md2, Digest};
//! use hex_literal::hex;
//!
//! // create a Md2 hasher instance
//! let mut hasher = Md2::new();
//!
//! // process input message
//! hasher.update(b"hello world");
//!
//! // acquire hash digest in the form of GenericArray,
//! // which in this case is equivalent to [u8; 16]
//! let result = hasher.finalize();
//! assert_eq!(result[..], hex!("d9cce882ee690a5c1ce70beff3a78c77"));
//! ```
//!
//! Also see [RustCrypto/hashes][2] readme.
//!
//! [1]: https://en.wikipedia.org/wiki/MD4
//! [2]: https://github.com/RustCrypto/hashes

#![no_std]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "std")]
extern crate std;

pub use digest::{self, Digest};

use block_buffer::{block_padding::Pkcs7, BlockBuffer};
use digest::{consts::U16, generic_array::GenericArray};
use digest::{BlockInput, FixedOutputDirty, Reset, Update};

mod consts;

type Block = GenericArray<u8, U16>;

#[derive(Clone)]
struct Md2State {
    x: [u8; 48],
    checksum: Block,
}

impl Default for Md2State {
    fn default() -> Self {
        Self {
            x: [0; 48],
            checksum: Default::default(),
        }
    }
}

/// The MD2 hasher
#[derive(Clone, Default)]
pub struct Md2 {
    buffer: BlockBuffer<U16>,
    state: Md2State,
}

impl Md2State {
    fn process_block(&mut self, input: &Block) {
        // Update state
        for j in 0..16 {
            self.x[16 + j] = input[j];
            self.x[32 + j] = self.x[16 + j] ^ self.x[j];
        }

        let mut t = 0u8;
        for j in 0..18u8 {
            for k in 0..48 {
                self.x[k] ^= consts::S[t as usize];
                t = self.x[k];
            }
            t = t.wrapping_add(j);
        }

        // Update checksum
        let mut l = self.checksum[15];
        for j in 0..16 {
            self.checksum[j] ^= consts::S[(input[j] ^ l) as usize];
            l = self.checksum[j];
        }
    }
}

impl BlockInput for Md2 {
    type BlockSize = U16;
}

impl Update for Md2 {
    fn update(&mut self, input: impl AsRef<[u8]>) {
        let input = input.as_ref();
        let s = &mut self.state;
        self.buffer.input_block(input, |d| s.process_block(d));
    }
}

impl FixedOutputDirty for Md2 {
    type OutputSize = U16;

    fn finalize_into_dirty(&mut self, out: &mut digest::Output<Self>) {
        let buf = self
            .buffer
            .pad_with::<Pkcs7>()
            .expect("we never use input_lazy");

        self.state.process_block(buf);

        let checksum = self.state.checksum;
        self.state.process_block(&checksum);

        out.copy_from_slice(&self.state.x[0..16]);
    }
}

impl Reset for Md2 {
    fn reset(&mut self) {
        self.state = Default::default();
        self.buffer.reset();
    }
}

opaque_debug::implement!(Md2);
digest::impl_write!(Md2);
