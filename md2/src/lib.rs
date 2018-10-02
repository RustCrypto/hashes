//! An implementation of the [MD2][1] cryptographic hash algorithm.
//!
//! # Usage
//!
//! ```rust
//! # #[macro_use] extern crate hex_literal;
//! # extern crate md2;
//! # fn main() {
//! use md2::{Md2, Digest};
//!
//! // create a Md2 hasher instance
//! let mut hasher = Md2::new();
//!
//! // process input message
//! hasher.input(b"hello world");
//!
//! // acquire hash digest in the form of GenericArray,
//! // which in this case is equivalent to [u8; 16]
//! let result = hasher.result();
//! assert_eq!(result[..], hex!("d9cce882ee690a5c1ce70beff3a78c77"));
//! # }
//! ```
//!
//! Also see [RustCrypto/hashes][2] readme.
//!
//! [1]: https://en.wikipedia.org/wiki/MD4
//! [2]: https://github.com/RustCrypto/hashes
#![no_std]
#![doc(html_logo_url =
    "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![cfg_attr(feature = "cargo-clippy", allow(needless_range_loop))]
#[macro_use] extern crate opaque_debug;
#[macro_use] pub extern crate digest;
extern crate block_buffer;
#[cfg(feature = "std")]
extern crate std;

pub use digest::Digest;
use digest::{Input, BlockInput, FixedOutput, Reset};
use block_buffer::BlockBuffer;
use block_buffer::block_padding::Pkcs7;
use digest::generic_array::GenericArray;
use digest::generic_array::typenum::U16;

mod consts;

type Block = GenericArray<u8, U16>;

#[derive(Clone)]
struct Md2State {
    x: [u8; 48],
    checksum: Block,
}

impl Default for Md2State {
    fn default() -> Self {
        Self { x: [0; 48], checksum: Default::default() }
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

impl Input for Md2 {
    fn input<B: AsRef<[u8]>>(&mut self, input: B) {
        let input = input.as_ref();
        let self_state = &mut self.state;
        self.buffer.input(input, |d| self_state.process_block(d) );
    }
}

impl FixedOutput for Md2 {
    type OutputSize = U16;

    fn fixed_result(mut self) -> GenericArray<u8, Self::OutputSize> {
        let buf = self.buffer.pad_with::<Pkcs7>()
            .expect("we never use input_lazy");
        self.state.process_block(buf);
        let checksum = self.state.checksum;
        self.state.process_block(&checksum);
        GenericArray::clone_from_slice(&self.state.x[0..16])
    }
}

impl Reset for Md2 {
    fn reset(&mut self) {
        self.state = Default::default();
        self.buffer.reset();
    }
}

impl_opaque_debug!(Md2);
impl_write!(Md2);
