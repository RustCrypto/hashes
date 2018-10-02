//! An implementation of the [MD5][1] cryptographic hash algorithm.
//!
//! # Usage
//!
//! ```rust
//! # #[macro_use] extern crate hex_literal;
//! # extern crate md5;
//! # fn main() {
//! use md5::{Md5, Digest};
//!
//! // create a Md5 hasher instance
//! let mut hasher = Md5::new();
//!
//! // process input message
//! hasher.input(b"hello world");
//!
//! // acquire hash digest in the form of GenericArray,
//! // which in this case is equivalent to [u8; 16]
//! let result = hasher.result();
//! assert_eq!(result[..], hex!("5eb63bbbe01eeed093cb22bb8f5acdc3"));
//! # }
//! ```
//!
//! Also see [RustCrypto/hashes][2] readme.
//!
//! [1]: https://en.wikipedia.org/wiki/MD5
//! [2]: https://github.com/RustCrypto/hashes
#![no_std]
#![doc(html_logo_url =
    "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
extern crate block_buffer;
#[macro_use] extern crate opaque_debug;
#[macro_use] pub extern crate digest;
#[cfg(feature = "asm")]
extern crate md5_asm as utils;
#[cfg(feature = "std")]
extern crate std;

#[cfg(not(feature = "asm"))]
mod utils;

use utils::compress;

use block_buffer::BlockBuffer;
use block_buffer::byteorder::{LE, ByteOrder};

pub use digest::Digest;
use digest::{Input, BlockInput, FixedOutput, Reset};
use digest::generic_array::GenericArray;
use digest::generic_array::typenum::{U16, U64};

mod consts;

/// The MD5 hasher
#[derive(Clone)]
pub struct Md5 {
    length_bytes: u64,
    buffer: BlockBuffer<U64>,
    state: [u32; 4],
}

impl Default for Md5 {
    fn default() -> Self {
        Md5 {
            length_bytes: 0,
            buffer: Default::default(),
            state: consts::S0,
        }
    }
}

#[inline(always)]
fn convert(d: &GenericArray<u8, U64>) -> &[u8; 64] {
    unsafe { &*(d.as_ptr() as *const [u8; 64]) }
}

impl Md5 {
    #[inline]
    fn finalize(&mut self) {
        let state = &mut self.state;
        let l = (self.length_bytes << 3) as u64;
        self.buffer.len64_padding::<LE, _>(l, |d| compress(state, convert(d)));
    }
}

impl BlockInput for Md5 {
    type BlockSize = U64;
}

impl Input for Md5 {
    #[inline]
    fn input<B: AsRef<[u8]>>(&mut self, input: B) {
        let input = input.as_ref();
        // Unlike Sha1 and Sha2, the length value in MD5 is defined as
        // the length of the message mod 2^64 - ie: integer overflow is OK.
        self.length_bytes = self.length_bytes.wrapping_add(input.len() as u64);
        let self_state = &mut self.state;
        self.buffer.input(input, |d| compress(self_state, convert(d)));
    }
}

impl FixedOutput for Md5 {
    type OutputSize = U16;

    #[inline]
    fn fixed_result(mut self) -> GenericArray<u8, Self::OutputSize> {
        let mut out = GenericArray::default();
        self.finalize();
        LE::write_u32_into(&self.state, &mut out);
        out
    }
}

impl Reset for Md5 {
    fn reset(&mut self) {
        self.state = consts::S0;
        self.length_bytes = 0;
        self.buffer.reset();
    }
}

impl_opaque_debug!(Md5);
impl_write!(Md5);
