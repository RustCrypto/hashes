//! The [MD5][1] hash function.
//!
//! [1]: https://en.wikipedia.org/wiki/MD5

#![no_std]
extern crate byte_tools;
extern crate block_buffer;
#[cfg(feature = "asm")]
extern crate md5_asm as utils;
#[cfg(feature = "generic")]
extern crate generic_array;
#[cfg(feature = "generic")]
extern crate digest;

#[cfg(not(feature = "asm"))]
mod utils;

use utils::compress;

use byte_tools::write_u32v_le;
use block_buffer::BlockBuffer512;

#[cfg(feature = "generic")]
pub use digest::Digest;
#[cfg(feature = "generic")]
use generic_array::GenericArray;
#[cfg(feature = "generic")]
use generic_array::typenum::{U16, U64};

mod consts;

/// The MD5 hasher
#[derive(Copy, Clone)]
pub struct Md5 {
    length_bytes: u64,
    buffer: BlockBuffer512,
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

impl Md5 {
    #[inline]
    fn finalize(mut self) -> [u32; 4] {
        {
            let self_state = &mut self.state;
            let l = (self.length_bytes << 3) as u64;
            self.buffer.len_padding(l, |d| compress(self_state, d));
        }
        self.state
    }

    #[inline]
    pub fn hash(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        write_u32v_le(&mut out, &self.finalize());
        out
    }

    #[inline]
    pub fn consume(&mut self, input: &[u8]) {
        // Unlike Sha1 and Sha2, the length value in MD5 is defined as
        // the length of the message mod 2^64 - ie: integer overflow is OK.
        self.length_bytes += input.len() as u64;
        let self_state = &mut self.state;
        self.buffer.input(input, |d| compress(self_state, d));
    }
}

#[cfg(feature = "generic")]
impl digest::BlockInput for Md5 {
    type BlockSize = U64;
}

#[cfg(feature = "generic")]
impl digest::Input for Md5 {
    #[inline]
    fn process(&mut self, input: &[u8]) {
        self.consume(input);
    }
}

#[cfg(feature = "generic")]
impl digest::FixedOutput for Md5 {
    type OutputSize = U16;

    #[inline]
    fn fixed_result(self) -> GenericArray<u8, Self::OutputSize> {
        let mut out = GenericArray::default();
        write_u32v_le(&mut out, &self.finalize());
        out
    }
}
