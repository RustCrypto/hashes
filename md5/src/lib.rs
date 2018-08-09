//! The [MD5][1] hash function.
//!
//! [1]: https://en.wikipedia.org/wiki/MD5

#![cfg_attr(not(feature = "std"), no_std)]
extern crate byte_tools;
extern crate block_buffer;
#[macro_use] extern crate opaque_debug;
#[macro_use] extern crate digest;
#[cfg(feature = "asm")]
extern crate md5_asm as utils;

#[cfg(not(feature = "asm"))]
mod utils;

use utils::compress;

use byte_tools::write_u32v_le;
use block_buffer::BlockBuffer;

pub use digest::Digest;
use digest::{Input, BlockInput, FixedOutput};
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
    fn finalize(&mut self) -> [u32; 4] {
        {
            let self_state = &mut self.state;
            let l = (self.length_bytes << 3) as u64;
            self.buffer.len64_padding_le(0x80, l,
                |d| compress(self_state, convert(d)));
        }
        let res = self.state.clone();
        *self = Default::default();
        res
    }

    #[inline]
    fn consume(&mut self, input: &[u8]) {
        // Unlike Sha1 and Sha2, the length value in MD5 is defined as
        // the length of the message mod 2^64 - ie: integer overflow is OK.
        self.length_bytes = self.length_bytes.wrapping_add(input.len() as u64);
        let self_state = &mut self.state;
        self.buffer.input(input, |d| compress(self_state, convert(d)));
    }
}

impl BlockInput for Md5 {
    type BlockSize = U64;
}

impl Input for Md5 {
    #[inline]
    fn process(&mut self, input: &[u8]) {
        self.consume(input);
    }
}

impl FixedOutput for Md5 {
    type OutputSize = U16;

    #[inline]
    fn fixed_result(&mut self) -> GenericArray<u8, Self::OutputSize> {
        let mut out = GenericArray::default();
        let res = self.finalize();
        write_u32v_le(&mut out, &res);
        out
    }
}

impl_opaque_debug!(Md5);
impl_write!(Md5);
