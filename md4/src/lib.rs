//! An implementation of the [MD4][1] cryptographic hash algorithm.
//!
//! # Usage
//!
//! ```rust
//! use md4::{Md4, Digest};
//! use hex_literal::hex;
//!
//! // create a Md4 hasher instance
//! let mut hasher = Md4::new();
//!
//! // process input message
//! hasher.update(b"hello world");
//!
//! // acquire hash digest in the form of GenericArray,
//! // which in this case is equivalent to [u8; 16]
//! let result = hasher.finalize();
//! assert_eq!(result[..], hex!("aa010fbc1d14c795d86ef98c95479d17"));
//! ```
//!
//! Also see [RustCrypto/hashes][2] readme.
//!
//! [1]: https://en.wikipedia.org/wiki/MD4
//! [2]: https://github.com/RustCrypto/hashes

#![no_std]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![deny(unsafe_code)]
#![warn(rust_2018_idioms)]
#![allow(clippy::many_single_char_names)]

#[cfg(feature = "std")]
extern crate std;

use core::convert::TryInto;
pub use digest::{self, Digest};

use block_buffer::BlockBuffer;
use digest::{
    consts::{U16, U64},
    generic_array::GenericArray,
};
use digest::{BlockInput, FixedOutputDirty, Reset, Update};

// initial values for Md4State
const S: [u32; 4] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476];

type Block = GenericArray<u8, U64>;

#[derive(Copy, Clone)]
struct Md4State {
    s: [u32; 4],
}

/// The MD4 hasher
#[derive(Clone, Default)]
pub struct Md4 {
    length_bytes: u64,
    buffer: BlockBuffer<U64>,
    state: Md4State,
}

impl Md4State {
    fn process_block(&mut self, input: &Block) {
        fn f(x: u32, y: u32, z: u32) -> u32 {
            (x & y) | (!x & z)
        }

        fn g(x: u32, y: u32, z: u32) -> u32 {
            (x & y) | (x & z) | (y & z)
        }

        fn h(x: u32, y: u32, z: u32) -> u32 {
            x ^ y ^ z
        }

        fn op1(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32) -> u32 {
            a.wrapping_add(f(b, c, d)).wrapping_add(k).rotate_left(s)
        }

        fn op2(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32) -> u32 {
            a.wrapping_add(g(b, c, d))
                .wrapping_add(k)
                .wrapping_add(0x5A82_7999)
                .rotate_left(s)
        }

        fn op3(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32) -> u32 {
            a.wrapping_add(h(b, c, d))
                .wrapping_add(k)
                .wrapping_add(0x6ED9_EBA1)
                .rotate_left(s)
        }

        let mut a = self.s[0];
        let mut b = self.s[1];
        let mut c = self.s[2];
        let mut d = self.s[3];

        // load block to data
        let mut data = [0u32; 16];
        for (o, chunk) in data.iter_mut().zip(input.chunks_exact(4)) {
            *o = u32::from_le_bytes(chunk.try_into().unwrap());
        }

        // round 1
        for &i in &[0, 4, 8, 12] {
            a = op1(a, b, c, d, data[i], 3);
            d = op1(d, a, b, c, data[i + 1], 7);
            c = op1(c, d, a, b, data[i + 2], 11);
            b = op1(b, c, d, a, data[i + 3], 19);
        }

        // round 2
        for i in 0..4 {
            a = op2(a, b, c, d, data[i], 3);
            d = op2(d, a, b, c, data[i + 4], 5);
            c = op2(c, d, a, b, data[i + 8], 9);
            b = op2(b, c, d, a, data[i + 12], 13);
        }

        // round 3
        for &i in &[0, 2, 1, 3] {
            a = op3(a, b, c, d, data[i], 3);
            d = op3(d, a, b, c, data[i + 8], 9);
            c = op3(c, d, a, b, data[i + 4], 11);
            b = op3(b, c, d, a, data[i + 12], 15);
        }

        self.s[0] = self.s[0].wrapping_add(a);
        self.s[1] = self.s[1].wrapping_add(b);
        self.s[2] = self.s[2].wrapping_add(c);
        self.s[3] = self.s[3].wrapping_add(d);
    }
}

impl Default for Md4State {
    fn default() -> Self {
        Md4State { s: S }
    }
}

impl Md4 {
    fn finalize_inner(&mut self) {
        let state = &mut self.state;
        let l = (self.length_bytes << 3) as u64;
        self.buffer.len64_padding_le(l, |d| state.process_block(d))
    }
}

impl BlockInput for Md4 {
    type BlockSize = U64;
}

impl Update for Md4 {
    fn update(&mut self, input: impl AsRef<[u8]>) {
        let input = input.as_ref();
        // Unlike Sha1 and Sha2, the length value in MD4 is defined as
        // the length of the message mod 2^64 - ie: integer overflow is OK.
        self.length_bytes = self.length_bytes.wrapping_add(input.len() as u64);
        let s = &mut self.state;
        self.buffer.input_block(input, |d| s.process_block(d));
    }
}

impl FixedOutputDirty for Md4 {
    type OutputSize = U16;

    fn finalize_into_dirty(&mut self, out: &mut digest::Output<Self>) {
        self.finalize_inner();

        for (chunk, v) in out.chunks_exact_mut(4).zip(self.state.s.iter()) {
            chunk.copy_from_slice(&v.to_le_bytes());
        }
    }
}

impl Reset for Md4 {
    fn reset(&mut self) {
        self.state = Default::default();
        self.length_bytes = 0;
        self.buffer.reset();
    }
}

opaque_debug::implement!(Md4);
digest::impl_write!(Md4);
