//! An implementation of the [MD4][1] cryptographic hash algorithm.
//!
//! # Usage
//!
//! ```rust
//! # #[macro_use] extern crate hex_literal;
//! # extern crate md4;
//! # fn main() {
//! use md4::{Md4, Digest};
//!
//! // create a Md4 hasher instance
//! let mut hasher = Md4::new();
//!
//! // process input message
//! hasher.input(b"hello world");
//!
//! // acquire hash digest in the form of GenericArray,
//! // which in this case is equivalent to [u8; 16]
//! let result = hasher.result();
//! assert_eq!(result[..], hex!("aa010fbc1d14c795d86ef98c95479d17"));
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
#![cfg_attr(feature = "cargo-clippy", allow(many_single_char_names))]
#[macro_use] extern crate opaque_debug;
#[macro_use] pub extern crate digest;
extern crate fake_simd as simd;
extern crate block_buffer;
#[cfg(feature = "std")]
extern crate std;

pub use digest::Digest;
use digest::{Input, BlockInput, FixedOutput, Reset};
use block_buffer::BlockBuffer;
use block_buffer::byteorder::{LE, ByteOrder};
use simd::u32x4;
use digest::generic_array::GenericArray;
use digest::generic_array::typenum::{U16, U64};

// initial values for Md4State
const S: u32x4 = u32x4(0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476);

type Block = GenericArray<u8, U64>;

#[derive(Copy, Clone)]
struct Md4State {
    s: u32x4,
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
            a.wrapping_add(g(b, c, d)).wrapping_add(k)
                .wrapping_add(0x5A82_7999).rotate_left(s)
        }

        fn op3(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32) -> u32 {
            a.wrapping_add(h(b, c, d)).wrapping_add(k)
                .wrapping_add(0x6ED9_EBA1).rotate_left(s)
        }

        let mut a = self.s.0;
        let mut b = self.s.1;
        let mut c = self.s.2;
        let mut d = self.s.3;

        // load block to data
        let mut data = [0u32; 16];
        LE::read_u32_into(input, &mut data);

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

        self.s = self.s + u32x4(a, b, c, d);
    }
}

impl Default for Md4State {
    fn default() -> Self { Md4State { s: S } }
}

impl Md4 {
    fn finalize(&mut self) {
        let state = &mut self.state;
        let l = (self.length_bytes << 3) as u64;
        self.buffer.len64_padding::<LE, _>(l, |d| state.process_block(d))
    }
}

impl BlockInput for Md4 {
    type BlockSize = U64;
}

impl Input for Md4 {
    fn input<B: AsRef<[u8]>>(&mut self, input: B) {
        let input = input.as_ref();
        // Unlike Sha1 and Sha2, the length value in MD4 is defined as
        // the length of the message mod 2^64 - ie: integer overflow is OK.
        self.length_bytes = self.length_bytes.wrapping_add(input.len() as u64);
        let self_state = &mut self.state;
        self.buffer.input(input, |d: &Block| self_state.process_block(d));
    }
}

impl FixedOutput for Md4 {
    type OutputSize = U16;

    fn fixed_result(mut self) -> GenericArray<u8, Self::OutputSize> {
        self.finalize();

        let mut out = GenericArray::default();
        LE::write_u32(&mut out[0..4], self.state.s.0);
        LE::write_u32(&mut out[4..8], self.state.s.1);
        LE::write_u32(&mut out[8..12], self.state.s.2);
        LE::write_u32(&mut out[12..16], self.state.s.3);

        out
    }
}

impl Reset for Md4 {
    fn reset(&mut self) {
        self.state = Default::default();
        self.length_bytes = 0;
        self.buffer.reset();
    }
}

impl_opaque_debug!(Md4);
impl_write!(Md4);
