//! The [MD4][1] hash function.
//!
//! [1]: https://en.wikipedia.org/wiki/MD4

#![no_std]
extern crate generic_array;
extern crate fake_simd as simd;
extern crate byte_tools;
extern crate digest;
extern crate digest_buffer;

pub use digest::Digest;
use byte_tools::{write_u32_le, read_u32v_le};
use digest_buffer::{DigestBuffer};
use simd::u32x4;
use generic_array::GenericArray;
use generic_array::typenum::{U16, U64};

// initial values for Md4State
const S: u32x4 = u32x4(0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476);

type BlockSize = U64;

#[derive(Copy, Clone)]
struct Md4State {
    s: u32x4,
}

#[derive(Copy, Clone)]
pub struct Md4 {
    length_bytes: u64,
    buffer: DigestBuffer<BlockSize>,
    state: Md4State,
}


impl Md4State {
    fn new() -> Md4State {
        Md4State { s: S }
    }

    fn process_block(&mut self, input: &[u8]) {
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
            a.wrapping_add(g(b, c, d)).wrapping_add(k).wrapping_add(0x5a827999).rotate_left(s)
        }

        fn op3(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32) -> u32 {
            a.wrapping_add(h(b, c, d)).wrapping_add(k).wrapping_add(0x6ED9EBA1).rotate_left(s)
        }

        let mut a = self.s.0;
        let mut b = self.s.1;
        let mut c = self.s.2;
        let mut d = self.s.3;

        // load block to data
        let mut data = [0u32; 16];
        read_u32v_le(&mut data, input);

        // FIXME: replace [0, 4, 8, 12] with (0..16).step_by(4)
        // after stabilization

        // round 1
        for &i in [0, 4, 8, 12].iter() {
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
        for &i in [0, 2, 1, 3].iter() {
            a = op3(a, b, c, d, data[i], 3);
            d = op3(d, a, b, c, data[i + 8], 9);
            c = op3(c, d, a, b, data[i + 4], 11);
            b = op3(b, c, d, a, data[i + 12], 15);
        }

        self.s = self.s + u32x4(a, b, c, d);
    }
}

impl Md4 {
    pub fn new() -> Md4 {
        Md4 {
            length_bytes: 0,
            buffer: Default::default(),
            state: Md4State::new()
        }
    }

    fn finalize(&mut self) {
        let self_state = &mut self.state;
        self.buffer.standard_padding(8, |d: &[u8]| { self_state.process_block(d); });
        write_u32_le(self.buffer.next(4), (self.length_bytes << 3) as u32);
        write_u32_le(self.buffer.next(4), (self.length_bytes >> 29) as u32);
        self_state.process_block(self.buffer.full_buffer());
    }
}

impl Default for Md4 {
    fn default() -> Self { Self::new() }
}

impl Digest for Md4 {
    type OutputSize = U16;
    type BlockSize = BlockSize;

    fn input(&mut self, input: &[u8]) {
        // 2^64 - ie: integer overflow is OK.
        self.length_bytes += input.len() as u64;
        let self_state = &mut self.state;
        self.buffer.input(input, |d: &[u8]| { self_state.process_block(d);}
        );
    }

    fn result(mut self) -> GenericArray<u8, Self::OutputSize> {
        self.finalize();

        let mut out = GenericArray::new();
        write_u32_le(&mut out[0..4], self.state.s.0);
        write_u32_le(&mut out[4..8], self.state.s.1);
        write_u32_le(&mut out[8..12], self.state.s.2);
        write_u32_le(&mut out[12..16], self.state.s.3);
        out
    }
}
