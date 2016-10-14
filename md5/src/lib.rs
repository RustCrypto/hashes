//! The [MD5][1] hash function.
//!
//! [1]: https://en.wikipedia.org/wiki/MD5

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


mod consts;
use consts::{C1, C2, C3, C4, S};

type BlockSize = U64;

/// A structure that represents that state of a digest computation for the MD5
/// digest function
#[derive(Copy, Clone)]
struct Md5State {
    s: u32x4,
}

impl Md5State {
    fn new() -> Md5State {
        Md5State { s: S }
    }

    fn process_block(&mut self, input: &[u8]) {
        fn f(u: u32, v: u32, w: u32) -> u32 { (u & v) | (!u & w) }

        fn g(u: u32, v: u32, w: u32) -> u32 { (u & w) | (v & !w) }

        fn h(u: u32, v: u32, w: u32) -> u32 { u ^ v ^ w }

        fn i(u: u32, v: u32, w: u32) -> u32 { v ^ (u | !w) }

        fn op_f(w: u32, x: u32, y: u32, z: u32, m: u32, s: u32) -> u32 {
            w.wrapping_add(f(x, y, z))
                .wrapping_add(m)
                .rotate_left(s)
                .wrapping_add(x)
        }

        fn op_g(w: u32, x: u32, y: u32, z: u32, m: u32, s: u32) -> u32 {
            w.wrapping_add(g(x, y, z))
                .wrapping_add(m)
                .rotate_left(s)
                .wrapping_add(x)
        }

        fn op_h(w: u32, x: u32, y: u32, z: u32, m: u32, s: u32) -> u32 {
            w.wrapping_add(h(x, y, z))
                .wrapping_add(m)
                .rotate_left(s)
                .wrapping_add(x)
        }

        fn op_i(w: u32, x: u32, y: u32, z: u32, m: u32, s: u32) -> u32 {
            w.wrapping_add(i(x, y, z))
                .wrapping_add(m)
                .rotate_left(s)
                .wrapping_add(x)
        }

        let u32x4(mut a, mut b, mut c, mut d) = self.s;

        let mut data = [0u32; 16];

        read_u32v_le(&mut data, input);

        // FIXME: replace [0, 4, 8, 12] with (0..16).step_by(4)
        // after stabilization

        // round 1
        for i in [0, 4, 8, 12].iter().cloned() {
            a = op_f(a, b, c, d, data[i].wrapping_add(C1[i]), 7);
            d = op_f(d, a, b, c, data[i + 1].wrapping_add(C1[i + 1]), 12);
            c = op_f(c, d, a, b, data[i + 2].wrapping_add(C1[i + 2]), 17);
            b = op_f(b, c, d, a, data[i + 3].wrapping_add(C1[i + 3]), 22);
        }

        // round 2
        let mut t = 1;
        for i in [0, 4, 8, 12].iter().cloned() {
            let q = data[t & 0x0f].wrapping_add(C2[i]);
            a = op_g(a, b, c, d, q, 5);
            let q = data[(t + 5) & 0x0f].wrapping_add(C2[i + 1]);
            d = op_g(d, a, b, c, q, 9);
            let q = data[(t + 10) & 0x0f].wrapping_add(C2[i + 2]);
            c = op_g(c, d, a, b, q, 14);
            let q = data[(t + 15) & 0x0f].wrapping_add(C2[i + 3]);
            b = op_g(b, c, d, a, q, 20);
            t += 20;
        }

        // round 3
        t = 5;
        for i in [0, 4, 8, 12].iter().cloned() {
            let q = data[t & 0x0f].wrapping_add(C3[i]);
            a = op_h(a, b, c, d, q, 4);
            let q = data[(t + 3) & 0x0f].wrapping_add(C3[i + 1]);
            d = op_h(d, a, b, c, q, 11);
            let q = data[(t + 6) & 0x0f].wrapping_add(C3[i + 2]);
            c = op_h(c, d, a, b, q, 16);
            let q = data[(t + 9) & 0x0f].wrapping_add(C3[i + 3]);
            b = op_h(b, c, d, a, q, 23);
            t += 12;
        }

        // round 4
        t = 0;
        for i in [0, 4, 8, 12].iter().cloned() {
            let q = data[t & 0x0f].wrapping_add(C4[i]);
            a = op_i(a, b, c, d, q, 6);
            let q = data[(t + 7) & 0x0f].wrapping_add(C4[i + 1]);
            d = op_i(d, a, b, c, q, 10);
            let q = data[(t + 14) & 0x0f].wrapping_add(C4[i + 2]);
            c = op_i(c, d, a, b, q, 15);
            let q = data[(t + 21) & 0x0f].wrapping_add(C4[i + 3]);
            b = op_i(b, c, d, a, q, 21);
            t += 28;
        }

        self.s = self.s + u32x4(a, b, c, d);
    }
}

/// The MD5 Digest algorithm
#[derive(Copy, Clone)]
pub struct Md5 {
    length_bytes: u64,
    buffer: DigestBuffer<BlockSize>,
    state: Md5State,
}

impl Md5 {
    fn finalize(&mut self) {
        let self_state = &mut self.state;
        self.buffer.standard_padding(8, |d: &[u8]| {
            self_state.process_block(d);
        });
        write_u32_le(self.buffer.next(4), (self.length_bytes << 3) as u32);
        write_u32_le(self.buffer.next(4), (self.length_bytes >> 29) as u32);
        self_state.process_block(self.buffer.full_buffer());
    }
}

impl Digest for Md5 {
    type R = U16;
    type B = BlockSize;

    fn new() -> Md5 {
        Md5 {
            length_bytes: 0,
            buffer: Default::default(),
            state: Md5State::new(),
        }
    }

    fn input(&mut self, input: &[u8]) {
        // Unlike Sha1 and Sha2, the length value in MD5 is defined as
        // the length of the message mod 2^64 - ie: integer overflow is OK.
        self.length_bytes += input.len() as u64;
        let self_state = &mut self.state;
        self.buffer.input(input, |d: &[u8]| {
            self_state.process_block(d);
        });
    }

    fn result(mut self) -> GenericArray<u8, Self::R> {
        self.finalize();

        let mut out = GenericArray::new();
        write_u32_le(&mut out[0..4], self.state.s.0);
        write_u32_le(&mut out[4..8], self.state.s.1);
        write_u32_le(&mut out[8..12], self.state.s.2);
        write_u32_le(&mut out[12..16], self.state.s.3);
        out
    }
}
