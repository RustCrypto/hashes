//! The [MD2][1] hash function.
//!
//! [1]: https://en.wikipedia.org/wiki/MD2_(cryptography)

#![no_std]
extern crate byte_tools;
extern crate digest;
extern crate digest_buffer;
extern crate generic_array;

pub use digest::Digest;
use byte_tools::copy_memory;
use digest_buffer::DigestBuffer;
use generic_array::GenericArray;
use generic_array::typenum::{U16, U48};

mod consts;

type BlockSize = U16;
type Block = GenericArray<u8, U16>;

#[derive(Copy, Clone, Default)]
struct Md2State {
    x: GenericArray<u8, U48>,
    checksum: GenericArray<u8, U16>,
}

#[derive(Copy, Clone, Default)]
pub struct Md2 {
    buffer: DigestBuffer<BlockSize>,
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

impl Md2 {
    pub fn new() -> Md2 {
        Default::default()
    }

    fn finalize(&mut self) {
        let self_state = &mut self.state;
        {
            // Padding
            let rem = self.buffer.remaining();
            let mut buffer_end = self.buffer.next(rem);
            for idx in 0..rem {
                buffer_end[idx] = rem as u8;
            }
        }
        self_state.process_block(self.buffer.full_buffer());
        let checksum = self_state.checksum;
        self_state.process_block(&checksum);
    }
}

impl digest::Input for Md2 {
    type BlockSize = BlockSize;

    fn digest(&mut self, input: &[u8]) {
        let self_state = &mut self.state;
        self.buffer.input(input, |d: &Block| {
            self_state.process_block(d);
        });
    }
}

impl digest::FixedOutput for Md2 {
    type OutputSize = U16;

    fn fixed_result(mut self) -> GenericArray<u8, Self::OutputSize> {
        self.finalize();

        let mut out = GenericArray::default();
        copy_memory(&self.state.x[0..16], &mut out);
        out
    }
}
