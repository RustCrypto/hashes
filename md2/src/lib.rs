//! The [MD2][1] hash function.
//!
//! [1]: https://en.wikipedia.org/wiki/MD2_(cryptography)

#![no_std]
extern crate byte_tools;
extern crate digest;
extern crate block_buffer;
extern crate generic_array;

pub use digest::Digest;
use byte_tools::copy_memory;
use block_buffer::{BlockBuffer, Pkcs7};
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

/// The MD2 hasher
#[derive(Copy, Clone, Default)]
pub struct Md2 {
    buffer: BlockBuffer<BlockSize>,
    state: Md2State,
}


impl Md2State {
    fn process_block(&mut self, input: &Block) {
        // Update state
        for (i, item) in input.iter().enumerate().take(16) {
            self.x[16 + i] = *item;
            self.x[32 + i] = self.x[16 + i] ^ self.x[i];
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
        for (k, item) in input.iter().enumerate().take(16) {
            self.checksum[k] ^= consts::S[(item ^ l) as usize];
            l = self.checksum[k];
        }
    }
}

impl Md2 {
    pub fn new() -> Md2 {
        Default::default()
    }

    fn finalize(&mut self) {
        let buf = self.buffer.pad_with::<Pkcs7>();
        self.state.process_block(buf);
        let checksum = self.state.checksum;
        self.state.process_block(&checksum);
    }
}


impl digest::BlockInput for Md2 {
    type BlockSize = BlockSize;
}

impl digest::Input for Md2 {
    fn process(&mut self, input: &[u8]) {
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
