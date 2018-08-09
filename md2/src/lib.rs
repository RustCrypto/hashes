//! The [MD2][1] hash function.
//!
//! [1]: https://en.wikipedia.org/wiki/MD2_(cryptography)

// Range loops are preferred for reading simplicity
#![cfg_attr(feature = "cargo-clippy", allow(needless_range_loop))]
#![cfg_attr(not(feature = "std"), no_std)]
#[macro_use] extern crate opaque_debug;
#[macro_use] extern crate digest;
extern crate block_buffer;

pub use digest::Digest;
use digest::{Input, BlockInput, FixedOutput};
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

impl Md2 {
    pub fn new() -> Md2 {
        Default::default()
    }

    fn finalize(&mut self) {
        let buf = self.buffer.pad_with::<Pkcs7>()
            .expect("we never use input_lazy");
        self.state.process_block(buf);
        let checksum = self.state.checksum;
        self.state.process_block(&checksum);
    }
}


impl BlockInput for Md2 {
    type BlockSize = U16;
}

impl Input for Md2 {
    fn process(&mut self, input: &[u8]) {
        let self_state = &mut self.state;
        self.buffer.input(input, |d: &Block| {
            self_state.process_block(d);
        });
    }
}

impl FixedOutput for Md2 {
    type OutputSize = U16;

    fn fixed_result(&mut self) -> GenericArray<u8, Self::OutputSize> {
        self.finalize();
        let res = GenericArray::clone_from_slice(&self.state.x[0..16]);
        *self = Default::default();
        res
    }
}

impl_opaque_debug!(Md2);
impl_write!(Md2);
