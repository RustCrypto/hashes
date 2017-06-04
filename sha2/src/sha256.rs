use digest;
use generic_array::GenericArray;
use digest_buffer::DigestBuffer;
use generic_array::typenum::{U28, U32, U64};
use byte_tools::{write_u32v_be, write_u32_be, add_bytes_to_bits};

use consts::{STATE_LEN, H224, H256};

#[cfg(not(feature = "asm"))]
use sha256_utils::compress256;
#[cfg(feature = "asm")]
use sha2_asm::compress256;

type BlockSize = U64;
pub type Block = GenericArray<u8, BlockSize>;

/// A structure that represents that state of a digest computation for the
/// SHA-2 512 family of digest functions
#[derive(Clone, Copy)]
struct Engine256State {
    h: [u32; 8],
}

impl Engine256State {
    fn new(h: &[u32; STATE_LEN]) -> Engine256State { Engine256State { h: *h } }

    pub fn process_block(&mut self, data: &Block) {
        compress256(&mut self.h, data);
    }
}

/// A structure that keeps track of the state of the Sha-256 operation and
/// contains the logic necessary to perform the final calculations.
#[derive(Clone, Copy)]
struct Engine256 {
    length_bits: u64,
    buffer: DigestBuffer<BlockSize>,
    state: Engine256State,
}

impl Engine256 {
    fn new(h: &[u32; STATE_LEN]) -> Engine256 {
        Engine256 {
            length_bits: 0,
            buffer: Default::default(),
            state: Engine256State::new(h),
        }
    }

    fn input(&mut self, input: &[u8]) {
        // Assumes that input.len() can be converted to u64 without overflow
        self.length_bits = add_bytes_to_bits(self.length_bits,
                                             input.len() as u64);
        let self_state = &mut self.state;
        self.buffer
            .input(input, |input| self_state.process_block(input));
    }

    fn finish(&mut self) {
        let self_state = &mut self.state;
        self.buffer.standard_padding(8, |input| {
            self_state.process_block(input)
        });
        write_u32_be(self.buffer.next(4), (self.length_bits >> 32) as u32);
        write_u32_be(self.buffer.next(4), self.length_bits as u32);
        self_state.process_block(self.buffer.full_buffer());
    }
}


/// The SHA-256 hash algorithm with the SHA-256 initial hash value.
#[derive(Clone, Copy)]
pub struct Sha256 {
    engine: Engine256,
}

impl Default for Sha256 {
    fn default() -> Self { Sha256 { engine: Engine256::new(&H256) } }
}

impl digest::Input for Sha256 {
    type BlockSize = BlockSize;

    fn digest(&mut self, msg: &[u8]) { self.engine.input(msg); }
}

impl digest::FixedOutput for Sha256 {
    type OutputSize = U32;

    fn fixed_result(mut self) -> GenericArray<u8, Self::OutputSize> {
        self.engine.finish();
        let mut out = GenericArray::default();
        write_u32v_be(&mut out, &self.engine.state.h);
        out
    }
}

/// The SHA-256 hash algorithm with the SHA-224 initial hash value. The result
/// is truncated to 224 bits.
#[derive(Clone, Copy)]
pub struct Sha224 {
    engine: Engine256,
}

impl Default for Sha224 {
    fn default() -> Self { Sha224 { engine: Engine256::new(&H224) } }
}

impl digest::Input for Sha224 {
    type BlockSize = BlockSize;

    fn digest(&mut self, msg: &[u8]) { self.engine.input(msg); }
}

impl digest::FixedOutput for Sha224 {
    type OutputSize = U28;

    fn fixed_result(mut self) -> GenericArray<u8, Self::OutputSize> {
        self.engine.finish();
        let mut out = GenericArray::default();
        write_u32v_be(&mut out[..28], &self.engine.state.h[..7]);
        out
    }
}
