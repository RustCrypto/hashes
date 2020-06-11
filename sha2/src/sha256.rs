//! SHA-256
use crate::consts::{H224, H256, STATE_LEN};
use crate::sha256_compress::compress256;
use block_buffer::BlockBuffer;
use core::slice::from_ref;
use digest::consts::{U28, U32, U64};
use digest::{BlockInput, FixedOutputDirty, Reset, Update};

type BlockSize = U64;

/// Structure that keeps state of the Sha-256 operation and
/// contains the logic necessary to perform the final calculations.
#[derive(Clone)]
struct Engine256 {
    len: u64,
    buffer: BlockBuffer<BlockSize>,
    state: [u32; 8],
}

impl Engine256 {
    fn new(h: &[u32; STATE_LEN]) -> Engine256 {
        Engine256 {
            len: 0,
            buffer: Default::default(),
            state: *h,
        }
    }

    fn update(&mut self, input: &[u8]) {
        // Assumes that input.len() can be converted to u64 without overflow
        self.len += (input.len() as u64) << 3;
        let s = &mut self.state;
        self.buffer.input_blocks(input, |b| compress256(s, b));
    }

    fn finish(&mut self) {
        let s = &mut self.state;
        let l = self.len;
        self.buffer
            .len64_padding_be(l, |b| compress256(s, from_ref(b)));
    }

    fn reset(&mut self, h: &[u32; STATE_LEN]) {
        self.len = 0;
        self.buffer.reset();
        self.state = *h;
    }
}

/// The SHA-256 hash algorithm with the SHA-256 initial hash value.
#[derive(Clone)]
pub struct Sha256 {
    engine: Engine256,
}

impl Default for Sha256 {
    fn default() -> Self {
        Sha256 {
            engine: Engine256::new(&H256),
        }
    }
}

impl BlockInput for Sha256 {
    type BlockSize = BlockSize;
}

impl Update for Sha256 {
    fn update(&mut self, input: impl AsRef<[u8]>) {
        self.engine.update(input.as_ref());
    }
}

impl FixedOutputDirty for Sha256 {
    type OutputSize = U32;

    fn finalize_into_dirty(&mut self, out: &mut digest::Output<Self>) {
        self.engine.finish();
        let s = self.engine.state;
        for (chunk, v) in out.chunks_exact_mut(4).zip(s.iter()) {
            chunk.copy_from_slice(&v.to_be_bytes());
        }
    }
}

impl Reset for Sha256 {
    fn reset(&mut self) {
        self.engine.reset(&H256);
    }
}

/// The SHA-256 hash algorithm with the SHA-224 initial hash value. The result
/// is truncated to 224 bits.
#[derive(Clone)]
pub struct Sha224 {
    engine: Engine256,
}

impl Default for Sha224 {
    fn default() -> Self {
        Sha224 {
            engine: Engine256::new(&H224),
        }
    }
}

impl BlockInput for Sha224 {
    type BlockSize = BlockSize;
}

impl Update for Sha224 {
    fn update(&mut self, input: impl AsRef<[u8]>) {
        self.engine.update(input.as_ref());
    }
}

impl FixedOutputDirty for Sha224 {
    type OutputSize = U28;

    fn finalize_into_dirty(&mut self, out: &mut digest::Output<Self>) {
        self.engine.finish();
        let s = &self.engine.state[..7];
        for (chunk, v) in out.chunks_exact_mut(4).zip(s.iter()) {
            chunk.copy_from_slice(&v.to_be_bytes());
        }
    }
}

impl Reset for Sha224 {
    fn reset(&mut self) {
        self.engine.reset(&H224);
    }
}

opaque_debug::impl_opaque_debug!(Sha224);
opaque_debug::impl_opaque_debug!(Sha256);

digest::impl_write!(Sha224);
digest::impl_write!(Sha256);
