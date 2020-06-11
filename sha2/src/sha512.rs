//! SHA-512

use crate::consts::{H384, H512, H512_TRUNC_224, H512_TRUNC_256, STATE_LEN};
use block_buffer::BlockBuffer;
use digest::{
    consts::{U128, U28, U32, U48, U64},
    generic_array::GenericArray,
};
use digest::{BlockInput, FixedOutputDirty, Reset, Update};

#[cfg(any(not(feature = "asm"), target_arch = "aarch64"))]
use crate::sha512_utils::compress512;

#[cfg(all(feature = "asm", not(target_arch = "aarch64")))]
use sha2_asm::compress512;

type BlockSize = U128;
type Block = GenericArray<u8, BlockSize>;

/// A structure that represents that state of a digest computation for the
/// SHA-2 512 family of digest functions
#[derive(Clone)]
struct Engine512State {
    h: [u64; 8],
}

impl Engine512State {
    fn new(h: &[u64; 8]) -> Engine512State {
        Engine512State { h: *h }
    }

    pub fn process_block(&mut self, block: &Block) {
        let block = unsafe { &*(block.as_ptr() as *const [u8; 128]) };
        compress512(&mut self.h, block);
    }
}

/// A structure that keeps track of the state of the Sha-512 operation and
/// contains the logic necessary to perform the final calculations.
#[derive(Clone)]
struct Engine512 {
    len: u128,
    buffer: BlockBuffer<BlockSize>,
    state: Engine512State,
}

impl Engine512 {
    fn new(h: &[u64; STATE_LEN]) -> Engine512 {
        Engine512 {
            len: 0,
            buffer: Default::default(),
            state: Engine512State::new(h),
        }
    }

    fn update(&mut self, input: &[u8]) {
        self.len += (input.len() as u128) << 3;
        let s = &mut self.state;
        self.buffer.input_block(input, |d| s.process_block(d));
    }

    fn finish(&mut self) {
        let s = &mut self.state;
        self.buffer
            .len128_padding_be(self.len, |d| s.process_block(d));
    }

    fn reset(&mut self, h: &[u64; STATE_LEN]) {
        self.len = 0;
        self.buffer.reset();
        self.state = Engine512State::new(h);
    }
}

/// The SHA-512 hash algorithm with the SHA-512 initial hash value.
#[derive(Clone)]
pub struct Sha512 {
    engine: Engine512,
}

impl Default for Sha512 {
    fn default() -> Self {
        Sha512 {
            engine: Engine512::new(&H512),
        }
    }
}

impl BlockInput for Sha512 {
    type BlockSize = BlockSize;
}

impl Update for Sha512 {
    fn update(&mut self, input: impl AsRef<[u8]>) {
        self.engine.update(input.as_ref());
    }
}

impl FixedOutputDirty for Sha512 {
    type OutputSize = U64;

    fn finalize_into_dirty(&mut self, out: &mut digest::Output<Self>) {
        self.engine.finish();
        let h = self.engine.state.h;
        for (chunk, v) in out.chunks_exact_mut(8).zip(h.iter()) {
            chunk.copy_from_slice(&v.to_be_bytes());
        }
    }
}

impl Reset for Sha512 {
    fn reset(&mut self) {
        self.engine.reset(&H512);
    }
}

/// The SHA-512 hash algorithm with the SHA-384 initial hash value. The result
/// is truncated to 384 bits.
#[derive(Clone)]
pub struct Sha384 {
    engine: Engine512,
}

impl Default for Sha384 {
    fn default() -> Self {
        Sha384 {
            engine: Engine512::new(&H384),
        }
    }
}

impl BlockInput for Sha384 {
    type BlockSize = BlockSize;
}

impl Update for Sha384 {
    fn update(&mut self, input: impl AsRef<[u8]>) {
        self.engine.update(input.as_ref());
    }
}

impl FixedOutputDirty for Sha384 {
    type OutputSize = U48;

    fn finalize_into_dirty(&mut self, out: &mut digest::Output<Self>) {
        self.engine.finish();
        let h = &self.engine.state.h[..6];
        for (chunk, v) in out.chunks_exact_mut(8).zip(h.iter()) {
            chunk.copy_from_slice(&v.to_be_bytes());
        }
    }
}

impl Reset for Sha384 {
    fn reset(&mut self) {
        self.engine.reset(&H384);
    }
}

/// The SHA-512 hash algorithm with the SHA-512/256 initial hash value. The
/// result is truncated to 256 bits.
#[derive(Clone)]
pub struct Sha512Trunc256 {
    engine: Engine512,
}

impl Default for Sha512Trunc256 {
    fn default() -> Self {
        Sha512Trunc256 {
            engine: Engine512::new(&H512_TRUNC_256),
        }
    }
}

impl BlockInput for Sha512Trunc256 {
    type BlockSize = BlockSize;
}

impl Update for Sha512Trunc256 {
    fn update(&mut self, input: impl AsRef<[u8]>) {
        self.engine.update(input.as_ref());
    }
}

impl FixedOutputDirty for Sha512Trunc256 {
    type OutputSize = U32;

    fn finalize_into_dirty(&mut self, out: &mut digest::Output<Self>) {
        self.engine.finish();
        let h = &self.engine.state.h[..4];
        for (chunk, v) in out.chunks_exact_mut(8).zip(h.iter()) {
            chunk.copy_from_slice(&v.to_be_bytes());
        }
    }
}

impl Reset for Sha512Trunc256 {
    fn reset(&mut self) {
        self.engine.reset(&H512_TRUNC_256);
    }
}

/// The SHA-512 hash algorithm with the SHA-512/224 initial hash value.
/// The result is truncated to 224 bits.
#[derive(Clone)]
pub struct Sha512Trunc224 {
    engine: Engine512,
}

impl Default for Sha512Trunc224 {
    fn default() -> Self {
        Sha512Trunc224 {
            engine: Engine512::new(&H512_TRUNC_224),
        }
    }
}

impl BlockInput for Sha512Trunc224 {
    type BlockSize = BlockSize;
}

impl Update for Sha512Trunc224 {
    fn update(&mut self, input: impl AsRef<[u8]>) {
        self.engine.update(input.as_ref());
    }
}

impl FixedOutputDirty for Sha512Trunc224 {
    type OutputSize = U28;

    fn finalize_into_dirty(&mut self, out: &mut digest::Output<Self>) {
        self.engine.finish();
        let h = &self.engine.state.h;
        for (chunk, v) in out.chunks_exact_mut(8).zip(h[..3].iter()) {
            chunk.copy_from_slice(&v.to_be_bytes());
        }
        out[24..28].copy_from_slice(&h[3].to_be_bytes()[..4]);
    }
}

impl Reset for Sha512Trunc224 {
    fn reset(&mut self) {
        self.engine.reset(&H512_TRUNC_224);
    }
}

opaque_debug::implement!(Sha384);
opaque_debug::implement!(Sha512);
opaque_debug::implement!(Sha512Trunc224);
opaque_debug::implement!(Sha512Trunc256);

digest::impl_write!(Sha384);
digest::impl_write!(Sha512);
digest::impl_write!(Sha512Trunc224);
digest::impl_write!(Sha512Trunc256);
