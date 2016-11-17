use generic_array::GenericArray;
use digest::Digest;
use digest_buffer::DigestBuffer;
use generic_array::typenum::{U28, U32, U48, U64, U128};
use byte_tools::{write_u64v_be, write_u32_be, write_u64_be, add_bytes_to_bits_tuple};

use consts::{STATE_LEN, H384, H512, H512_TRUNC_224, H512_TRUNC_256};

use sha512_utils::sha512_digest_block;

type BlockSize = U128;

/// A structure that represents that state of a digest computation for the
/// SHA-2 512 family of digest functions
#[derive(Copy, Clone)]
struct Engine512State {
    h: [u64; 8],
}

impl Engine512State {
    fn new(h: &[u64; 8]) -> Engine512State { Engine512State { h: *h } }

    pub fn process_block(&mut self, data: &[u8]) {
        sha512_digest_block(&mut self.h, data);
    }
}

/// A structure that keeps track of the state of the Sha-512 operation and
/// contains the logic necessary to perform the final calculations.
#[derive(Copy, Clone)]
struct Engine512 {
    length_bits: (u64, u64),
    buffer: DigestBuffer<BlockSize>,
    state: Engine512State,
}

impl Engine512 {
    fn new(h: &[u64; STATE_LEN]) -> Engine512 {
        Engine512 {
            length_bits: (0, 0),
            buffer: Default::default(),
            state: Engine512State::new(h),
        }
    }

    fn input(&mut self, input: &[u8]) {
        // Assumes that input.len() can be converted to u64 without overflow
        self.length_bits = add_bytes_to_bits_tuple(self.length_bits,
                                                   input.len() as u64);
        let self_state = &mut self.state;
        self.buffer
            .input(input, |input: &[u8]| self_state.process_block(input));
    }

    fn finish(&mut self) {
        let self_state = &mut self.state;
        self.buffer.standard_padding(16, |input: &[u8]| {
            self_state.process_block(input)
        });
        match self.length_bits {
            (hi, low) => {
                write_u64_be(self.buffer.next(8), hi);
                write_u64_be(self.buffer.next(8), low);
            },
        }
        self_state.process_block(self.buffer.full_buffer());
    }
}


/// The SHA-512 hash algorithm with the SHA-512 initial hash value.
#[derive(Copy, Clone)]
pub struct Sha512 {
    engine: Engine512,
}

impl Sha512 {
    pub fn new() -> Sha512 { Sha512 { engine: Engine512::new(&H512) } }
}

impl Default for Sha512 {
    fn default() -> Self { Self::new() }
}

impl Digest for Sha512 {
    type OutputSize = U64;
    type BlockSize = BlockSize;

    fn input(&mut self, msg: &[u8]) { self.engine.input(msg); }

    fn result(mut self) -> GenericArray<u8, Self::OutputSize> {
        self.engine.finish();

        let mut out = GenericArray::new();
        write_u64v_be(&mut out, &self.engine.state.h[..]);
        out
    }
}



/// The SHA-512 hash algorithm with the SHA-384 initial hash value. The result
/// is truncated to 384 bits.
#[derive(Copy, Clone)]
pub struct Sha384 {
    engine: Engine512,
}

impl Sha384 {
    pub fn new() -> Sha384 { Sha384 { engine: Engine512::new(&H384) } }
}

impl Default for Sha384 {
    fn default() -> Self { Self::new() }
}

impl Digest for Sha384 {
    type OutputSize = U48;
    type BlockSize = BlockSize;

    fn input(&mut self, d: &[u8]) { self.engine.input(d); }

    fn result(mut self) -> GenericArray<u8, Self::OutputSize> {
        self.engine.finish();

        let mut out = GenericArray::new();
        write_u64v_be(&mut out, &self.engine.state.h[..6]);
        out
    }
}


/// The SHA-512 hash algorithm with the SHA-512/256 initial hash value. The
/// result is truncated to 256 bits.
#[derive(Clone, Copy)]
pub struct Sha512Trunc256 {
    engine: Engine512,
}

impl Sha512Trunc256 {
    pub fn new() -> Sha512Trunc256 {
        Sha512Trunc256 { engine: Engine512::new(&H512_TRUNC_256) }
    }
}

impl Default for Sha512Trunc256 {
    fn default() -> Self { Self::new() }
}


impl Digest for Sha512Trunc256 {
    type OutputSize = U32;
    type BlockSize = BlockSize;

    fn input(&mut self, d: &[u8]) { self.engine.input(d); }

    fn result(mut self) -> GenericArray<u8, Self::OutputSize> {
        self.engine.finish();

        let mut out = GenericArray::new();
        write_u64v_be(&mut out, &self.engine.state.h[..4]);
        out
    }
}


/// The SHA-512 hash algorithm with the SHA-512/224 initial hash value.
/// The result is truncated to 224 bits.
#[derive(Clone, Copy)]
pub struct Sha512Trunc224 {
    engine: Engine512,
}

impl Sha512Trunc224 {
    pub fn new() -> Sha512Trunc224 {
        Sha512Trunc224 { engine: Engine512::new(&H512_TRUNC_224) }
    }
}

impl Default for Sha512Trunc224 {
    fn default() -> Self { Self::new() }
}

impl Digest for Sha512Trunc224 {
    type OutputSize = U28;
    type BlockSize = BlockSize;

    fn input(&mut self, d: &[u8]) { self.engine.input(d); }

    fn result(mut self) -> GenericArray<u8, Self::OutputSize> {
        self.engine.finish();

        let mut out = GenericArray::new();
        write_u64v_be(&mut out[..24], &self.engine.state.h[..3]);
        write_u32_be(&mut out[24..28], (self.engine.state.h[3] >> 32) as u32);
        out
    }
}
