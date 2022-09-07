//! An implementation of the [Tiger][1] cryptographic hash algorithms.
//!
//! Tiger2 is a variant of the original Tiger with a small padding tweak.
//!
//! # Usage
//!
//! ```rust
//! use hex_literal::hex;
//! use tiger::{Tiger, Digest};
//!
//! // create a Tiger object
//! let mut hasher = Tiger::new();
//!
//! // process input message
//! hasher.update(b"hello world");
//!
//! // acquire hash digest in the form of GenericArray,
//! // which in this case is equivalent to [u8; 24]
//! let result = hasher.finalize();
//! assert_eq!(result[..], hex!("4c8fbddae0b6f25832af45e7c62811bb64ec3e43691e9cc3"));
//! ```
//!
//! Also see [RustCrypto/hashes][2] readme.
//!
//! [1]: https://en.wikipedia.org/wiki/Tiger_(hash_function)
//! [2]: https://github.com/RustCrypto/hashes

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub use digest::{self, Digest};

use core::{convert::TryInto, fmt};
use digest::{
    block_buffer::Eager,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore,
        OutputSizeUser, Reset, UpdateCore,
    },
    crypto_common::{DeserializeStateError, SerializableState, SerializedState},
    generic_array::{
        sequence::{Concat, Split},
        GenericArray,
    },
    typenum::{Unsigned, U24, U32, U64},
    HashMarker, Output,
};

mod compress;
mod tables;
use compress::compress;

type State = [u64; STATE_LEN];
const STATE_LEN: usize = 3;
const S0: State = [
    0x0123_4567_89AB_CDEF,
    0xFEDC_BA98_7654_3210,
    0xF096_A5B4_C3B2_E187,
];

/// Core Tiger hasher state.
#[derive(Clone)]
pub struct TigerCore {
    block_len: u64,
    state: State,
}

impl HashMarker for TigerCore {}

impl BlockSizeUser for TigerCore {
    type BlockSize = U64;
}

impl BufferKindUser for TigerCore {
    type BufferKind = Eager;
}

impl OutputSizeUser for TigerCore {
    type OutputSize = U24;
}

impl UpdateCore for TigerCore {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.block_len += blocks.len() as u64;
        for block in blocks {
            compress(&mut self.state, block.as_ref());
        }
    }
}

impl FixedOutputCore for TigerCore {
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let bs = Self::BlockSize::U64 as u64;
        let pos = buffer.get_pos() as u64;
        let bit_len = 8 * (pos + bs * self.block_len);

        buffer.digest_pad(1, &bit_len.to_le_bytes(), |b| {
            compress(&mut self.state, b.as_ref())
        });
        for (chunk, v) in out.chunks_exact_mut(8).zip(self.state.iter()) {
            chunk.copy_from_slice(&v.to_le_bytes());
        }
    }
}

impl Default for TigerCore {
    fn default() -> Self {
        Self {
            block_len: 0,
            state: S0,
        }
    }
}

impl Reset for TigerCore {
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl AlgorithmName for TigerCore {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Tiger")
    }
}

impl fmt::Debug for TigerCore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TigerCore { ... }")
    }
}

impl SerializableState for TigerCore {
    type SerializedStateSize = U32;

    fn serialize(&self) -> SerializedState<Self> {
        let mut serialized_state = GenericArray::<_, U24>::default();

        for (val, chunk) in self.state.iter().zip(serialized_state.chunks_exact_mut(8)) {
            chunk.copy_from_slice(&val.to_le_bytes());
        }

        serialized_state.concat(self.block_len.to_le_bytes().into())
    }

    fn deserialize(
        serialized_state: &SerializedState<Self>,
    ) -> Result<Self, DeserializeStateError> {
        let (serialized_state, serialized_block_len) = Split::<_, U24>::split(serialized_state);

        let mut state = [0; STATE_LEN];
        for (val, chunk) in state.iter_mut().zip(serialized_state.chunks_exact(8)) {
            *val = u64::from_le_bytes(chunk.try_into().unwrap());
        }

        let block_len = u64::from_le_bytes((*serialized_block_len).into());

        Ok(Self { state, block_len })
    }
}

/// Core Tiger2 hasher state.
#[derive(Clone)]
pub struct Tiger2Core {
    block_len: u64,
    state: State,
}

impl HashMarker for Tiger2Core {}

impl BlockSizeUser for Tiger2Core {
    type BlockSize = U64;
}

impl BufferKindUser for Tiger2Core {
    type BufferKind = Eager;
}

impl OutputSizeUser for Tiger2Core {
    type OutputSize = U24;
}

impl UpdateCore for Tiger2Core {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.block_len += blocks.len() as u64;
        for block in blocks {
            compress(&mut self.state, block.as_ref());
        }
    }
}

impl FixedOutputCore for Tiger2Core {
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let bs = Self::BlockSize::U64 as u64;
        let pos = buffer.get_pos() as u64;
        let bit_len = 8 * (pos + bs * self.block_len);

        buffer.len64_padding_le(bit_len, |b| compress(&mut self.state, b.as_ref()));
        for (chunk, v) in out.chunks_exact_mut(8).zip(self.state.iter()) {
            chunk.copy_from_slice(&v.to_le_bytes());
        }
    }
}

impl Default for Tiger2Core {
    fn default() -> Self {
        Self {
            block_len: 0,
            state: [
                0x0123_4567_89AB_CDEF,
                0xFEDC_BA98_7654_3210,
                0xF096_A5B4_C3B2_E187,
            ],
        }
    }
}

impl Reset for Tiger2Core {
    #[inline]
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl AlgorithmName for Tiger2Core {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Tiger2")
    }
}

impl fmt::Debug for Tiger2Core {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Tiger2Core { ... }")
    }
}

impl SerializableState for Tiger2Core {
    type SerializedStateSize = U32;

    fn serialize(&self) -> SerializedState<Self> {
        let mut serialized_state = GenericArray::<_, U24>::default();

        for (val, chunk) in self.state.iter().zip(serialized_state.chunks_exact_mut(8)) {
            chunk.copy_from_slice(&val.to_le_bytes());
        }

        serialized_state.concat(self.block_len.to_le_bytes().into())
    }

    fn deserialize(
        serialized_state: &SerializedState<Self>,
    ) -> Result<Self, DeserializeStateError> {
        let (serialized_state, serialized_block_len) = Split::<_, U24>::split(serialized_state);

        let mut state = [0; STATE_LEN];
        for (val, chunk) in state.iter_mut().zip(serialized_state.chunks_exact(8)) {
            *val = u64::from_le_bytes(chunk.try_into().unwrap());
        }

        let block_len = u64::from_le_bytes((*serialized_block_len).into());

        Ok(Self { state, block_len })
    }
}

/// Tiger hasher state.
pub type Tiger = CoreWrapper<TigerCore>;
/// Tiger2 hasher state.
pub type Tiger2 = CoreWrapper<Tiger2Core>;
