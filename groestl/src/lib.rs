//! An implementation of the [Grøstl][1] cryptographic hash function.
//!
//! # Usage
//!
//! ```
//! use groestl::{Digest, Groestl256};
//! use hex_literal::hex;
//!
//! // create a Groestl-256 hasher instance
//! let mut hasher = Groestl256::default();
//!
//! // process input message
//! hasher.update(b"my message");
//!
//! // acquire hash digest in the form of GenericArray,
//! // which in this case is equivalent to [u8; 32]
//! let result = hasher.finalize();
//! assert_eq!(result[..], hex!("
//!     dc0283ca481efa76b7c19dd5a0b763dff0e867451bd9488a9c59f6c8b8047a86
//! "));
//! ```
//!
//! Also see [RustCrypto/hashes][2] readme.
//!
//! [1]: https://en.wikipedia.org/wiki/Grøstl
//! [2]: https://github.com/RustCrypto/hashes

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(rust_2018_idioms)]

pub use digest::{self, Digest};

use core::fmt;
use digest::{
    block_buffer::Eager,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper,
        CtVariableCoreWrapper, OutputSizeUser, RtVariableCoreWrapper, TruncSide, UpdateCore,
        VariableOutputCore,
    },
    typenum::{Unsigned, U128, U28, U32, U48, U64},
    HashMarker, InvalidOutputSize, Output,
};

mod compress1024;
mod compress512;
mod table;

/// Lowest-level core hasher state of the short Groestl variant.
#[derive(Clone)]
pub struct GroestlShortVarCore {
    state: [u64; compress512::COLS],
    blocks_len: u64,
}

impl HashMarker for GroestlShortVarCore {}

impl BlockSizeUser for GroestlShortVarCore {
    type BlockSize = U64;
}

impl BufferKindUser for GroestlShortVarCore {
    type BufferKind = Eager;
}

impl UpdateCore for GroestlShortVarCore {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.blocks_len += blocks.len() as u64;
        for block in blocks {
            compress512::compress(&mut self.state, block.as_ref());
        }
    }
}

impl OutputSizeUser for GroestlShortVarCore {
    type OutputSize = U32;
}

impl VariableOutputCore for GroestlShortVarCore {
    const TRUNC_SIDE: TruncSide = TruncSide::Right;

    #[inline]
    fn new(output_size: usize) -> Result<Self, InvalidOutputSize> {
        if output_size > Self::OutputSize::USIZE {
            return Err(InvalidOutputSize);
        }
        let mut state = [0; compress512::COLS];
        state[compress512::COLS - 1] = 8 * output_size as u64;
        let blocks_len = 0;
        Ok(Self { state, blocks_len })
    }

    #[inline]
    fn finalize_variable_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let blocks_len = if buffer.remaining() <= 8 {
            self.blocks_len + 2
        } else {
            self.blocks_len + 1
        };
        buffer.len64_padding_be(blocks_len, |block| {
            compress512::compress(&mut self.state, block.as_ref())
        });
        let res = compress512::p(&self.state);
        let n = compress512::COLS / 2;
        for (chunk, v) in out.chunks_exact_mut(8).zip(res[n..].iter()) {
            chunk.copy_from_slice(&v.to_be_bytes());
        }
    }
}

impl AlgorithmName for GroestlShortVarCore {
    #[inline]
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GroestlShort")
    }
}

impl fmt::Debug for GroestlShortVarCore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GroestlShortVarCore { ... }")
    }
}

/// Short Groestl variant which allows to choose output size at runtime.
pub type GroestlShortVar = RtVariableCoreWrapper<GroestlShortVarCore>;
/// Core hasher state of the short Groestl variant generic over output size.
pub type GroestlShortCore<OutSize> = CtVariableCoreWrapper<GroestlShortVarCore, OutSize>;
/// Hasher state of the short Groestl variant generic over output size.
pub type GroestlShort<OutSize> = CoreWrapper<GroestlShortCore<OutSize>>;

/// Groestl-224 hasher state.
pub type Groestl224 = CoreWrapper<GroestlShortCore<U28>>;
/// Groestl-256 hasher state.
pub type Groestl256 = CoreWrapper<GroestlShortCore<U32>>;

/// Lowest-level core hasher state of the long Groestl variant.
#[derive(Clone)]
pub struct GroestlLongVarCore {
    state: [u64; compress1024::COLS],
    blocks_len: u64,
}

impl HashMarker for GroestlLongVarCore {}

impl BlockSizeUser for GroestlLongVarCore {
    type BlockSize = U128;
}

impl BufferKindUser for GroestlLongVarCore {
    type BufferKind = Eager;
}

impl UpdateCore for GroestlLongVarCore {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.blocks_len += blocks.len() as u64;
        for block in blocks {
            compress1024::compress(&mut self.state, block.as_ref());
        }
    }
}

impl OutputSizeUser for GroestlLongVarCore {
    type OutputSize = U64;
}

impl VariableOutputCore for GroestlLongVarCore {
    const TRUNC_SIDE: TruncSide = TruncSide::Right;

    #[inline]
    fn new(output_size: usize) -> Result<Self, InvalidOutputSize> {
        if output_size > Self::OutputSize::USIZE {
            return Err(InvalidOutputSize);
        }
        let mut state = [0; compress1024::COLS];
        state[compress1024::COLS - 1] = 8 * output_size as u64;
        let blocks_len = 0;
        Ok(Self { state, blocks_len })
    }

    #[inline]
    fn finalize_variable_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let blocks_len = if buffer.remaining() <= 8 {
            self.blocks_len + 2
        } else {
            self.blocks_len + 1
        };
        buffer.len64_padding_be(blocks_len, |block| {
            compress1024::compress(&mut self.state, block.as_ref())
        });
        let res = compress1024::p(&self.state);
        let n = compress1024::COLS / 2;
        for (chunk, v) in out.chunks_exact_mut(8).zip(res[n..].iter()) {
            chunk.copy_from_slice(&v.to_be_bytes());
        }
    }
}

impl AlgorithmName for GroestlLongVarCore {
    #[inline]
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GroestlLong")
    }
}

impl fmt::Debug for GroestlLongVarCore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GroestlLongVarCore { ... }")
    }
}

/// Long Groestl variant which allows to choose output size at runtime.
pub type GroestlLongVar = RtVariableCoreWrapper<GroestlLongVarCore>;
/// Core hasher state of the long Groestl variant generic over output size.
pub type GroestlLongCore<OutSize> = CtVariableCoreWrapper<GroestlLongVarCore, OutSize>;
/// Hasher state of the long Groestl variant generic over output size.
pub type GroestlLong<OutSize> = CoreWrapper<GroestlLongCore<OutSize>>;

/// Groestl-384 hasher state.
pub type Groestl384 = CoreWrapper<GroestlLongCore<U48>>;
/// Groestl-512 hasher state.
pub type Groestl512 = CoreWrapper<GroestlLongCore<U64>>;
