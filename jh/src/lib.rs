#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![warn(missing_docs, rust_2018_idioms)]

mod compressor;
mod consts;

// This function is exported only for benchmarks
pub use compressor::f8_impl;

pub use digest::{self, Digest};

use crate::compressor::Compressor;
use core::fmt;
use digest::{
    array::typenum::{Unsigned, U28, U32, U48, U64},
    block_buffer::Eager,
    core_api::{
        AlgorithmName, Block, Buffer, BufferKindUser, CoreWrapper, CtVariableCoreWrapper,
        TruncSide, UpdateCore, VariableOutputCore,
    },
    crypto_common::{BlockSizeUser, OutputSizeUser},
    HashMarker, InvalidOutputSize, Output,
};

#[cfg(feature = "zeroize")]
use digest::zeroize::{Zeroize, ZeroizeOnDrop};

/// Core JH hasher state
#[derive(Clone)]
pub struct JhCore {
    state: Compressor,
    block_len: u64,
}

/// Jh-224 hasher state
pub type Jh224 = CoreWrapper<CtVariableCoreWrapper<JhCore, U28>>;
/// Jh-256 hasher state
pub type Jh256 = CoreWrapper<CtVariableCoreWrapper<JhCore, U32>>;
/// Jh-384 hasher state
pub type Jh384 = CoreWrapper<CtVariableCoreWrapper<JhCore, U48>>;
/// Jh-512 hasher state
pub type Jh512 = CoreWrapper<CtVariableCoreWrapper<JhCore, U64>>;

impl HashMarker for JhCore {}

impl BlockSizeUser for JhCore {
    type BlockSize = U64;
}

impl BufferKindUser for JhCore {
    type BufferKind = Eager;
}

impl OutputSizeUser for JhCore {
    type OutputSize = U64;
}

impl UpdateCore for JhCore {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.block_len = self.block_len.wrapping_add(blocks.len() as u64);
        for b in blocks {
            self.state.update(b);
        }
    }
}

impl VariableOutputCore for JhCore {
    const TRUNC_SIDE: TruncSide = TruncSide::Right;

    #[inline]
    fn new(output_size: usize) -> Result<Self, InvalidOutputSize> {
        let h0 = match output_size {
            28 => consts::JH224_H0,
            32 => consts::JH256_H0,
            48 => consts::JH384_H0,
            64 => consts::JH512_H0,
            _ => return Err(InvalidOutputSize),
        };
        Ok(Self {
            state: Compressor::new(h0),
            block_len: 0,
        })
    }

    #[inline]
    fn finalize_variable_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let Self { state, block_len } = self;
        let bit_len = block_len
            .wrapping_mul(Self::BlockSize::U64)
            .wrapping_add(buffer.get_pos() as u64)
            .wrapping_mul(8);
        if buffer.get_pos() == 0 {
            buffer.len64_padding_be(bit_len, |b| state.update(b));
        } else {
            buffer.digest_pad(0x80, &[], |b| state.update(b));
            buffer.digest_pad(0, &bit_len.to_be_bytes(), |b| state.update(b));
        }
        out.copy_from_slice(&self.state.finalize()[64..]);
    }
}

impl AlgorithmName for JhCore {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Jh")
    }
}

impl fmt::Debug for JhCore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JhCore { ... }")
    }
}

impl Drop for JhCore {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            // TODO: implement Zeroize for Compressor
            // self.state.zeroize();
            self.block_len.zeroize();
        }
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for JhCore {}
