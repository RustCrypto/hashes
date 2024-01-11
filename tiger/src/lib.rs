#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![warn(missing_docs, rust_2018_idioms)]

pub use digest::{self, Digest};

use core::fmt;
use digest::{
    block_buffer::Eager,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore,
        OutputSizeUser, Reset, UpdateCore,
    },
    typenum::{Unsigned, U24, U64},
    HashMarker, Output,
};

#[cfg(feature = "zeroize")]
use digest::zeroize::{Zeroize, ZeroizeOnDrop};

mod compress;
mod tables;
use compress::compress;

type State = [u64; 3];
const S0: State = [
    0x0123_4567_89AB_CDEF,
    0xFEDC_BA98_7654_3210,
    0xF096_A5B4_C3B2_E187,
];

/// Core Tiger hasher state.
#[derive(Clone)]
pub struct TigerCore<const VER2: bool = true> {
    block_len: u64,
    state: State,
}

/// Tiger hasher state.
pub type Tiger = CoreWrapper<TigerCore<false>>;
/// Tiger2 hasher state.
pub type Tiger2 = CoreWrapper<TigerCore<true>>;

impl<const VER2: bool> HashMarker for TigerCore<VER2> {}

impl<const VER2: bool> BlockSizeUser for TigerCore<VER2> {
    type BlockSize = U64;
}

impl<const VER2: bool> BufferKindUser for TigerCore<VER2> {
    type BufferKind = Eager;
}

impl<const VER2: bool> OutputSizeUser for TigerCore<VER2> {
    type OutputSize = U24;
}

impl<const VER2: bool> UpdateCore for TigerCore<VER2> {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.block_len += blocks.len() as u64;
        for block in blocks {
            compress(&mut self.state, block.as_ref());
        }
    }
}

impl<const VER2: bool> FixedOutputCore for TigerCore<VER2> {
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let bs = Self::BlockSize::U64;
        let pos = buffer.get_pos() as u64;
        let bit_len = 8 * (pos + bs * self.block_len);

        if VER2 {
            buffer.len64_padding_le(bit_len, |b| compress(&mut self.state, b.as_ref()));
        } else {
            buffer.digest_pad(1, &bit_len.to_le_bytes(), |b| {
                compress(&mut self.state, b.as_ref())
            });
        }

        for (chunk, v) in out.chunks_exact_mut(8).zip(self.state.iter()) {
            chunk.copy_from_slice(&v.to_le_bytes());
        }
    }
}

impl<const VER2: bool> Default for TigerCore<VER2> {
    #[inline]
    fn default() -> Self {
        Self {
            block_len: 0,
            state: S0,
        }
    }
}

impl<const VER2: bool> Reset for TigerCore<VER2> {
    #[inline]
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl<const VER2: bool> AlgorithmName for TigerCore<VER2> {
    #[inline]
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if VER2 {
            f.write_str("Tiger2")
        } else {
            f.write_str("Tiger")
        }
    }
}

impl<const VER2: bool> fmt::Debug for TigerCore<VER2> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if VER2 {
            f.write_str("Tiger2Core { ... }")
        } else {
            f.write_str("TigerCore { ... }")
        }
    }
}

impl<const VER2: bool> Drop for TigerCore<VER2> {
    #[inline]
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            self.state.zeroize();
            self.block_len.zeroize();
        }
    }
}

#[cfg(feature = "zeroize")]
impl<const VER2: bool> ZeroizeOnDrop for TigerCore<VER2> {}
