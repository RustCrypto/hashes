#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub use digest::{self, Digest};

use core::fmt;
use digest::{
    array::ArrayOps,
    block_buffer::Eager,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore,
        OutputSizeUser, Reset, UpdateCore,
    },
    typenum::U64,
    HashMarker, Output,
};

#[cfg(feature = "zeroize")]
use digest::zeroize::{Zeroize, ZeroizeOnDrop};

mod compress;
mod consts;

use compress::compress;

/// Core Whirlpool hasher state.
#[derive(Clone)]
pub struct WhirlpoolCore {
    bit_len: [u64; 4],
    state: [u64; 8],
}

/// Whirlpool hasher state.
pub type Whirlpool = CoreWrapper<WhirlpoolCore>;

impl HashMarker for WhirlpoolCore {}

impl BlockSizeUser for WhirlpoolCore {
    type BlockSize = U64;
}

impl BufferKindUser for WhirlpoolCore {
    type BufferKind = Eager;
}

impl OutputSizeUser for WhirlpoolCore {
    type OutputSize = U64;
}

impl UpdateCore for WhirlpoolCore {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        let block_bits = 8 * Self::block_size() as u64;
        self.update_len(block_bits * (blocks.len() as u64));
        let blocks = ArrayOps::cast_slice_to_core(blocks);
        compress(&mut self.state, blocks);
    }
}

impl FixedOutputCore for WhirlpoolCore {
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let pos = buffer.get_pos();
        self.update_len(8 * pos as u64);

        let mut buf = [0u8; 4 * 8];
        for (chunk, v) in buf.chunks_exact_mut(8).zip(self.bit_len.iter()) {
            chunk.copy_from_slice(&v.to_be_bytes());
        }

        let mut state = self.state;
        buffer.digest_pad(0x80, &buf, |block| {
            compress(&mut state, core::slice::from_ref(&block.0));
        });

        for (chunk, v) in out.chunks_exact_mut(8).zip(state.iter()) {
            chunk.copy_from_slice(&v.to_le_bytes());
        }
    }
}

impl WhirlpoolCore {
    fn update_len(&mut self, len: u64) {
        #[inline(always)]
        fn adc(a: &mut u64, b: u64, carry: &mut u64) {
            let ret = (*a as u128) + (b as u128) + (*carry as u128);
            *a = ret as u64;
            *carry = (ret >> 64) as u64;
        }

        let mut carry = 0;
        adc(&mut self.bit_len[3], len, &mut carry);
        adc(&mut self.bit_len[2], 0, &mut carry);
        adc(&mut self.bit_len[1], 0, &mut carry);
        adc(&mut self.bit_len[0], 0, &mut carry);
    }
}

// derivable impl does not inline
#[allow(clippy::derivable_impls)]
impl Default for WhirlpoolCore {
    #[inline]
    fn default() -> Self {
        Self {
            bit_len: Default::default(),
            state: [0u64; 8],
        }
    }
}

impl Reset for WhirlpoolCore {
    #[inline]
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl AlgorithmName for WhirlpoolCore {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Whirlpool")
    }
}

impl fmt::Debug for WhirlpoolCore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WhirlpoolCore { ... }")
    }
}

impl Drop for WhirlpoolCore {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            self.state.zeroize();
            self.bit_len.zeroize();
        }
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for WhirlpoolCore {}
