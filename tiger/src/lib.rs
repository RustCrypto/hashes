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
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub use digest::{self, Digest};

use core::{fmt, slice::from_ref};
use digest::{
    block_buffer::BlockBuffer,
    core_api::{AlgorithmName, CoreWrapper, FixedOutputCore, UpdateCore},
    generic_array::{
        typenum::{Unsigned, U24, U64},
        GenericArray,
    },
    Reset,
};

mod compress;
mod tables;
use compress::compress;

type BlockSize = U64;
type Block = GenericArray<u8, U64>;

/// Core Tiger hasher state.
#[derive(Clone)]
pub struct TigerCore {
    block_len: u64,
    state: [u64; 3],
}

impl UpdateCore for TigerCore {
    type BlockSize = BlockSize;
    type Buffer = BlockBuffer<BlockSize>;

    fn update_blocks(&mut self, blocks: &[Block]) {
        self.block_len += blocks.len() as u64;
        compress(&mut self.state, blocks);
    }
}

impl FixedOutputCore for TigerCore {
    type OutputSize = U24;

    #[inline]
    fn finalize_fixed_core(
        &mut self,
        buffer: &mut BlockBuffer<Self::BlockSize>,
        out: &mut GenericArray<u8, Self::OutputSize>,
    ) {
        let bs = Self::BlockSize::U64 as u64;
        let pos = buffer.get_pos() as u64;
        let bit_len = 8 * (pos + bs * self.block_len);

        buffer.digest_pad(1, &bit_len.to_le_bytes(), |b| {
            compress(&mut self.state, from_ref(b))
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
            state: [
                0x0123_4567_89AB_CDEF,
                0xFEDC_BA98_7654_3210,
                0xF096_A5B4_C3B2_E187,
            ],
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

/// Core Tiger2 hasher state.
#[derive(Clone)]
pub struct Tiger2Core {
    block_len: u64,
    state: [u64; 3],
}

impl UpdateCore for Tiger2Core {
    type BlockSize = BlockSize;
    type Buffer = BlockBuffer<BlockSize>;

    fn update_blocks(&mut self, blocks: &[Block]) {
        self.block_len += blocks.len() as u64;
        compress(&mut self.state, blocks);
    }
}

impl FixedOutputCore for Tiger2Core {
    type OutputSize = U24;

    #[inline]
    fn finalize_fixed_core(
        &mut self,
        buffer: &mut BlockBuffer<Self::BlockSize>,
        out: &mut GenericArray<u8, Self::OutputSize>,
    ) {
        let bs = Self::BlockSize::U64 as u64;
        let pos = buffer.get_pos() as u64;
        let bit_len = 8 * (pos + bs * self.block_len);

        buffer.len64_padding_le(bit_len, |b| compress(&mut self.state, from_ref(b)));
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

/// Tiger hasher state.
pub type Tiger = CoreWrapper<TigerCore>;
/// Tiger2 hasher state.
pub type Tiger2 = CoreWrapper<Tiger2Core>;
