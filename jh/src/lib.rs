//! Implementation of JH cryptographic hash algorithms.
//! The JH hash function was one of the submissions to SHA-3,
//! the cryptographic hash algorithm competition organized by the NIST.
//!
//! There are 4 standard versions of the JH hash function:
//!
//! * `JH-224`
//! * `JH-256`
//! * `JH-384`
//! * `JH-512`
//!
//! # Examples
//!
//! Output size of JH-256 is fixed, so its functionality is usually
//! accessed via the `Digest` trait:
//!
//! ```
//! use hex_literal::hex;
//! use jh::{Digest, Jh256, digest::generic_array::typenum::U32};
//!
//! // create a JH-256 object
//! let mut hasher = Jh256::new();
//!
//! // write input message
//! hasher.update(b"hello");
//!
//! // read hash digest
//! let result = hasher.finalize();
//!
//! assert_eq!(result[..], hex!("
//!     94fd3f4c564957c6754265676bf8b244c707d3ffb294e18af1f2e4f9b8306089
//! ")[..]);
//! ```
//! Also see [RustCrypto/hashes][2] readme.
//!
//! [1]: https://www3.ntu.edu.sg/home/wuhj/research/jh
//! [2]: https://github.com/RustCrypto/hashes
#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![warn(missing_docs, rust_2018_idioms)]

#[doc(hidden)]
pub mod compressor;
mod consts;

pub use digest::{self, Digest};

use crate::compressor::Compressor;
use core::fmt;
use digest::{
    block_buffer::Eager,
    core_api::{
        AlgorithmName, Block, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore, UpdateCore,
    },
    crypto_common::{BlockSizeUser, OutputSizeUser},
    generic_array::typenum::{Unsigned, U28, U32, U48, U64},
    HashMarker, Output,
};

macro_rules! define_hasher {
    ($name:ident, $full_name:ident, $init:path, $OutputBytes:ident, $alg_name:expr) => {
        #[doc = "Core "]
        #[doc = $alg_name]
        #[doc = " hasher state."]
        #[derive(Clone)]
        pub struct $name {
            block_len: u64,
            state: Compressor,
        }

        impl HashMarker for $name {}

        impl BlockSizeUser for $name {
            type BlockSize = U64;
        }

        impl BufferKindUser for $name {
            type BufferKind = Eager;
        }

        impl OutputSizeUser for $name {
            type OutputSize = $OutputBytes;
        }

        impl UpdateCore for $name {
            fn update_blocks(&mut self, blocks: &[Block<Self>]) {
                self.block_len = self.block_len.wrapping_add(blocks.len() as u64);
                for b in blocks {
                    self.state.input(b);
                }
            }
        }

        impl FixedOutputCore for $name {
            fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
                let state = &mut self.state;
                let bit_len = self
                    .block_len
                    .wrapping_mul(<Self as BlockSizeUser>::block_size() as u64)
                    .wrapping_add(buffer.get_pos() as u64)
                    .wrapping_mul(8);
                if buffer.get_pos() == 0 {
                    buffer.len64_padding_be(bit_len, |b| state.input(b));
                } else {
                    buffer.digest_pad(0x80, &[], |b| state.input(b));
                    buffer.digest_pad(0, &bit_len.to_be_bytes(), |b| state.input(b));
                }
                let finalized = self.state.finalize();
                out.copy_from_slice(&finalized[(128 - $OutputBytes::to_usize())..]);
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self {
                    block_len: 0,
                    state: Compressor::new($init),
                }
            }
        }

        impl digest::Reset for $name {
            fn reset(&mut self) {
                *self = Self::default();
            }
        }

        impl AlgorithmName for $name {
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(stringify!($full_name))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), " { ... }"))
            }
        }

        #[doc = $alg_name]
        #[doc = " hasher state."]
        pub type $full_name = CoreWrapper<$name>;
    };
}

define_hasher!(Jh224Core, Jh224, consts::JH224_H0, U28, "JH-224");
define_hasher!(Jh256Core, Jh256, consts::JH256_H0, U32, "JH-256");
define_hasher!(Jh384Core, Jh384, consts::JH384_H0, U48, "JH-384");
define_hasher!(Jh512Core, Jh512, consts::JH512_H0, U64, "JH-512");
