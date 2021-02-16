//! An implementation of the [SHA-2][1] cryptographic hash algorithms.
//!
//! There are 6 standard algorithms specified in the SHA-2 standard:
//!
//! * `Sha224`, which is the 32-bit `Sha256` algorithm with the result truncated
//! to 224 bits.
//! * `Sha256`, which is the 32-bit `Sha256` algorithm.
//! * `Sha384`, which is the 64-bit `Sha512` algorithm with the result truncated
//! to 384 bits.
//! * `Sha512`, which is the 64-bit `Sha512` algorithm.
//! * `Sha512Trunc224`, which is the 64-bit `Sha512` algorithm with the result
//! truncated to 224 bits.
//! * `Sha512Trunc256`, which is the 64-bit `Sha512` algorithm with the result
//! truncated to 256 bits.
//!
//! Algorithmically, there are only 2 core algorithms: `Sha256` and `Sha512`.
//! All other algorithms are just applications of these with different initial
//! hash values, and truncated to different digest bit lengths.
//!
//! # Usage
//!
//! ```rust
//! use hex_literal::hex;
//! use sha2::{Sha256, Sha512, Digest};
//!
//! // create a Sha256 object
//! let mut hasher = Sha256::new();
//!
//! // write input message
//! hasher.update(b"hello world");
//!
//! // read hash digest and consume hasher
//! let result = hasher.finalize();
//!
//! assert_eq!(result[..], hex!("
//!     b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
//! ")[..]);
//!
//! // same for Sha512
//! let mut hasher = Sha512::new();
//! hasher.update(b"hello world");
//! let result = hasher.finalize();
//!
//! assert_eq!(result[..], hex!("
//!     309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f
//!     989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f
//! ")[..]);
//! ```
//!
//! Also see [RustCrypto/hashes][2] readme.
//!
//! [1]: https://en.wikipedia.org/wiki/SHA-2
//! [2]: https://github.com/RustCrypto/hashes

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![warn(missing_docs, rust_2018_idioms)]

pub use digest::{self, Digest};

use core::{fmt, mem::size_of, slice::from_ref};
use digest::{
    block_buffer::BlockBuffer,
    core_api::{AlgorithmName, CoreWrapper, FixedOutputCore, UpdateCore},
    generic_array::{
        typenum::{Unsigned, U128, U28, U32, U48, U64},
        GenericArray,
    },
    Reset,
};

mod consts;
mod sha256;
mod sha512;

#[cfg(feature = "compress")]
pub use sha256::compress256;
#[cfg(feature = "compress")]
pub use sha512::compress512;

macro_rules! implement {
    (
        $name:ident, $full_name:ident, $init:expr, $block_size:ty, $out_size:ty,
        $compress:expr, $word:ty, $dword:ty, $alg_name:expr,
    ) => {
        #[doc = "Core "]
        #[doc = $alg_name]
        #[doc = " hasher state."]
        #[derive(Clone)]
        pub struct $name {
            state: [$word; 8],
            block_len: $dword,
        }

        impl UpdateCore for $name {
            type BlockSize = $block_size;
            type Buffer = BlockBuffer<$block_size>;

            #[inline]
            fn update_blocks(&mut self, blocks: &[GenericArray<u8, $block_size>]) {
                self.block_len += blocks.len() as $dword;
                $compress(&mut self.state, blocks);
            }
        }

        impl FixedOutputCore for $name {
            type OutputSize = $out_size;

            #[inline]
            fn finalize_fixed_core(
                &mut self,
                buffer: &mut BlockBuffer<Self::BlockSize>,
                out: &mut GenericArray<u8, Self::OutputSize>,
            ) {
                let bs = Self::BlockSize::U64 as $dword;
                let bit_len = 8 * (buffer.get_pos() as $dword + bs * self.block_len);
                let pad = bit_len.to_be_bytes();
                let s = &mut self.state;
                buffer.digest_pad(0x80, &pad, |b| $compress(s, from_ref(b)));
                let n = size_of::<$word>();
                for (chunk, v) in out.chunks_mut(n).zip(s.iter()) {
                    chunk.copy_from_slice(&v.to_be_bytes()[..chunk.len()]);
                }
            }
        }

        impl Default for $name {
            #[inline]
            fn default() -> Self {
                Self {
                    state: $init,
                    block_len: 0,
                }
            }
        }

        impl Reset for $name {
            #[inline]
            fn reset(&mut self) {
                *self = Default::default();
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

implement!(
    Sha224Core,
    Sha224,
    consts::H224,
    U64,
    U28,
    sha256::compress256,
    u32,
    u64,
    "SHA-224",
);
implement!(
    Sha256Core,
    Sha256,
    consts::H256,
    U64,
    U32,
    sha256::compress256,
    u32,
    u64,
    "SHA-256",
);
implement!(
    Sha512Trunc224Core,
    Sha512Trunc224,
    consts::H512_TRUNC_224,
    U128,
    U28,
    sha512::compress512,
    u64,
    u128,
    "SHA-512/224",
);
implement!(
    Sha512Trunc256Core,
    Sha512Trunc256,
    consts::H512_TRUNC_256,
    U128,
    U32,
    sha512::compress512,
    u64,
    u128,
    "SHA-512/256",
);
implement!(
    Sha384Core,
    Sha384,
    consts::H384,
    U128,
    U48,
    sha512::compress512,
    u64,
    u128,
    "SHA-384",
);
implement!(
    Sha512Core,
    Sha512,
    consts::H512,
    U128,
    U64,
    sha512::compress512,
    u64,
    u128,
    "SHA-512",
);
