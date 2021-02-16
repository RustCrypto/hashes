//! An implementation of the [MD2][1] cryptographic hash algorithm.
//!
//! # Usage
//!
//! ```rust
//! use md2::{Md2, Digest};
//! use hex_literal::hex;
//!
//! // create a Md2 hasher instance
//! let mut hasher = Md2::new();
//!
//! // process input message
//! hasher.update(b"hello world");
//!
//! // acquire hash digest in the form of GenericArray,
//! // which in this case is equivalent to [u8; 16]
//! let result = hasher.finalize();
//! assert_eq!(result[..], hex!("d9cce882ee690a5c1ce70beff3a78c77"));
//! ```
//!
//! Also see [RustCrypto/hashes][2] readme.
//!
//! [1]: https://en.wikipedia.org/wiki/MD4
//! [2]: https://github.com/RustCrypto/hashes

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub use digest::{self, Digest};

use core::fmt;
use digest::{
    block_buffer::{block_padding::Pkcs7, BlockBuffer},
    core_api::{AlgorithmName, CoreWrapper, FixedOutputCore, UpdateCore},
    generic_array::{typenum::U16, GenericArray},
    Reset,
};

mod consts;

type BlockSize = U16;
type Block = GenericArray<u8, BlockSize>;

/// Core MD2 hasher state.
#[derive(Clone)]
pub struct Md2Core {
    x: [u8; 48],
    checksum: Block,
}

impl Md2Core {
    fn compress(&mut self, block: &Block) {
        // Update state
        for j in 0..16 {
            self.x[16 + j] = block[j];
            self.x[32 + j] = self.x[16 + j] ^ self.x[j];
        }

        let mut t = 0u8;
        for j in 0..18u8 {
            for k in 0..48 {
                self.x[k] ^= consts::S[t as usize];
                t = self.x[k];
            }
            t = t.wrapping_add(j);
        }

        // Update checksum
        let mut l = self.checksum[15];
        for j in 0..16 {
            self.checksum[j] ^= consts::S[(block[j] ^ l) as usize];
            l = self.checksum[j];
        }
    }
}

impl UpdateCore for Md2Core {
    type BlockSize = BlockSize;
    type Buffer = BlockBuffer<BlockSize>;

    #[inline]
    fn update_blocks(&mut self, blocks: &[Block]) {
        for block in blocks {
            self.compress(block)
        }
    }
}

impl FixedOutputCore for Md2Core {
    type OutputSize = U16;

    #[inline]
    fn finalize_fixed_core(
        &mut self,
        buffer: &mut BlockBuffer<Self::BlockSize>,
        out: &mut GenericArray<u8, Self::OutputSize>,
    ) {
        let block = buffer.pad_with::<Pkcs7>();
        self.compress(block);
        let checksum = self.checksum;
        self.compress(&checksum);
        out.copy_from_slice(&self.x[0..16]);
    }
}

impl Default for Md2Core {
    #[inline]
    fn default() -> Self {
        Self {
            x: [0; 48],
            checksum: Default::default(),
        }
    }
}

impl Reset for Md2Core {
    #[inline]
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl AlgorithmName for Md2Core {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Md2")
    }
}

impl fmt::Debug for Md2Core {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Md2Core { ... }")
    }
}

/// MD2 hasher state.
pub type Md2 = CoreWrapper<Md2Core>;
