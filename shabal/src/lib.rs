//! An implementation of the [Shabal][1] cryptographic hash algorithms.
//!
//! # Usage
//!
//! ```rust
//! use hex_literal::hex;
//! use shabal::{Shabal256, Digest};
//!
//! // create a Shabal256 hasher instance
//! let mut hasher = Shabal256::new();
//!
//! // process input message
//! hasher.update(b"helloworld");
//!
//! // acquire hash digest in the form of GenericArray,
//! // which in this case is equivalent to [u8; 32]
//! let result = hasher.finalize();
//! assert_eq!(result[..], hex!("
//!     d945dee21ffca23ac232763aa9cac6c15805f144db9d6c97395437e01c8595a8
//! ")[..]);
//! ```
//!
//! Also see [RustCrypto/hashes][2] readme.
//!
//! [1]: https://www.cs.rit.edu/~ark/20090927/Round2Candidates/Shabal.pdf
//! [2]: https://github.com/RustCrypto/hashes

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "std")]
extern crate std;

mod consts;
mod state;

pub use digest::{self, Digest};

use core::fmt;
use digest::{
    block_buffer::{block_padding::Iso7816, BlockBuffer},
    consts::{U24, U28, U32, U48, U64},
    core_api::{AlgorithmName, CoreWrapper, FixedOutputCore, UpdateCore},
    generic_array::{typenum::Unsigned, GenericArray},
    Reset,
};
use state::{compress, compress_final, Block, BlockSize, EngineState};

macro_rules! impl_core {
    ($name:ident, $full_name:ident, $init:expr, $out_size:ty, $alg_name:expr) => {
        #[doc = "Core "]
        #[doc = $alg_name]
        #[doc = " hasher state."]
        #[derive(Clone)]
        pub struct $name {
            state: EngineState,
        }

        impl UpdateCore for $name {
            type BlockSize = BlockSize;
            type Buffer = BlockBuffer<BlockSize>;

            #[inline]
            fn update_blocks(&mut self, blocks: &[Block]) {
                for block in blocks {
                    compress(&mut self.state, block)
                }
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
                let block = buffer.pad_with::<Iso7816>();
                compress_final(&mut self.state, &block);
                let n = 16 - <$out_size>::USIZE / 4;
                let b = &self.state.get_b()[n..];
                for (chunk, v) in out.chunks_exact_mut(4).zip(b.iter()) {
                    chunk.copy_from_slice(&v.to_le_bytes());
                }
            }
        }

        impl Default for $name {
            #[inline]
            fn default() -> Self {
                Self {
                    state: EngineState::new($init),
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

impl_core!(Shabal192Core, Shabal192, consts::INIT_192, U24, "Shabal192");
impl_core!(Shabal224Core, Shabal224, consts::INIT_224, U28, "Shabal224");
impl_core!(Shabal256Core, Shabal256, consts::INIT_256, U32, "Shabal256");
impl_core!(Shabal384Core, Shabal384, consts::INIT_384, U48, "Shabal384");
impl_core!(Shabal512Core, Shabal512, consts::INIT_512, U64, "Shabal512");
