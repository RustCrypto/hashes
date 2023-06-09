//! Implementation of the [Skein] family of cryptographic hash algorithms.
//!
//! There are 3 standard versions of the Skein hash function:
//!
//! * [`Skein256`]
//! * [`Skein512`]
//! * [`Skein1024`]
//!
//! Output size of the Skein hash functions is arbitrary, so it has to be
//! fixed using additional type parameter
//!
//! # Examples
//! Hash functionality is usually accessed via the [`Digest`] trait:
//!
//! ```
//! use hex_literal::hex;
//! use skein::{Digest, Skein512, consts::U32};
//!
//! // Create a Skein-512-256 hasher object
//! let mut hasher = Skein512::<U32>::new();
//!
//! // Write input message
//! hasher.update(b"The quick brown fox ");
//! hasher.update(b"jumps over the lazy dog");
//!
//! // Read hash digest
//! let result = hasher.finalize();
//!
//! let expected = hex!("b3250457e05d3060b1a4bbc1428bc75a3f525ca389aeab96cfa34638d96e492a");
//! assert_eq!(result[..], expected[..]);
//! ```
//! Also see [RustCrypto/hashes] readme.
//!
//! [Skein]: https://schneier.com/academic/skein
//! [RustCrypto/hashes]: https://github.com/RustCrypto/hashes

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![warn(missing_docs, rust_2018_idioms)]
#![deny(unsafe_code)]

pub use digest::{self, consts, Digest};

use core::{fmt, marker::PhantomData};
use digest::{
    block_buffer::Lazy,
    consts::{U128, U32, U64},
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore,
        OutputSizeUser, Reset, UpdateCore,
    },
    generic_array::{typenum::Unsigned, ArrayLength, GenericArray},
    HashMarker, Output,
};
use threefish::{Threefish1024, Threefish256, Threefish512};

const VERSION: u64 = 1;
const ID_STRING_LE: u64 = 0x3341_4853;
const SCHEMA_VER: u64 = (VERSION << 32) | ID_STRING_LE;
const CFG_TREE_INFO_SEQUENTIAL: u64 = 0;
const T1_FLAG_FIRST: u64 = 1 << 62;
const T1_FLAG_FINAL: u64 = 1 << 63;
const T1_BLK_TYPE_CFG: u64 = 4 << 56;
const T1_BLK_TYPE_MSG: u64 = 48 << 56;
const T1_BLK_TYPE_OUT: u64 = 63 << 56;
const CFG_STR_LEN: usize = 4 * 8;

macro_rules! define_hasher {
    (
        $name:ident, $full_name:ident, $threefish:ident,
        $state_bytes:ty, $alg_name:expr
    ) => {
        #[doc = $alg_name]
        #[doc = " core hasher state"]
        #[derive(Clone)]
        pub struct $name<N: ArrayLength<u8> + 'static> {
            t: [u64; 2],
            x: [u64; <$state_bytes>::USIZE / 8],
            _pd: PhantomData<N>,
        }

        impl<N: ArrayLength<u8> + 'static> $name<N> {
            fn blank_state(t1: u64, x: [u64; <$state_bytes>::USIZE / 8]) -> Self {
                Self {
                    t: [0, t1],
                    x,
                    _pd: PhantomData,
                }
            }

            fn process_block(
                &mut self,
                block: &GenericArray<u8, $state_bytes>,
                byte_count_add: usize,
            ) {
                const STATE_WORDS: usize = <$state_bytes>::USIZE / 8;

                self.t[0] += byte_count_add as u64;
                let cipher = $threefish::new_with_tweak_u64(&self.x.into(), &self.t);

                let mut x = [0u64; STATE_WORDS];
                for (src, dst) in block.chunks_exact(8).zip(x.iter_mut()) {
                    *dst = u64::from_le_bytes(src.try_into().unwrap());
                }
                let t = x;

                cipher.encrypt_block_u64(&mut x);

                for i in 0..STATE_WORDS {
                    self.x[i] = t[i] ^ x[i];
                }
                self.t[1] &= !T1_FLAG_FIRST;
            }
        }

        impl<N> HashMarker for $name<N> where N: ArrayLength<u8> + 'static {}

        impl<N: ArrayLength<u8> + 'static> BlockSizeUser for $name<N> {
            type BlockSize = $state_bytes;
        }

        impl<N: ArrayLength<u8> + 'static> BufferKindUser for $name<N> {
            type BufferKind = Lazy;
        }

        impl<N: ArrayLength<u8> + 'static> OutputSizeUser for $name<N> {
            type OutputSize = N;
        }

        impl<N: ArrayLength<u8> + 'static> UpdateCore for $name<N> {
            #[inline]
            fn update_blocks(&mut self, blocks: &[Block<Self>]) {
                for block in blocks {
                    self.process_block(block, block.len())
                }
            }
        }

        impl<N: ArrayLength<u8> + 'static> FixedOutputCore for $name<N> {
            #[inline]
            fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
                self.t[1] |= T1_FLAG_FINAL;
                let pos = buffer.get_pos();
                let final_block = buffer.pad_with_zeros();
                self.process_block(final_block, pos);

                // run Threefish in "counter mode" to generate output
                let flag = T1_FLAG_FIRST | T1_BLK_TYPE_OUT | T1_FLAG_FINAL;
                let mut block = GenericArray::<u8, $state_bytes>::default();
                for (i, chunk) in out.chunks_mut(<$state_bytes>::USIZE).enumerate() {
                    let mut ctr = Self::blank_state(flag, self.x);

                    block[..8].copy_from_slice(&(i as u64).to_le_bytes());
                    Self::process_block(&mut ctr, &block, 8);

                    for (src, dst) in ctr.x.iter().zip(chunk.chunks_exact_mut(8)) {
                        dst.copy_from_slice(&src.to_le_bytes());
                    }
                }
            }
        }

        impl<N: ArrayLength<u8> + 'static> Default for $name<N> {
            fn default() -> Self {
                // build and process config block
                let mut state = Self::blank_state(
                    T1_FLAG_FIRST | T1_BLK_TYPE_CFG | T1_FLAG_FINAL,
                    Default::default(),
                );

                let mut cfg = GenericArray::<u8, $state_bytes>::default();
                cfg[..8].copy_from_slice(&SCHEMA_VER.to_le_bytes());
                cfg[8..16].copy_from_slice(&(N::to_u64() * 8).to_le_bytes());
                cfg[16..24].copy_from_slice(&CFG_TREE_INFO_SEQUENTIAL.to_le_bytes());

                state.process_block(&cfg, CFG_STR_LEN);

                // The chaining vars ctx->X are now initialized for the given hashBitLen.
                // Set up to process the data message portion of the hash (default)
                state.t = [0, T1_FLAG_FIRST | T1_BLK_TYPE_MSG];
                state
            }
        }

        impl<N: ArrayLength<u8> + 'static> Reset for $name<N> {
            #[inline]
            fn reset(&mut self) {
                *self = Default::default();
            }
        }

        impl<N: ArrayLength<u8> + 'static> AlgorithmName for $name<N> {
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(stringify!($full_name))
            }
        }

        impl<N: ArrayLength<u8> + 'static> fmt::Debug for $name<N> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
                write!(f, "{}<{}> {{ .. }}", stringify!($name), N::USIZE)
            }
        }

        #[doc = $alg_name]
        #[doc = " hasher state"]
        pub type $full_name<OutputSize = $state_bytes> = CoreWrapper<$name<OutputSize>>;
    };
}

define_hasher!(Skein256Core, Skein256, Threefish256, U32, "Skein-256");
define_hasher!(Skein512Core, Skein512, Threefish512, U64, "Skein-512");
#[rustfmt::skip]
define_hasher!(Skein1024Core, Skein1024, Threefish1024, U128, "Skein-1024");
