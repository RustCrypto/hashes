//! Implementation of Skein cryptographic hash algorithms.
//! The Skein hash function was one of the submissions to SHA-3,
//! the cryptographic hash algorithm competition organized by the NIST.
//!
//! There are 3 standard versions of the Skein hash function:
//!
//! * `Skein-256`
//! * `Skein-512`
//! * `Skein-1024`
//!
//! # Examples
//!
//! Output size of Skein-256 is fixed, so its functionality is usually
//! accessed via the `Digest` trait:
//!
//! ```
//! use hex_literal::hex;
//! use skein::{Digest, Skein256, digest::generic_array::typenum::U32};
//!
//! // create a Skein-256 object
//! let mut hasher = Skein256::<U32>::new();
//!
//! // write input message
//! hasher.update(b"hello");
//!
//! // read hash digest
//! let result = hasher.finalize();
//!
//! assert_eq!(result[..], hex!("
//!     8b467f67dd324c9c9fe9aff562ee0e3746d88abcb2879e4e1b4fbd06a5061f89
//! ")[..]);
//! ```
//! Also see [RustCrypto/hashes][2] readme.
//!
//! [1]: https://schneier.com/academic/skein
//! [2]: https://github.com/RustCrypto/hashes

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![warn(missing_docs, rust_2018_idioms)]

use core::fmt;
pub use digest::{self, Digest};
use digest::{
    block_buffer::Lazy,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore,
        OutputSizeUser, Reset, UpdateCore,
    },
    generic_array::{
        typenum::{U128, U32, U64},
        ArrayLength, GenericArray,
    },
    HashMarker, Output,
};
use threefish::{cipher::BlockEncrypt, Threefish1024, Threefish256, Threefish512};

#[derive(Clone)]
struct State<N>
where
    N: ArrayLength<u8>,
{
    t: (u64, u64),
    x: GenericArray<u8, N>,
}

impl<N> State<N>
where
    N: ArrayLength<u8>,
{
    fn new(t1: u64, x: GenericArray<u8, N>) -> Self {
        let t = (0, t1);
        State { t, x }
    }
}

impl<N> core::fmt::Debug for State<N>
where
    N: ArrayLength<u8>,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        f.debug_struct("State<X>")
            .field("t", &"(unknown)")
            .field("x", &"(unknown)")
            .finish()
    }
}

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
    ($name:ident, $full_name:ident, $threefish:ident, $state_bytes:ty, $state_bits:expr, $alg_name:expr) => {
        /// Skein hash function.
        #[derive(Clone)]
        pub struct $name<N>
        where
            N: ArrayLength<u8>,
        {
            state: State<<Self as BlockSizeUser>::BlockSize>,
            _output: core::marker::PhantomData<N>,
        }

        impl<N> HashMarker for $name<N> where N: ArrayLength<u8> {}

        impl<N> BlockSizeUser for $name<N>
        where
            N: ArrayLength<u8>,
        {
            type BlockSize = <$threefish as BlockSizeUser>::BlockSize;
        }

        impl<N> BufferKindUser for $name<N>
        where
            N: ArrayLength<u8>,
        {
            type BufferKind = Lazy;
        }

        impl<N> OutputSizeUser for $name<N>
        where
            N: ArrayLength<u8>,
        {
            type OutputSize = N;
        }

        impl<N> UpdateCore for $name<N>
        where
            N: ArrayLength<u8>,
        {
            #[inline]
            fn update_blocks(&mut self, blocks: &[Block<Self>]) {
                for block in blocks {
                    Self::process_block(&mut self.state, block, $state_bits / 8)
                }
            }
        }

        impl<N> FixedOutputCore for $name<N>
        where
            N: ArrayLength<u8>,
        {
            #[inline]
            fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
                self.state.t.1 |= T1_FLAG_FINAL;
                let pos = buffer.get_pos();
                let final_block = buffer.pad_with_zeros();
                Self::process_block(&mut self.state, final_block, pos);

                // run Threefish in "counter mode" to generate output
                for (i, chunk) in out.chunks_mut($state_bits / 8).enumerate() {
                    let mut ctr = State::new(
                        T1_FLAG_FIRST | T1_BLK_TYPE_OUT | T1_FLAG_FINAL,
                        self.state.x,
                    );
                    let mut b = GenericArray::<u8, $state_bytes>::default();
                    b[..8].copy_from_slice(&(i as u64).to_le_bytes());
                    Self::process_block(&mut ctr, &b, 8);
                    let n = chunk.len();
                    chunk.copy_from_slice(&ctr.x[..n]);
                }
            }
        }

        impl<N> $name<N>
        where
            N: ArrayLength<u8>,
        {
            fn process_block(
                state: &mut State<<Self as BlockSizeUser>::BlockSize>,
                block: &GenericArray<u8, $state_bytes>,
                byte_count_add: usize,
            ) {
                state.t.0 += byte_count_add as u64;
                let mut tweak = [0u8; 16];
                tweak[..8].copy_from_slice(&state.t.0.to_le_bytes());
                tweak[8..].copy_from_slice(&state.t.1.to_le_bytes());
                let mut key = [0u8; { $state_bits / 8 }];
                key[..].copy_from_slice(&state.x[..]);
                let fish = $threefish::new_with_tweak(&key, &tweak);
                let mut x = block.clone();
                fish.encrypt_block(&mut x);
                for i in 0..x.len() {
                    state.x[i] = x[i] ^ block[i];
                }
                state.t.1 &= !T1_FLAG_FIRST;
            }
        }

        impl<N> Default for $name<N>
        where
            N: ArrayLength<u8>,
        {
            fn default() -> Self {
                // build and process config block
                let mut state = State::new(
                    T1_FLAG_FIRST | T1_BLK_TYPE_CFG | T1_FLAG_FINAL,
                    Block::<$name<N>>::default(),
                );
                let mut cfg = GenericArray::<u8, $state_bytes>::default();
                cfg[..8].copy_from_slice(&SCHEMA_VER.to_le_bytes());
                cfg[8..16].copy_from_slice(&(N::to_u64() * 8).to_le_bytes());
                cfg[16..24].copy_from_slice(&CFG_TREE_INFO_SEQUENTIAL.to_le_bytes());
                Self::process_block(&mut state, &cfg, CFG_STR_LEN);

                // The chaining vars ctx->X are now initialized for the given hashBitLen.
                // Set up to process the data message portion of the hash (default)
                state.t = Default::default();
                state.t.1 = T1_FLAG_FIRST | T1_BLK_TYPE_MSG;
                Self {
                    state,
                    _output: Default::default(),
                }
            }
        }

        impl<N> Reset for $name<N>
        where
            N: ArrayLength<u8>,
        {
            #[inline]
            fn reset(&mut self) {
                *self = Default::default();
            }
        }

        impl<N> AlgorithmName for $name<N>
        where
            N: ArrayLength<u8>,
        {
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(stringify!($full_name))
            }
        }

        impl<N> fmt::Debug for $name<N>
        where
            N: ArrayLength<u8>,
        {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
                f.debug_struct("Skein").field("state", &self.state).finish()
            }
        }

        #[doc = $alg_name]
        #[doc = " hasher state."]
        pub type $full_name<OutputSize> = CoreWrapper<$name<OutputSize>>;
    };
}

#[rustfmt::skip]
define_hasher!(Skein256Core, Skein256, Threefish256, U32, 256, "Skein-256");
#[rustfmt::skip]
define_hasher!(Skein512Core, Skein512, Threefish512, U64, 512, "Skein-512");
#[rustfmt::skip]
define_hasher!(Skein1024Core, Skein1024, Threefish1024, U128, 1024, "Skein-1024");
