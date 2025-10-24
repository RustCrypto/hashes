#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(unexpected_cfgs)] // `simd` feature is broken
#![warn(missing_docs, unreachable_pub)]
#![cfg_attr(feature = "simd", feature(platform_intrinsics, repr_simd))]
#![cfg_attr(feature = "simd", allow(incomplete_features))]

pub use digest::{self, Digest};

use core::{fmt, marker::PhantomData, ops::Div};
use digest::{
    CustomizedInit, FixedOutput, HashMarker, InvalidOutputSize, MacMarker, Output, Update,
    array::{Array, ArraySize},
    block_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, OutputSizeUser, TruncSide,
        UpdateCore, VariableOutputCore, VariableOutputCoreCustomized,
    },
    block_buffer::{Lazy, LazyBuffer},
    consts::{U4, U16, U32, U64, U128},
    crypto_common::{InvalidLength, Key, KeyInit, KeySizeUser},
    typenum::{IsLessOrEqual, True, Unsigned},
};
#[cfg(feature = "reset")]
use digest::{FixedOutputReset, Reset};

#[cfg(feature = "zeroize")]
use digest::zeroize::{Zeroize, ZeroizeOnDrop};

mod as_bytes;
mod consts;

mod simd;

#[macro_use]
mod macros;

use as_bytes::AsBytes;
use consts::{BLAKE2B_IV, BLAKE2S_IV};
use simd::{Vector4, u32x4, u64x4};

blake2_impl!(
    Blake2bVarCore,
    "Blake2b",
    u64,
    u64x4,
    U64,
    U128,
    32,
    24,
    16,
    63,
    BLAKE2B_IV,
    "Blake2b instance with a variable output.",
    "Blake2b instance with a fixed output.",
);

digest::buffer_ct_variable!(
    /// BLAKE2b generic over output size.
    pub struct Blake2b<OutSize>(Blake2bVarCore);
    exclude: SerializableState;
    max_size: U64;
);

// TODO: impl in the macro
impl<OutSize> CustomizedInit for Blake2b<OutSize>
where
    OutSize: ArraySize + IsLessOrEqual<U64, Output = True>,
{
    fn new_customized(customization: &[u8]) -> Self {
        Self {
            core: CustomizedInit::new_customized(customization),
            buffer: Default::default(),
        }
    }
}

/// BLAKE2b-128 hasher state.
pub type Blake2b128 = Blake2b<U16>;
/// BLAKE2b-256 hasher state.
pub type Blake2b256 = Blake2b<U32>;
/// BLAKE2b-512 hasher state.
pub type Blake2b512 = Blake2b<U64>;

blake2_mac_impl!(Blake2bMac, Blake2bVarCore, U64, "Blake2b MAC function");

/// BLAKE2b-512 MAC state.
pub type Blake2bMac512 = Blake2bMac<U64>;

blake2_impl!(
    Blake2sVarCore,
    "Blake2s",
    u32,
    u32x4,
    U32,
    U64,
    16,
    12,
    8,
    7,
    BLAKE2S_IV,
    "Blake2s instance with a variable output.",
    "Blake2s instance with a fixed output.",
);

digest::buffer_ct_variable!(
    /// BLAKE2s generic over output size.
    pub struct Blake2s<OutSize>(Blake2sVarCore);
    exclude: SerializableState;
    max_size: U32;
);

// TODO: impl in the macro
impl<OutSize> CustomizedInit for Blake2s<OutSize>
where
    OutSize: ArraySize + IsLessOrEqual<U32, Output = True>,
{
    fn new_customized(customization: &[u8]) -> Self {
        Self {
            core: CustomizedInit::new_customized(customization),
            buffer: Default::default(),
        }
    }
}

/// BLAKE2s-128 hasher state.
pub type Blake2s128 = Blake2s<U16>;
/// BLAKE2s-256 hasher state.
pub type Blake2s256 = Blake2s<U32>;

blake2_mac_impl!(Blake2sMac, Blake2sVarCore, U32, "Blake2s MAC function");

/// BLAKE2s-256 MAC state.
pub type Blake2sMac256 = Blake2sMac<U32>;
