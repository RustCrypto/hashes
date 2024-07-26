#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![allow(unexpected_cfgs)] // `simd` feature is broken
#![warn(missing_docs, rust_2018_idioms)]
#![cfg_attr(feature = "simd", feature(platform_intrinsics, repr_simd))]
#![cfg_attr(feature = "simd", allow(incomplete_features))]

#[cfg(feature = "std")]
extern crate std;

pub use digest::{self, Digest};

use core::{fmt, marker::PhantomData, ops::Div};
use digest::{
    array::{Array, ArraySize},
    block_buffer::{Lazy, LazyBuffer},
    consts::{U128, U16, U32, U4, U64},
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper,
        CtVariableCoreWrapper, OutputSizeUser, RtVariableCoreWrapper, TruncSide, UpdateCore,
        VariableOutputCore,
    },
    crypto_common::{InvalidLength, Key, KeyInit, KeySizeUser},
    typenum::{IsLessOrEqual, LeEq, NonZero, Unsigned},
    FixedOutput, HashMarker, InvalidOutputSize, MacMarker, Output, Update,
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
use simd::{u32x4, u64x4, Vector4};

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

/// BLAKE2b which allows to choose output size at runtime.
pub type Blake2bVar = RtVariableCoreWrapper<Blake2bVarCore>;
/// Core hasher state of BLAKE2b generic over output size.
pub type Blake2bCore<OutSize> = CtVariableCoreWrapper<Blake2bVarCore, OutSize>;
/// BLAKE2b generic over output size.
pub type Blake2b<OutSize> = CoreWrapper<Blake2bCore<OutSize>>;
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

/// BLAKE2s which allows to choose output size at runtime.
pub type Blake2sVar = RtVariableCoreWrapper<Blake2sVarCore>;
/// Core hasher state of BLAKE2s generic over output size.
pub type Blake2sCore<OutSize> = CtVariableCoreWrapper<Blake2sVarCore, OutSize>;
/// BLAKE2s generic over output size.
pub type Blake2s<OutSize> = CoreWrapper<Blake2sCore<OutSize>>;
/// BLAKE2s-128 hasher state.
pub type Blake2s128 = Blake2s<U16>;
/// BLAKE2s-256 hasher state.
pub type Blake2s256 = Blake2s<U32>;

blake2_mac_impl!(Blake2sMac, Blake2sVarCore, U32, "Blake2s MAC function");

/// BLAKE2s-256 MAC state.
pub type Blake2sMac256 = Blake2sMac<U32>;
