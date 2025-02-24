#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
#![allow(non_snake_case)]

#[macro_use]
mod macros;

use core::{fmt, ops::Add};
pub use digest::{self, Digest};

// Double check this contains all values in the reference implementation
static PI: &[u8; 272384] = include_bytes!("pi.bin");

use digest::{
    HashMarker, Output,
    block_buffer::Eager,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore,
        OutputSizeUser, Reset, UpdateCore,
    },
    crypto_common::hazmat::{DeserializeStateError, SerializableState, SerializedState},
    typenum::{U8, Unsigned},
};

#[cfg(feature = "zeroize")]
use digest::zeroize::{Zeroize, ZeroizeOnDrop};

// FSB-160
fsb_impl!(
    Fsb160,
    Fsb160Core,
    160,
    U60,
    U20,
    U80,
    5 << 18,
    80,
    640,
    653,
    1120,
    "FSB-160 hasher state",
    "Core FSB-160 hasher state",
);

// FSB-224
fsb_impl!(
    Fsb224,
    Fsb224Core,
    224,
    U84,
    U28,
    U112,
    7 << 18,
    112,
    896,
    907,
    1568,
    "FSB-224 hasher state",
    "Core FSB-224 hasher state",
);

// FSB-256
fsb_impl!(
    Fsb256,
    Fsb256Core,
    256,
    U96,
    U32,
    U128,
    1 << 21,
    128,
    1024,
    1061,
    1792,
    "FSB-256 hasher state",
    "Core FSB-256 hasher state",
);

// FSB-384
fsb_impl!(
    Fsb384,
    Fsb384Core,
    384,
    U115,
    U48,
    U184,
    23 << 16,
    184,
    1472,
    1483,
    2392,
    "FSB-384 hasher state",
    "Core FSB-384 hasher state",
);

// FSB-512
fsb_impl!(
    Fsb512,
    Fsb512Core,
    512,
    U155,
    U64,
    U248,
    31 << 16,
    248,
    1984,
    1987,
    3224,
    "FSB-512 hasher state",
    "Core FSB-512 hasher state",
);
