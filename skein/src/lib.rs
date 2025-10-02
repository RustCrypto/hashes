#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, unreachable_pub)]
#![deny(unsafe_code)]

pub use digest::{
    self, Digest,
    consts::{U32, U64, U128},
};

use digest::array::ArraySize;

/// Block-level types
pub mod block_api;

digest::buffer_fixed!(
    /// Skein-256 hasher generic over output size
    pub struct Skein256<N: ArraySize>(block_api::Skein256Core<N>);
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// Skein-512 hasher generic over output size
    pub struct Skein512<N: ArraySize>(block_api::Skein512Core<N>);
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// Skein-1024 hasher generic over output size
    pub struct Skein1024<N: ArraySize>(block_api::Skein1024Core<N>);
    impl: FixedHashTraits;
);

/// Skein-256-256 hasher.
pub type Skein256_256 = Skein256<U32>;
/// Skein-256-512 hasher.
pub type Skein256_512 = Skein256<U64>;
/// Skein-512-256 hasher.
pub type Skein512_256 = Skein512<U32>;
/// Skein-512-512 hasher.
pub type Skein512_512 = Skein512<U64>;
/// Skein-1024-256 hasher.
pub type Skein1024_256 = Skein1024<U32>;
/// Skein-1024-512 hasher.
pub type Skein1024_512 = Skein1024<U64>;
/// Skein-1024-1024 hasher.
pub type Skein1024_1024 = Skein1024<U128>;
