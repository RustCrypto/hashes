#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, unreachable_pub)]

pub use digest::{self, Digest};

/// Block-level types
pub mod block_api;
mod compressor;
mod consts;

use digest::{
    block_api::CtOutWrapper,
    consts::{U28, U32, U48, U64},
};

digest::buffer_fixed!(
    /// JH-224 hasher.
    pub struct Jh224(CtOutWrapper<block_api::JhCore, U28>);
    impl: BaseFixedTraits AlgorithmName Default Clone HashMarker Reset FixedOutputReset;
);
digest::buffer_fixed!(
    /// JH-256 hasher.
    pub struct Jh256(CtOutWrapper<block_api::JhCore, U32>);
    impl: BaseFixedTraits AlgorithmName Default Clone HashMarker Reset FixedOutputReset;
);
digest::buffer_fixed!(
    /// JH-384 hasher.
    pub struct Jh384(CtOutWrapper<block_api::JhCore, U48>);
    impl: BaseFixedTraits AlgorithmName Default Clone HashMarker Reset FixedOutputReset;
);
digest::buffer_fixed!(
    /// JH-512 hasher.
    pub struct Jh512(CtOutWrapper<block_api::JhCore, U64>);
    impl: BaseFixedTraits AlgorithmName Default Clone HashMarker Reset FixedOutputReset;
);
