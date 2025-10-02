#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, unreachable_pub)]

pub use digest::{self, Digest};

/// Block-level types
pub mod block_api;

#[rustfmt::skip]
mod consts;


use block_api::ShabalVarCore;
use digest::{
    block_api::CtOutWrapper,
    consts::{U24, U28, U32, U48, U64},
};

digest::buffer_fixed!(
    /// Shabal-192 hasher.
    pub struct Shabal192(CtOutWrapper<ShabalVarCore, U24>);
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// Shabal-224 hasher.
    pub struct Shabal224(CtOutWrapper<ShabalVarCore, U28>);
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// Shabal-256 hasher.
    pub struct Shabal256(CtOutWrapper<ShabalVarCore, U32>);
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// Shabal-384 hasher.
    pub struct Shabal384(CtOutWrapper<ShabalVarCore, U48>);
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// Shabal-512 hasher.
    pub struct Shabal512(CtOutWrapper<ShabalVarCore, U64>);
    impl: FixedHashTraits;
);
