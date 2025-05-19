#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[rustfmt::skip]
mod consts;
mod block_api;

pub use block_api::ShabalVarCore;
pub use digest::{self, Digest};

use digest::{
    consts::{U24, U28, U32, U48, U64},
    core_api::CtOutWrapper,
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
