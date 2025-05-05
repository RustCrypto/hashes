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
    core_api::CtVariableCoreWrapper,
};

digest::newtype_fixed_hash!(
    /// Shabal-192 hasher.
    pub struct Shabal192(CtVariableCoreWrapper<ShabalVarCore, U24>);
);
digest::newtype_fixed_hash!(
    /// Shabal-224 hasher.
    pub struct Shabal224(CtVariableCoreWrapper<ShabalVarCore, U28>);
);
digest::newtype_fixed_hash!(
    /// Shabal-256 hasher.
    pub struct Shabal256(CtVariableCoreWrapper<ShabalVarCore, U32>);
);
digest::newtype_fixed_hash!(
    /// Shabal-384 hasher.
    pub struct Shabal384(CtVariableCoreWrapper<ShabalVarCore, U48>);
);
digest::newtype_fixed_hash!(
    /// Shabal-512 hasher.
    pub struct Shabal512(CtVariableCoreWrapper<ShabalVarCore, U64>);
);
