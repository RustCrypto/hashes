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
    core_api::{CoreWrapper, CtVariableCoreWrapper},
};

digest::newtype!(
    /// Shabal-192 hasher.
    pub struct Shabal192(CoreWrapper<CtVariableCoreWrapper<ShabalVarCore, U24>>);
    delegate_template: FixedOutputHash
);
digest::newtype!(
    /// Shabal-224 hasher.
    pub struct Shabal224(CoreWrapper<CtVariableCoreWrapper<ShabalVarCore, U28>>);
    delegate_template: FixedOutputHash
);
digest::newtype!(
    /// Shabal-256 hasher.
    pub struct Shabal256(CoreWrapper<CtVariableCoreWrapper<ShabalVarCore, U32>>);
    delegate_template: FixedOutputHash
);
digest::newtype!(
    /// Shabal-384 hasher.
    pub struct Shabal384(CoreWrapper<CtVariableCoreWrapper<ShabalVarCore, U48>>);
    delegate_template: FixedOutputHash
);
digest::newtype!(
    /// Shabal-512 hasher.
    pub struct Shabal512(CoreWrapper<CtVariableCoreWrapper<ShabalVarCore, U64>>);
    delegate_template: FixedOutputHash
);
