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
mod core_api;

pub use core_api::ShabalVarCore;
pub use digest::{self, Digest};

use digest::{
    consts::{U24, U28, U32, U48, U64},
    core_api::{CoreWrapper, CtVariableCoreWrapper},
};

/// Shabal192 hasher.
pub type Shabal192 = CoreWrapper<CtVariableCoreWrapper<ShabalVarCore, U24>>;
/// Shabal224 hasher.
pub type Shabal224 = CoreWrapper<CtVariableCoreWrapper<ShabalVarCore, U28>>;
/// Shabal256 hasher.
pub type Shabal256 = CoreWrapper<CtVariableCoreWrapper<ShabalVarCore, U32>>;
/// Shabal384 hasher.
pub type Shabal384 = CoreWrapper<CtVariableCoreWrapper<ShabalVarCore, U48>>;
/// Shabal512 hasher.
pub type Shabal512 = CoreWrapper<CtVariableCoreWrapper<ShabalVarCore, U64>>;
