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

digest::newtype!(
    "Shabal192 hasher",
    Shabal192 = CoreWrapper<CtVariableCoreWrapper<ShabalVarCore, U24>>
);

digest::newtype!(
    "Shabal224 hasher",
    Shabal224 = CoreWrapper<CtVariableCoreWrapper<ShabalVarCore, U28>>
);

digest::newtype!(
    "Shabal256 hasher",
    Shabal256 = CoreWrapper<CtVariableCoreWrapper<ShabalVarCore, U32>>
);

digest::newtype!(
    "Shabal384 hasher",
    Shabal384 = CoreWrapper<CtVariableCoreWrapper<ShabalVarCore, U48>>
);

digest::newtype!(
    "Shabal512 hasher",
    Shabal512 = CoreWrapper<CtVariableCoreWrapper<ShabalVarCore, U64>>
);
