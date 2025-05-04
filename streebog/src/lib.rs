#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

use digest::{
    consts::{U32, U64},
    core_api::{CoreWrapper, CtVariableCoreWrapper},
};

mod block_api;
mod consts;

pub use block_api::StreebogVarCore;
pub use digest::{self, Digest};

digest::newtype_fixed_hash!(
    /// Streebog256 hasher.
    pub struct Streebog256(CoreWrapper<CtVariableCoreWrapper<StreebogVarCore, U32>>);
    oid: "1.2.643.7.1.1.2.2"
);

digest::newtype_fixed_hash!(
    /// Streebog512 hasher.
    pub struct Streebog512(CoreWrapper<CtVariableCoreWrapper<StreebogVarCore, U64>>);
    oid: "1.2.643.7.1.1.2.3"
);
