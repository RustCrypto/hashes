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
    block_api::CtOutWrapper,
    consts::{U32, U64},
};

mod block_api;
mod consts;

pub use block_api::StreebogVarCore;
pub use digest::{self, Digest};

digest::buffer_fixed!(
    /// Streebog256 hasher.
    pub struct Streebog256(CtOutWrapper<StreebogVarCore, U32>);
    oid: "1.2.643.7.1.1.2.2";
    impl: FixedHashTraits;
);

digest::buffer_fixed!(
    /// Streebog512 hasher.
    pub struct Streebog512(CtOutWrapper<StreebogVarCore, U64>);
    oid: "1.2.643.7.1.1.2.3";
    impl: FixedHashTraits;
);
