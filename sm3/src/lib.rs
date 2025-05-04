#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub use digest::{self, Digest};

mod block_api;
mod compress;
mod consts;

pub use block_api::Sm3Core;

digest::newtype_fixed_hash!(
    /// ShangMi 3 (SM3) hasher.
    pub struct Sm3(digest::core_api::CoreWrapper<Sm3Core>);
);
