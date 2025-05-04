#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![warn(missing_docs)]

pub use digest::{self, Digest};

mod block_api;
mod compress;
mod tables;

pub use block_api::TigerCore;

digest::newtype_fixed_hash!(
    /// Tiger hasher.
    pub struct Tiger(digest::core_api::CoreWrapper<TigerCore<false>>);
);

digest::newtype_fixed_hash!(
    /// Tiger2 hasher.
    pub struct Tiger2(digest::core_api::CoreWrapper<TigerCore<true>>);
);
