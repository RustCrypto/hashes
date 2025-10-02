#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, unreachable_pub)]

pub use digest::{self, Digest};

/// Block-level types
pub mod block_api;
mod compress;
mod tables;

digest::buffer_fixed!(
    /// Tiger hasher.
    pub struct Tiger(block_api::TigerCore<false>);
    impl: FixedHashTraits;
);

digest::buffer_fixed!(
    /// Tiger2 hasher.
    pub struct Tiger2(block_api::TigerCore<true>);
    impl: FixedHashTraits;
);
