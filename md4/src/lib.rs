#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, unreachable_pub)]

pub use digest::{self, Digest};

/// Block-level types
pub mod block_api;
mod compress;

digest::buffer_fixed!(
    /// MD4 hash.
    pub struct Md4(block_api::Md4Core);
    oid: "1.2.840.113549.2.4";
    impl: FixedHashTraits;
);
