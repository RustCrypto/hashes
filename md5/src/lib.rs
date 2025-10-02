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
mod consts;

digest::buffer_fixed!(
    /// MD5 hasher state.
    pub struct Md5(block_api::Md5Core);
    oid: "1.2.840.113549.2.5";
    impl: FixedHashTraits;
);
