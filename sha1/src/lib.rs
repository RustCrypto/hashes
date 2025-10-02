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

digest::buffer_fixed!(
    /// SHA-1 hasher.
    pub struct Sha1(block_api::Sha1Core);
    oid: "1.3.14.3.2.26";
    impl: FixedHashTraits;
);
