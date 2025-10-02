#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, unreachable_pub)]
#![forbid(unsafe_code)]

pub use digest::{self, Digest};

/// Block-level types
pub mod block_api;

digest::buffer_fixed!(
    /// BelT hasher state.
    pub struct BeltHash(block_api::BeltHashCore);
    oid: "1.2.112.0.2.0.34.101.31.81";
    impl: FixedHashTraits;
);
