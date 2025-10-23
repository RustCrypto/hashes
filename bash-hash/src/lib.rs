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
    /// BASH256 hasher state.
    pub struct BashHash256(block_api::Bash256Core);
    oid: "1.2.112.0.2.0.34.101.77.11";
    impl: FixedHashTraits;
);

digest::buffer_fixed!(
    /// BASH384 hasher state.
    pub struct BashHash384(block_api::Bash384Core);
    oid: "1.2.112.0.2.0.34.101.77.12";
    impl: FixedHashTraits;
);

digest::buffer_fixed!(
    /// BASH512 hasher state.
    pub struct BashHash512(block_api::Bash512Core);
    oid: "1.2.112.0.2.0.34.101.77.13";
    impl: FixedHashTraits;
);
