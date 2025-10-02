#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, unreachable_pub)]
#![allow(non_snake_case)]

pub use digest::{self, Digest};

static PI: &[u8; 272_384] = include_bytes!("pi.bin");

/// Block-level types
pub mod block_api;

digest::buffer_fixed!(
    /// FSB-160 hasher.
    pub struct Fsb160(block_api::Fsb160Core);
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// FSB-224 hasher.
    pub struct Fsb224(block_api::Fsb224Core);
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// FSB-256 hasher.
    pub struct Fsb256(block_api::Fsb256Core);
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// FSB-384 hasher.
    pub struct Fsb384(block_api::Fsb384Core);
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// FSB-512 hasher.
    pub struct Fsb512(block_api::Fsb512Core);
    impl: FixedHashTraits;
);
