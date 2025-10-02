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
mod c128;
mod c160;
mod c256;
mod c320;

// Note about used OIDs: there are two OIDs defined for RIPEMD-128/160.
// The Teletrust one (which is used by almost anybody, including BouncyCastle,
// OpenSSL, GnuTLS, etc.) and the ISO one (1.0.10118.3.0.50/49), which appears
// to be used only by the Go standard library.

digest::buffer_fixed!(
    /// RIPEMD-128 hasher
    pub struct Ripemd128(block_api::Ripemd128Core);
    oid: "1.3.36.3.2.2";
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// RIPEMD-160 hasher
    pub struct Ripemd160(block_api::Ripemd160Core);
    oid: "1.3.36.3.2.1";
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// RIPEMD-256 hasher
    pub struct Ripemd256(block_api::Ripemd256Core);
    oid: "1.3.36.3.2.3";
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// RIPEMD-320 hasher
    pub struct Ripemd320(block_api::Ripemd320Core);
    impl: FixedHashTraits;
);
