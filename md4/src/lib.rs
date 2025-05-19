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
pub use block_api::Md4Core;

digest::newtype_fixed_hash!(
    /// MD4 hash.
    pub struct Md4(Md4Core);
    oid: "1.2.840.113549.2.4";
    impl: FixedHashTraits;
);
