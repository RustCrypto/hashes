#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(unsafe_code)]
#![warn(missing_docs)]

pub use digest::{self, Digest};

mod block_api;
mod compress;
mod consts;

pub use block_api::WhirlpoolCore;

digest::newtype_fixed_hash!(
    /// Whirlpool hasher.
    pub struct Whirlpool(WhirlpoolCore);
    impl: FixedHashTraits;
);
