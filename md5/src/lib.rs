#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![warn(missing_docs)]

pub use digest::{self, Digest};

mod block_api;
mod compress;
mod consts;
pub use block_api::Md5Core;

digest::newtype_fixed_hash!(
    /// MD5 hasher state.
    pub struct Md5(Md5Core);
    oid: "1.2.840.113549.2.5"
);
