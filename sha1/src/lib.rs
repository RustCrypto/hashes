#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![warn(missing_docs)]

pub use digest::{self, Digest};

use digest::core_api::CoreWrapper;

mod block_api;
mod compress;

pub use block_api::Sha1Core;
pub use compress::compress;

digest::newtype!(
    /// SHA-1 hasher.
    pub struct Sha1(CoreWrapper<Sha1Core>);
    delegate_template: FixedOutputHash
    oid: "1.3.14.3.2.26"
);
