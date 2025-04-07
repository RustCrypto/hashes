#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![warn(missing_docs)]
#![forbid(unsafe_code)]

pub use digest::{self, Digest};

use digest::core_api::CoreWrapper;

mod block_api;

pub use block_api::BeltHashCore;

digest::newtype!(
    /// BelT hasher state.
    pub struct BeltHash(CoreWrapper<BeltHashCore>);
    delegate_template: FixedOutputHash
    oid: "1.2.112.0.2.0.34.101.31.81"
);
