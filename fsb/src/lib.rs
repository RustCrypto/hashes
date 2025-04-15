#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![allow(non_snake_case)]

pub use digest::{self, Digest};

static PI: &[u8; 272_384] = include_bytes!("pi.bin");

mod block_api;
pub use block_api::{Fsb160Core, Fsb224Core, Fsb256Core, Fsb384Core, Fsb512Core};

use digest::core_api::CoreWrapper;

digest::newtype!(
    /// FSB-160 hasher.
    pub struct Fsb160(CoreWrapper<Fsb160Core>);
    delegate_template: FixedOutputHash
);
digest::newtype!(
    /// FSB-224 hasher.
    pub struct Fsb224(CoreWrapper<Fsb224Core>);
    delegate_template: FixedOutputHash
);
digest::newtype!(
    /// FSB-256 hasher.
    pub struct Fsb256(CoreWrapper<Fsb256Core>);
    delegate_template: FixedOutputHash
);
digest::newtype!(
    /// FSB-384 hasher.
    pub struct Fsb384(CoreWrapper<Fsb384Core>);
    delegate_template: FixedOutputHash
);
digest::newtype!(
    /// FSB-512 hasher.
    pub struct Fsb512(CoreWrapper<Fsb512Core>);
    delegate_template: FixedOutputHash
);
