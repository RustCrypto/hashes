#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![warn(missing_docs)]
#![deny(unsafe_code)]

pub use digest::{
    self, Digest,
    consts::{U32, U64, U128},
};

mod block_api;
pub use block_api::{Skein256Core, Skein512Core, Skein1024Core};

use digest::core_api::CoreWrapper;

digest::newtype!(
    /// Skein-256-256 hasher.
    pub struct Skein256_256(CoreWrapper<Skein256Core<U32>>);
    delegate_template: FixedOutputHash
);
digest::newtype!(
    /// Skein-256-512 hasher.
    pub struct Skein256_512(CoreWrapper<Skein256Core<U64>>);
    delegate_template: FixedOutputHash
);
digest::newtype!(
    /// Skein-512-256 hasher.
    pub struct Skein512_256(CoreWrapper<Skein512Core<U64>>);
    delegate_template: FixedOutputHash
);
digest::newtype!(
    /// Skein-512-512 hasher.
    pub struct Skein512_512(CoreWrapper<Skein512Core<U64>>);
    delegate_template: FixedOutputHash
);
digest::newtype!(
    /// Skein-1024-256 hasher.
    pub struct Skein1024_256(CoreWrapper<Skein1024Core<U32>>);
    delegate_template: FixedOutputHash
);
digest::newtype!(
    /// Skein-1024-512 hasher.
    pub struct Skein1024_512(CoreWrapper<Skein1024Core<U64>>);
    delegate_template: FixedOutputHash
);
digest::newtype!(
    /// Skein-1024-1024 hasher.
    pub struct Skein1024_1024(CoreWrapper<Skein1024Core<U128>>);
    delegate_template: FixedOutputHash
);
