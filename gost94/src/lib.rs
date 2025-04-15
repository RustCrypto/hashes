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

mod gost94_core;
/// GOST94 parameters.
pub mod params;

pub use gost94_core::Gost94Core;

// TODO: expose Gost94 generic over params
digest::newtype!(
    /// GOST94 hash function with CryptoPro parameters.
    pub struct Gost94CryptoPro(CoreWrapper<Gost94Core<params::CryptoProParam>>);
    delegate_template: FixedOutputHash
    // Per RFC 4490
    oid: "1.2.643.2.2.9"
);

digest::newtype!(
    /// GOST94 hash function with S-box defined in GOST R 34.12-2015.
    pub struct Gost94s2015(CoreWrapper<Gost94Core<params::S2015Param>>);
    delegate_template: FixedOutputHash
);

digest::newtype!(
    /// GOST94 hash function with test parameters.
    pub struct Gost94Test(CoreWrapper<Gost94Core<params::TestParam>>);
    delegate_template: FixedOutputHash
);

digest::newtype!(
    /// GOST94 hash function with UAPKI GOST 34.311-95 parameters
    pub struct Gost94UA(CoreWrapper<Gost94Core<params::GOST28147UAParam>>);
    delegate_template: FixedOutputHash
    oid: "1.2.804.2.1.1.1.1.2.1"
);
