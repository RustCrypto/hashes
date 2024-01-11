#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![warn(missing_docs, rust_2018_idioms)]
#![forbid(unsafe_code)]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "oid")]
use digest::const_oid::{AssociatedOid, ObjectIdentifier};
use digest::core_api::CoreWrapper;

mod gost94_core;
/// GOST94 parameters.
pub mod params;

pub use digest::{self, Digest};

pub use gost94_core::Gost94Core;

#[cfg(feature = "oid")]
impl AssociatedOid for Gost94Core<params::CryptoProParam> {
    /// Per RFC 4490
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.643.2.2.9");
}

#[cfg(feature = "oid")]
impl AssociatedOid for Gost94Core<params::GOST28147UAParam> {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.804.2.1.1.1.1.2.1");
}

/// GOST94 hash function with CryptoPro parameters.
pub type Gost94CryptoPro = CoreWrapper<Gost94Core<params::CryptoProParam>>;
/// GOST94 hash function with S-box defined in GOST R 34.12-2015.
pub type Gost94s2015 = CoreWrapper<Gost94Core<params::S2015Param>>;
/// GOST94 hash function with test parameters.
pub type Gost94Test = CoreWrapper<Gost94Core<params::TestParam>>;
/// GOST94 hash function with UAPKI GOST 34.311-95 parameters
/// (1.2.804.2.1.1.1.1.2.1 OID).
pub type Gost94UA = CoreWrapper<Gost94Core<params::GOST28147UAParam>>;
