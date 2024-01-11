#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![warn(missing_docs, rust_2018_idioms)]

pub use digest::{self, Digest};

#[cfg(feature = "oid")]
use digest::const_oid::{AssociatedOid, ObjectIdentifier};
use digest::{
    consts::{U28, U32, U48, U64},
    core_api::{CoreWrapper, CtVariableCoreWrapper},
    impl_oid_carrier,
};

#[rustfmt::skip]
mod consts;
mod core_api;
mod sha256;
mod sha512;

pub use sha256::compress256;
pub use sha512::compress512;

pub use core_api::{Sha256VarCore, Sha512VarCore};

impl_oid_carrier!(OidSha256, "2.16.840.1.101.3.4.2.1");
impl_oid_carrier!(OidSha384, "2.16.840.1.101.3.4.2.2");
impl_oid_carrier!(OidSha512, "2.16.840.1.101.3.4.2.3");
impl_oid_carrier!(OidSha224, "2.16.840.1.101.3.4.2.4");
impl_oid_carrier!(OidSha512_224, "2.16.840.1.101.3.4.2.5");
impl_oid_carrier!(OidSha512_256, "2.16.840.1.101.3.4.2.6");

/// SHA-224 hasher.
pub type Sha224 = CoreWrapper<CtVariableCoreWrapper<Sha256VarCore, U28, OidSha224>>;
/// SHA-256 hasher.
pub type Sha256 = CoreWrapper<CtVariableCoreWrapper<Sha256VarCore, U32, OidSha256>>;
/// SHA-512/224 hasher.
pub type Sha512_224 = CoreWrapper<CtVariableCoreWrapper<Sha512VarCore, U28, OidSha512_224>>;
/// SHA-512/256 hasher.
pub type Sha512_256 = CoreWrapper<CtVariableCoreWrapper<Sha512VarCore, U32, OidSha512_256>>;
/// SHA-384 hasher.
pub type Sha384 = CoreWrapper<CtVariableCoreWrapper<Sha512VarCore, U48, OidSha384>>;
/// SHA-512 hasher.
pub type Sha512 = CoreWrapper<CtVariableCoreWrapper<Sha512VarCore, U64, OidSha512>>;
