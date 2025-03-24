#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "oid")]
use digest::const_oid::{AssociatedOid, ObjectIdentifier};
use digest::{
    consts::{U32, U64},
    core_api::{CoreWrapper, CtVariableCoreWrapper},
    impl_oid_carrier,
};

mod consts;
mod core_api;

pub use core_api::StreebogVarCore;
pub use digest::{self, Digest};

impl_oid_carrier!(Oid256, "1.2.643.7.1.1.2.2");
impl_oid_carrier!(Oid512, "1.2.643.7.1.1.2.3");

/// Streebog256 hasher.
pub type Streebog256 = CoreWrapper<CtVariableCoreWrapper<StreebogVarCore, U32, Oid256>>;
/// Streebog512 hasher.
pub type Streebog512 = CoreWrapper<CtVariableCoreWrapper<StreebogVarCore, U64, Oid512>>;
