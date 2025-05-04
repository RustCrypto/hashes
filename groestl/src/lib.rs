#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub use digest::{self, Digest};

mod block_api;
mod compress_long;
mod compress_short;
mod table;

pub use block_api::{GroestlLongVarCore, GroestlShortVarCore};

use digest::{
    consts::{U28, U32, U48, U64},
    core_api::{CoreWrapper, CtVariableCoreWrapper, RtVariableCoreWrapper},
};

digest::newtype_variable_hash!(
    /// Hasher state of the short Groestl variant generic over output size.
    pub struct GroestlShort<OutSize>(CoreWrapper<CtVariableCoreWrapper<GroestlShortVarCore, OutSize>>);
    /// Short Groestl variant which allows to select output size at runtime.
    pub struct GroestlShortVar(RtVariableCoreWrapper<GroestlShortVarCore>);
    max_size: U32;
);
digest::newtype_variable_hash!(
    /// Hasher state of the long Groestl variant generic over output size.
    pub struct GroestlLong<OutSize>(CoreWrapper<CtVariableCoreWrapper<GroestlLongVarCore, OutSize>>);
    /// Short Groestl variant which allows to select output size at runtime.
    pub struct GroestlLongVar(RtVariableCoreWrapper<GroestlLongVarCore>);
    max_size: U64;
);

/// Groestl-224 hasher state.
pub type Groestl224 = GroestlShort<U28>;
/// Groestl-256 hasher state.
pub type Groestl256 = GroestlShort<U32>;

/// Groestl-384 hasher state.
pub type Groestl384 = GroestlLong<U48>;
/// Groestl-512 hasher state.
pub type Groestl512 = GroestlLong<U64>;
