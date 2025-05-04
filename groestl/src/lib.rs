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

/// Short Groestl variant which allows to choose output size at runtime.
pub type GroestlShortVar = RtVariableCoreWrapper<GroestlShortVarCore>;
/// Core hasher state of the short Groestl variant generic over output size.
pub type GroestlShortCore<OutSize> = CtVariableCoreWrapper<GroestlShortVarCore, OutSize>;
/// Hasher state of the short Groestl variant generic over output size.
pub type GroestlShort<OutSize> = CoreWrapper<GroestlShortCore<OutSize>>;

/// Groestl-224 hasher state.
pub type Groestl224 = CoreWrapper<GroestlShortCore<U28>>;
/// Groestl-256 hasher state.
pub type Groestl256 = CoreWrapper<GroestlShortCore<U32>>;

/// Long Groestl variant which allows to choose output size at runtime.
pub type GroestlLongVar = RtVariableCoreWrapper<GroestlLongVarCore>;
/// Core hasher state of the long Groestl variant generic over output size.
pub type GroestlLongCore<OutSize> = CtVariableCoreWrapper<GroestlLongVarCore, OutSize>;
/// Hasher state of the long Groestl variant generic over output size.
pub type GroestlLong<OutSize> = CoreWrapper<GroestlLongCore<OutSize>>;

/// Groestl-384 hasher state.
pub type Groestl384 = CoreWrapper<GroestlLongCore<U48>>;
/// Groestl-512 hasher state.
pub type Groestl512 = CoreWrapper<GroestlLongCore<U64>>;
