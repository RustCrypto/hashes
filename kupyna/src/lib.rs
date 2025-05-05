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
use digest::{
    core_api::{CoreWrapper, CtVariableCoreWrapper, RtVariableCoreWrapper},
    typenum::{U28, U32, U48, U64},
};

mod consts;
mod long;
mod long_compress;
mod short;
mod short_compress;
pub(crate) mod utils;

pub use long::KupynaLongVarCore;
pub use short::KupynaShortVarCore;

digest::newtype_variable_hash!(
    /// Hasher state of the short Groestl variant generic over output size.
    pub struct KupynaShort<OutSize>(CoreWrapper<CtVariableCoreWrapper<KupynaShortVarCore, OutSize>>);
    /// Short Groestl variant which allows to select output size at runtime.
    pub struct KupynaShortVar(RtVariableCoreWrapper<KupynaShortVarCore>);
    max_size: U32;
);
digest::newtype_variable_hash!(
    /// Hasher state of the long Groestl variant generic over output size.
    pub struct KupynaLong<OutSize>(CoreWrapper<CtVariableCoreWrapper<KupynaLongVarCore, OutSize>>);
    /// Short Groestl variant which allows to select output size at runtime.
    pub struct KupynaLongVar(RtVariableCoreWrapper<KupynaLongVarCore>);
    max_size: U64;
);

/// Kupyna-224 hasher state.
pub type Kupyna224 = KupynaShort<U28>;
/// Kupyna-256 hasher state.
pub type Kupyna256 = KupynaShort<U32>;
/// Kupyna-384 hasher state.
pub type Kupyna384 = KupynaLong<U48>;
/// Kupyna-512 hasher state.
pub type Kupyna512 = KupynaLong<U64>;
