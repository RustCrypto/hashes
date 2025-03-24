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

/// Short Kupyna variant which allows to choose output size at runtime.
pub type KupynaShortVar = RtVariableCoreWrapper<KupynaShortVarCore>;
/// Core hasher state of the short Kupyna variant generic over output size.
pub type KupynaShortCore<OutSize> = CtVariableCoreWrapper<KupynaShortVarCore, OutSize>;
/// Hasher state of the short Kupyna variant generic over output size.
pub type KupynaShort<OutSize> = CoreWrapper<KupynaShortCore<OutSize>>;

/// Long Kupyna variant which allows to choose output size at runtime.
pub type KupynaLongVar = RtVariableCoreWrapper<KupynaLongVarCore>;
/// Core hasher state of the long Kupyna variant generic over output size.
pub type KupynaLongCore<OutSize> = CtVariableCoreWrapper<KupynaLongVarCore, OutSize>;
/// Hasher state of the long Kupyna variant generic over output size.
pub type KupynaLong<OutSize> = CoreWrapper<KupynaLongCore<OutSize>>;

/// Kupyna-224 hasher state.
pub type Kupyna224 = CoreWrapper<KupynaShortCore<U28>>;
/// Kupyna-256 hasher state.
pub type Kupyna256 = CoreWrapper<KupynaShortCore<U32>>;
/// Kupyna-384 hasher state.
pub type Kupyna384 = CoreWrapper<KupynaLongCore<U48>>;
/// Kupyna-512 hasher state.
pub type Kupyna512 = CoreWrapper<KupynaLongCore<U64>>;
