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
    core_api::{CoreWrapper, CtVariableCoreWrapper},
    typenum::{U28, U32, U48, U64},
};

mod block_api;
mod consts;
mod long;
mod short;
pub(crate) mod utils;

pub use block_api::{KupynaLongVarCore, KupynaShortVarCore};

digest::newtype_ct_variable_hash!(
    /// Short Kupyna variant generic over output size.
    pub struct KupynaShort<OutSize>(CoreWrapper<CtVariableCoreWrapper<KupynaShortVarCore, OutSize>>);
    max_size: U32;
);
digest::newtype_rt_variable_hash!(
    /// Short Kupyna variant which allows to select output size at runtime.
    pub struct KupynaShortVar(KupynaShortVarCore);
);
digest::newtype_ct_variable_hash!(
    /// Long Kupyna variant generic over output size.
    pub struct KupynaLong<OutSize>(CoreWrapper<CtVariableCoreWrapper<KupynaLongVarCore, OutSize>>);
    max_size: U64;
);
digest::newtype_rt_variable_hash!(
    /// Long Kupyna variant which allows to select output size at runtime.
    pub struct KupynaLongVar(KupynaLongVarCore);
);

/// Kupyna-224 hasher.
pub type Kupyna224 = KupynaShort<U28>;
/// Kupyna-256 hasher.
pub type Kupyna256 = KupynaShort<U32>;
/// Kupyna-384 hasher.
pub type Kupyna384 = KupynaLong<U48>;
/// Kupyna-512 hasher.
pub type Kupyna512 = KupynaLong<U64>;
