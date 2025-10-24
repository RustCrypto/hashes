#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, unreachable_pub)]

pub use digest::{self, Digest};

/// Block-level types
pub mod block_api;
mod consts;
mod long;
mod short;
pub(crate) mod utils;

use digest::consts::{U28, U32, U48, U64};

digest::buffer_ct_variable!(
    /// Short Kupyna variant generic over output size.
    pub struct KupynaShort<OutSize>(block_api::KupynaShortVarCore);
    max_size: U32;
);
digest::buffer_ct_variable!(
    /// Long Kupyna variant generic over output size.
    pub struct KupynaLong<OutSize>(block_api::KupynaLongVarCore);
    max_size: U64;
);

/// Kupyna-224 hasher.
pub type Kupyna224 = KupynaShort<U28>;
/// Kupyna-256 hasher.
pub type Kupyna256 = KupynaShort<U32>;
/// Kupyna-384 hasher.
pub type Kupyna384 = KupynaLong<U48>;
/// Kupyna-512 hasher.
pub type Kupyna512 = KupynaLong<U64>;
