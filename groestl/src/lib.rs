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

mod compress_long;
mod compress_short;
mod table;

use digest::consts::{U28, U32, U48, U64};

digest::buffer_ct_variable!(
    /// Short Groestl variant generic over output size.
    pub struct GroestlShort<OutSize>(block_api::GroestlShortVarCore);
    max_size: U32;
);
digest::buffer_ct_variable!(
    /// Long Groestl variant generic over output size.
    pub struct GroestlLong<OutSize>(block_api::GroestlLongVarCore);
    max_size: U64;
);

/// Groestl-224 hasher.
pub type Groestl224 = GroestlShort<U28>;
/// Groestl-256 hasher.
pub type Groestl256 = GroestlShort<U32>;

/// Groestl-384 hasher.
pub type Groestl384 = GroestlLong<U48>;
/// Groestl-512 hasher.
pub type Groestl512 = GroestlLong<U64>;
