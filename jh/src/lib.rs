#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![warn(missing_docs)]

pub use digest::{self, Digest};

mod block_api;
mod compressor;
mod consts;

pub use block_api::JhCore;

use digest::{
    consts::{U28, U32, U48, U64},
    core_api::CtOutWrapper,
};

digest::newtype_fixed_hash!(
    /// JH-224 hasher.
    pub struct Jh224(CtOutWrapper<JhCore, U28>);
    impl: BaseFixedTraits Default Clone HashMarker Reset FixedOutputReset;
);
digest::newtype_fixed_hash!(
    /// JH-256 hasher.
    pub struct Jh256(CtOutWrapper<JhCore, U32>);
    impl: BaseFixedTraits Default Clone HashMarker Reset FixedOutputReset;
);
digest::newtype_fixed_hash!(
    /// JH-384 hasher.
    pub struct Jh384(CtOutWrapper<JhCore, U48>);
    impl: BaseFixedTraits Default Clone HashMarker Reset FixedOutputReset;
);
digest::newtype_fixed_hash!(
    /// JH-512 hasher.
    pub struct Jh512(CtOutWrapper<JhCore, U64>);
    impl: BaseFixedTraits Default Clone HashMarker Reset FixedOutputReset;
);
