#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![warn(missing_docs)]
#![deny(unsafe_code)]

pub use digest::{
    self, Digest,
    consts::{U32, U64, U128},
};

mod block_api;
pub use block_api::{Skein256Core, Skein512Core, Skein1024Core};

use digest::core_api::CoreWrapper;

// note: we do not use `delegate_template: FixedOutputHash` because
// `Skein*Core`  not implement `SerializableState`
// TODO: expose output size type parameter
digest::newtype!(
    /// Skein256 hasher.
    pub struct Skein256(CoreWrapper<Skein256Core<U32>>);
    delegate:
        Debug Clone Default
        AlgorithmName
        BlockSizeUser OutputSizeUser
        HashMarker Reset Update
        FixedOutput FixedOutputReset
);
digest::newtype!(
    /// Skein512 hasher.
    pub struct Skein512(CoreWrapper<Skein512Core<U64>>);
    delegate:
        Debug Clone Default
        AlgorithmName
        BlockSizeUser OutputSizeUser
        HashMarker Reset Update
        FixedOutput FixedOutputReset
);
digest::newtype!(
    /// Skein1024 hasher.
    pub struct Skein1024(CoreWrapper<Skein1024Core<U128>>);
    delegate:
        Debug Clone Default
        AlgorithmName
        BlockSizeUser OutputSizeUser
        HashMarker Reset Update
        FixedOutput FixedOutputReset
);
