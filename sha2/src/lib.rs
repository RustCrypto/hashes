#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, unreachable_pub)]
#![cfg_attr(
    any(sha2_backend = "riscv-zknh", sha2_backend = "riscv-zknh-compact"),
    feature(riscv_ext_intrinsics)
)]
#![allow(clippy::needless_range_loop)]

#[cfg(all(
    any(sha2_backend = "riscv-zknh", sha2_backend = "riscv-zknh-compact"),
    not(any(any(target_arch = "riscv32", target_arch = "riscv64")))
))]
compile_error!("The Zknh backends can be enabled only for RISC-V targets");

pub use digest::{self, Digest};

use digest::{
    block_api::CtOutWrapper,
    consts::{U28, U32, U48, U64},
};

/// Block-level types
pub mod block_api;

#[rustfmt::skip]
mod consts;
mod sha256;
mod sha512;

digest::buffer_fixed!(
    /// SHA-256 hasher.
    pub struct Sha256(CtOutWrapper<block_api::Sha256VarCore, U32>);
    oid: "2.16.840.1.101.3.4.2.1";
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// SHA-384 hasher.
    pub struct Sha384(CtOutWrapper<block_api::Sha512VarCore, U48>);
    oid: "2.16.840.1.101.3.4.2.2";
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// SHA-512 hasher.
    pub struct Sha512(CtOutWrapper<block_api::Sha512VarCore, U64>);
    oid: "2.16.840.1.101.3.4.2.3";
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// SHA-224 hasher.
    pub struct Sha224(CtOutWrapper<block_api::Sha256VarCore, U28>);
    oid: "2.16.840.1.101.3.4.2.4";
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// SHA-512/224 hasher.
    pub struct Sha512_224(CtOutWrapper<block_api::Sha512VarCore, U28>);
    oid: "2.16.840.1.101.3.4.2.5";
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// SHA-512/256 hasher.
    pub struct Sha512_256(CtOutWrapper<block_api::Sha512VarCore, U32>);
    oid: "2.16.840.1.101.3.4.2.6";
    impl: FixedHashTraits;
);
