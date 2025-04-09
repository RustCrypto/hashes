#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub use digest::{self, CustomizedInit, Digest};

use core::fmt;
use digest::{
    HashMarker,
    array::typenum::Unsigned,
    block_buffer::Eager,
    consts::{U28, U32, U48, U64, U72, U104, U136, U144, U168, U200},
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper,
        ExtendableOutputCore, Reset, UpdateCore, XofReaderCore, XofReaderCoreWrapper,
    },
};

#[cfg(feature = "oid")]
use digest::const_oid::{AssociatedOid, ObjectIdentifier};
#[cfg(feature = "zeroize")]
use digest::zeroize::{Zeroize, ZeroizeOnDrop};

#[macro_use]
mod macros;
mod fixed;
mod state;

use crate::state::Sha3State;
pub use fixed::Sha3FixedCore;

// Paddings
const KECCAK: u8 = 0x01;
const SHA3: u8 = 0x06;
const SHAKE: u8 = 0x1f;
const CSHAKE: u8 = 0x4;

// Round counts
const TURBO_SHAKE_ROUND_COUNT: usize = 12;

digest::newtype!(
    /// SHA-3-224 hasher.
    pub struct Sha3_224(digest::core_api::CoreWrapper<Sha3FixedCore<U144, U28, SHA3>>);
    delegate_template: FixedOutputHash
    oid: "2.16.840.1.101.3.4.2.7"
);
digest::newtype!(
    /// SHA-3-256 hasher.
    pub struct Sha3_256(digest::core_api::CoreWrapper<Sha3FixedCore<U136, U32, SHA3>>);
    delegate_template: FixedOutputHash
    oid: "2.16.840.1.101.3.4.2.8"
);
digest::newtype!(
    /// SHA-3-384 hasher.
    pub struct Sha3_384(digest::core_api::CoreWrapper<Sha3FixedCore<U104, U48, SHA3>>);
    delegate_template: FixedOutputHash
    oid: "2.16.840.1.101.3.4.2.9"
);
digest::newtype!(
    /// SHA-3-512 hasher.
    pub struct Sha3_512(digest::core_api::CoreWrapper<Sha3FixedCore<U72, U64, SHA3>>);
    delegate_template: FixedOutputHash
    oid: "2.16.840.1.101.3.4.2.10"
);

digest::newtype!(
    /// SHA-3 CryptoNight variant.
    pub struct Keccak256Full(digest::core_api::CoreWrapper<Sha3FixedCore<U136, U200, KECCAK>>);
    delegate_template: FixedOutputHash
);
digest::newtype!(
    /// Keccak-224 hasher.
    pub struct Keccak224(digest::core_api::CoreWrapper<Sha3FixedCore<U144, U28, KECCAK>>);
    delegate_template: FixedOutputHash
);
digest::newtype!(
    /// Keccak-256 hasher.
    pub struct Keccak256(digest::core_api::CoreWrapper<Sha3FixedCore<U136, U32, KECCAK>>);
    delegate_template: FixedOutputHash
);
digest::newtype!(
    /// Keccak-384 hasher.
    pub struct Keccak384(digest::core_api::CoreWrapper<Sha3FixedCore<U104, U48, KECCAK>>);
    delegate_template: FixedOutputHash
);
digest::newtype!(
    /// Keccak-512 hasher.
    pub struct Keccak512(digest::core_api::CoreWrapper<Sha3FixedCore<U72, U64, KECCAK>>);
    delegate_template: FixedOutputHash
);

impl_shake!(
    Shake128Core,
    Shake128,
    Shake128ReaderCore,
    Shake128Reader,
    U168,
    SHAKE,
    "SHAKE128",
    "2.16.840.1.101.3.4.2.11",
);
impl_shake!(
    Shake256Core,
    Shake256,
    Shake256ReaderCore,
    Shake256Reader,
    U136,
    SHAKE,
    "SHAKE256",
    "2.16.840.1.101.3.4.2.11",
);

impl_turbo_shake!(
    TurboShake128Core,
    TurboShake128,
    TurboShake128ReaderCore,
    TurboShake128Reader,
    U168,
    "TurboSHAKE128",
);
impl_turbo_shake!(
    TurboShake256Core,
    TurboShake256,
    TurboShake256ReaderCore,
    TurboShake256Reader,
    U136,
    "TurboSHAKE256",
);

impl_cshake!(
    CShake128Core,
    CShake128,
    CShake128ReaderCore,
    CShake128Reader,
    U168,
    SHAKE,
    CSHAKE,
    "CSHAKE128",
);
impl_cshake!(
    CShake256Core,
    CShake256,
    CShake256ReaderCore,
    CShake256Reader,
    U136,
    SHAKE,
    CSHAKE,
    "CSHAKE256",
);

#[inline(always)]
pub(crate) fn left_encode(val: u64, b: &mut [u8; 9]) -> &[u8] {
    b[1..].copy_from_slice(&val.to_be_bytes());
    let i = b[1..8].iter().take_while(|&&a| a == 0).count();
    b[i] = (8 - i) as u8;
    &b[i..]
}
