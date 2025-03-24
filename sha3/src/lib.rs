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
    HashMarker, Output,
    array::typenum::Unsigned,
    block_buffer::Eager,
    consts::{U28, U32, U48, U64, U72, U104, U136, U144, U168, U200},
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper,
        ExtendableOutputCore, FixedOutputCore, OutputSizeUser, Reset, UpdateCore, XofReaderCore,
        XofReaderCoreWrapper,
    },
    crypto_common::hazmat::{DeserializeStateError, SerializableState, SerializedState},
};

#[cfg(feature = "oid")]
use digest::const_oid::{AssociatedOid, ObjectIdentifier};
#[cfg(feature = "zeroize")]
use digest::zeroize::{Zeroize, ZeroizeOnDrop};

#[macro_use]
mod macros;
mod state;

use crate::state::Sha3State;

// Paddings
const KECCAK: u8 = 0x01;
const SHA3: u8 = 0x06;
const SHAKE: u8 = 0x1f;
const CSHAKE: u8 = 0x4;

// Round counts
const TURBO_SHAKE_ROUND_COUNT: usize = 12;

impl_sha3!(Keccak224Core, Keccak224, U28, U144, KECCAK, "Keccak-224");
impl_sha3!(Keccak256Core, Keccak256, U32, U136, KECCAK, "Keccak-256");
impl_sha3!(Keccak384Core, Keccak384, U48, U104, KECCAK, "Keccak-384");
impl_sha3!(Keccak512Core, Keccak512, U64, U72, KECCAK, "Keccak-512");

impl_sha3!(
    Keccak256FullCore,
    Keccak256Full,
    U200,
    U136,
    KECCAK,
    "SHA-3 CryptoNight variant",
);

impl_sha3!(
    Sha3_224Core,
    Sha3_224,
    U28,
    U144,
    SHA3,
    "SHA-3-224",
    "2.16.840.1.101.3.4.2.7",
);
impl_sha3!(
    Sha3_256Core,
    Sha3_256,
    U32,
    U136,
    SHA3,
    "SHA-3-256",
    "2.16.840.1.101.3.4.2.8",
);
impl_sha3!(
    Sha3_384Core,
    Sha3_384,
    U48,
    U104,
    SHA3,
    "SHA-3-384",
    "2.16.840.1.101.3.4.2.9",
);
impl_sha3!(
    Sha3_512Core,
    Sha3_512,
    U64,
    U72,
    SHA3,
    "SHA-3-512",
    "2.16.840.1.101.3.4.2.10",
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
