#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]
#![warn(unreachable_pub)]

pub use digest::{self, CollisionResistance, CustomizedInit, Digest};

/// Block-level types
pub mod block_api;
mod cshake;
mod turbo_shake;

pub use cshake::{CShake128, CShake128Reader, CShake256, CShake256Reader};
pub use turbo_shake::{TurboShake128, TurboShake128Reader, TurboShake256, TurboShake256Reader};

use block_api::{Sha3HasherCore, Sha3ReaderCore};
use digest::consts::{U0, U16, U28, U32, U48, U64, U72, U104, U136, U144, U168, U200};

// Paddings
const KECCAK_PAD: u8 = 0x01;
const SHA3_PAD: u8 = 0x06;
const SHAKE_PAD: u8 = 0x1f;
const CSHAKE_PAD: u8 = 0x04;

const PLEN: usize = 25;
const DEFAULT_ROUND_COUNT: usize = 24;

digest::buffer_fixed!(
    /// SHA-3-224 hasher.
    pub struct Sha3_224(Sha3HasherCore<U144, U28, SHA3_PAD>);
    oid: "2.16.840.1.101.3.4.2.7";
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// SHA-3-256 hasher.
    pub struct Sha3_256(Sha3HasherCore<U136, U32, SHA3_PAD>);
    oid: "2.16.840.1.101.3.4.2.8";
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// SHA-3-384 hasher.
    pub struct Sha3_384(Sha3HasherCore<U104, U48, SHA3_PAD>);
    oid: "2.16.840.1.101.3.4.2.9";
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// SHA-3-512 hasher.
    pub struct Sha3_512(Sha3HasherCore<U72, U64, SHA3_PAD>);
    oid: "2.16.840.1.101.3.4.2.10";
    impl: FixedHashTraits;
);
digest::buffer_xof!(
    /// SHAKE128 hasher.
    pub struct Shake128(Sha3HasherCore<U168, U0, SHAKE_PAD>);
    oid: "2.16.840.1.101.3.4.2.11";
    impl: XofHasherTraits;
    /// SHAKE128 XOF reader.
    pub struct Shake128Reader(Sha3ReaderCore<U168>);
    impl: XofReaderTraits;
);
digest::buffer_xof!(
    /// SHAKE256 hasher.
    pub struct Shake256(Sha3HasherCore<U136, U0, SHAKE_PAD>);
    oid: "2.16.840.1.101.3.4.2.12";
    impl: XofHasherTraits;
    /// SHAKE256 XOF reader.
    pub struct Shake256Reader(Sha3ReaderCore<U136>);
    impl: XofReaderTraits;
);

digest::buffer_fixed!(
    /// SHA-3 CryptoNight variant.
    pub struct Keccak256Full(Sha3HasherCore<U136, U200, KECCAK_PAD>);
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// Keccak-224 hasher.
    pub struct Keccak224(Sha3HasherCore<U144, U28, KECCAK_PAD>);
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// Keccak-256 hasher.
    pub struct Keccak256(Sha3HasherCore<U136, U32, KECCAK_PAD>);
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// Keccak-384 hasher.
    pub struct Keccak384(Sha3HasherCore<U104, U48, KECCAK_PAD>);
    impl: FixedHashTraits;
);
digest::buffer_fixed!(
    /// Keccak-512 hasher.
    pub struct Keccak512(Sha3HasherCore<U72, U64, KECCAK_PAD>);
    impl: FixedHashTraits;
);

impl CollisionResistance for Shake128 {
    // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf#page=31
    type CollisionResistance = U16;
}

impl CollisionResistance for Shake256 {
    // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf#page=31
    type CollisionResistance = U32;
}
