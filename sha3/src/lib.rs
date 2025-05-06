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

mod block_api;
mod cshake;
mod turbo_shake;
mod xof_reader;

pub use block_api::Sha3HasherCore;
pub use cshake::{
    CShake128, CShake128Core, CShake128Reader, CShake256, CShake256Core, CShake256Reader,
};
pub use turbo_shake::{TurboShake128, TurboShake128Reader, TurboShake256, TurboShake256Reader};
pub use xof_reader::Sha3ReaderCore;

use digest::consts::{U0, U28, U32, U48, U64, U72, U104, U136, U144, U168, U200};

// Paddings
const KECCAK_PAD: u8 = 0x01;
const SHA3_PAD: u8 = 0x06;
const SHAKE_PAD: u8 = 0x1f;
const CSHAKE_PAD: u8 = 0x04;

const PLEN: usize = 25;
const DEFAULT_ROUND_COUNT: usize = 24;

digest::newtype_fixed_hash!(
    /// SHA-3-224 hasher.
    pub struct Sha3_224(Sha3HasherCore<U144, U28, SHA3_PAD>);
    oid: "2.16.840.1.101.3.4.2.7"
);
digest::newtype_fixed_hash!(
    /// SHA-3-256 hasher.
    pub struct Sha3_256(Sha3HasherCore<U136, U32, SHA3_PAD>);
    oid: "2.16.840.1.101.3.4.2.8"
);
digest::newtype_fixed_hash!(
    /// SHA-3-384 hasher.
    pub struct Sha3_384(Sha3HasherCore<U104, U48, SHA3_PAD>);
    oid: "2.16.840.1.101.3.4.2.9"
);
digest::newtype_fixed_hash!(
    /// SHA-3-512 hasher.
    pub struct Sha3_512(Sha3HasherCore<U72, U64, SHA3_PAD>);
    oid: "2.16.840.1.101.3.4.2.10"
);
digest::newtype_xof_hash!(
    /// SHAKE128 hasher.
    pub struct Shake128(Sha3HasherCore<U168, U0, SHAKE_PAD>);
    /// SHAKE128 XOF reader.
    pub struct Shake128Reader(Sha3ReaderCore<U168>);
    oid: "2.16.840.1.101.3.4.2.11"
);
digest::newtype_xof_hash!(
    /// SHAKE256 hasher.
    pub struct Shake256(Sha3HasherCore<U136, U0, SHAKE_PAD>);
    /// SHAKE256 XOF reader.
    pub struct Shake256Reader(Sha3ReaderCore<U136>);
    oid: "2.16.840.1.101.3.4.2.12"
);

digest::newtype_fixed_hash!(
    /// SHA-3 CryptoNight variant.
    pub struct Keccak256Full(Sha3HasherCore<U136, U200, KECCAK_PAD>);
);
digest::newtype_fixed_hash!(
    /// Keccak-224 hasher.
    pub struct Keccak224(Sha3HasherCore<U144, U28, KECCAK_PAD>);
);
digest::newtype_fixed_hash!(
    /// Keccak-256 hasher.
    pub struct Keccak256(Sha3HasherCore<U136, U32, KECCAK_PAD>);
);
digest::newtype_fixed_hash!(
    /// Keccak-384 hasher.
    pub struct Keccak384(Sha3HasherCore<U104, U48, KECCAK_PAD>);
);
digest::newtype_fixed_hash!(
    /// Keccak-512 hasher.
    pub struct Keccak512(Sha3HasherCore<U72, U64, KECCAK_PAD>);
);

fn xor_block(state: &mut [u64; PLEN], block: &[u8]) {
    assert!(block.len() < 8 * PLEN);

    let mut chunks = block.chunks_exact(8);
    for (s, chunk) in state.iter_mut().zip(&mut chunks) {
        *s ^= u64::from_le_bytes(chunk.try_into().unwrap());
    }

    let rem = chunks.remainder();
    if !rem.is_empty() {
        let mut buf = [0u8; 8];
        buf[..rem.len()].copy_from_slice(rem);
        let n = block.len() / 8;
        state[n] ^= u64::from_le_bytes(buf);
    }
}
