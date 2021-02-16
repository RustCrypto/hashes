//! An implementation of the [SHA-3][1] cryptographic hash algorithms.
//!
//! There are 6 standard algorithms specified in the SHA-3 standard:
//!
//! * `SHA3-224`
//! * `SHA3-256`
//! * `SHA3-384`
//! * `SHA3-512`
//! * `SHAKE128`, an extendable output function (XOF)
//! * `SHAKE256`, an extendable output function (XOF)
//! * `Keccak224`, `Keccak256`, `Keccak384`, `Keccak512` (NIST submission
//!    without padding changes)
//!
//! # Examples
//!
//! Output size of SHA3-256 is fixed, so its functionality is usually
//! accessed via the `Digest` trait:
//!
//! ```
//! use hex_literal::hex;
//! use sha3::{Digest, Sha3_256};
//!
//! // create a SHA3-256 object
//! let mut hasher = Sha3_256::new();
//!
//! // write input message
//! hasher.update(b"abc");
//!
//! // read hash digest
//! let result = hasher.finalize();
//!
//! assert_eq!(result[..], hex!("
//!     3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
//! ")[..]);
//! ```
//!
//! SHAKE functions have an extendable output, so finalization method returns
//! XOF reader from which results of arbitrary length can be read. Note that
//! these functions do not implement `Digest`, so lower-level traits have to
//! be imported:
//!
//! ```
//! use sha3::{Shake128, digest::{Update, ExtendableOutput, XofReader}};
//! use hex_literal::hex;
//!
//! let mut hasher = Shake128::default();
//! hasher.update(b"abc");
//! let mut reader = hasher.finalize_xof();
//! let mut res1 = [0u8; 10];
//! reader.read(&mut res1);
//! assert_eq!(res1, hex!("5881092dd818bf5cf8a3"));
//! ```
//!
//! Also see [RustCrypto/hashes][2] readme.
//!
//! [1]: https://en.wikipedia.org/wiki/SHA-3
//! [2]: https://github.com/RustCrypto/hashes

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub use digest::{self, Digest};

use core::fmt;
use digest::{
    block_buffer::BlockBuffer,
    consts::{U104, U136, U144, U168, U200, U28, U32, U48, U64, U72},
    core_api::{
        AlgorithmName, CoreWrapper, ExtendableOutputCore, FixedOutputCore, UpdateCore,
        XofReaderCore, XofReaderCoreWrapper,
    },
    generic_array::GenericArray,
    Reset,
};

mod paddings;
#[macro_use]
mod macros;
mod state;

use crate::state::Sha3State;

sha3_impl!(
    Keccak224Core,
    Keccak224,
    U28,
    U144,
    paddings::Keccak,
    "Keccak-224",
);
sha3_impl!(
    Keccak256Core,
    Keccak256,
    U32,
    U136,
    paddings::Keccak,
    "Keccak-256",
);
sha3_impl!(
    Keccak384Core,
    Keccak384,
    U48,
    U104,
    paddings::Keccak,
    "Keccak-384",
);
sha3_impl!(
    Keccak512Core,
    Keccak512,
    U64,
    U72,
    paddings::Keccak,
    "Keccak-512",
);

sha3_impl!(
    Keccak256FullCore,
    Keccak256Full,
    U200,
    U136,
    paddings::Keccak,
    "SHA-3 CryptoNight variant",
);

sha3_impl!(
    Sha3_224Core,
    Sha3_224,
    U28,
    U144,
    paddings::Sha3,
    "SHA-3-224",
);
sha3_impl!(
    Sha3_256Core,
    Sha3_256,
    U32,
    U136,
    paddings::Sha3,
    "SHA-3-256",
);
sha3_impl!(
    Sha3_384Core,
    Sha3_384,
    U48,
    U104,
    paddings::Sha3,
    "SHA-3-384",
);
sha3_impl!(
    Sha3_512Core,
    Sha3_512,
    U64,
    U72,
    paddings::Sha3,
    "SHA-3-512",
);

shake_impl!(
    Shake128Core,
    Shake128,
    Shake128ReaderCore,
    Shake128Reader,
    U168,
    paddings::Shake,
    "SHAKE128",
);
shake_impl!(
    Shake256Core,
    Shake256,
    Shake256ReaderCore,
    Shake256Reader,
    U136,
    paddings::Shake,
    "SHAKE256",
);
