//! An implementation of the [GOST R 34.11-94][1] cryptographic hash algorithm.
//!
//! # Usage
//! ```rust
//! use gost94::{Gost94CryptoPro, Digest};
//! use hex_literal::hex;
//!
//! // create Gost94 hasher instance with CryptoPro params
//! let mut hasher = Gost94CryptoPro::new();
//!
//! // process input message
//! hasher.update("The quick brown fox jumps over the lazy dog");
//!
//! // acquire hash digest in the form of GenericArray,
//! // which in this case is equivalent to [u8; 32]
//! let result = hasher.finalize();
//! assert_eq!(result[..], hex!("
//!     9004294a361a508c586fe53d1f1b02746765e71b765472786e4770d565830a76
//! "));
//! ```
//!
//! Also see [RustCrypto/hashes][2] readme.
//!
//! # Associated OIDs.
//! There can be a confusion regarding OIDs associated with declared types. According to the
//! [RFC 4357][3], the OIDs 1.2.643.2.2.30.1 and 1.2.643.2.2.30.0 are used to identify the hash
//! function parameter sets (CryptoPro vs Test ones). According to [RFC 4490][4] the OID
//! 1.2.643.2.2.9 identifies the GOST 34.311-95 (former GOST R 34.11-94) function, but then it
//! continues that this function MUST be used only with the CryptoPro parameter set.
//!
//! [1]: https://en.wikipedia.org/wiki/GOST_(hash_function)
//! [2]: https://github.com/RustCrypto/hashes
//! [3]: https://www.rfc-editor.org/rfc/rfc4357
//! [4]: https://www.rfc-editor.org/rfc/rfc4490

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![warn(missing_docs, rust_2018_idioms)]
#![forbid(unsafe_code)]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "oid")]
use digest::const_oid::{AssociatedOid, ObjectIdentifier};
use digest::core_api::CoreWrapper;

mod gost94_core;
/// GOST94 parameters.
pub mod params;

pub use digest::{self, Digest};

pub use gost94_core::Gost94Core;

#[cfg(feature = "oid")]
impl AssociatedOid for Gost94Core<params::CryptoProParam> {
    /// Per RFC 4490
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.643.2.2.9");
}

#[cfg(feature = "oid")]
impl AssociatedOid for Gost94Core<params::GOST28147UAParam> {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.804.2.1.1.1.1.2.1");
}

/// GOST94 hash function with CryptoPro parameters.
pub type Gost94CryptoPro = CoreWrapper<Gost94Core<params::CryptoProParam>>;
/// GOST94 hash function with S-box defined in GOST R 34.12-2015.
pub type Gost94s2015 = CoreWrapper<Gost94Core<params::S2015Param>>;
/// GOST94 hash function with test parameters.
pub type Gost94Test = CoreWrapper<Gost94Core<params::TestParam>>;
/// GOST94 hash function with UAPKI GOST 34.311-95 parameters
/// (1.2.804.2.1.1.1.1.2.1 OID).
pub type Gost94UA = CoreWrapper<Gost94Core<params::GOST28147UAParam>>;
