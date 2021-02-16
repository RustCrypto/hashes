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
//! [1]: https://en.wikipedia.org/wiki/GOST_(hash_function)
//! [2]: https://github.com/RustCrypto/hashes

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "std")]
extern crate std;

use digest::core_api::CoreWrapper;

mod gost94_core;
/// GOST94 parameters.
pub mod params;

pub use digest::{self, Digest};

pub use gost94_core::Gost94Core;

/// GOST94 hash function with CryptoPro parameters.
pub type Gost94CryptoPro = CoreWrapper<Gost94Core<params::CryptoProParam>>;
/// GOST94 hash function with S-box defined in GOST R 34.12-2015.
pub type Gost94s2015 = CoreWrapper<Gost94Core<params::S2015Param>>;
/// GOST94 hash function with test parameters.
pub type Gost94Test = CoreWrapper<Gost94Core<params::TestParam>>;
