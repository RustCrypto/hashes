//! An implementation of the [Shabal][1] cryptographic hash algorithm.
//!
//! There are 5 standard algorithms specified in the Shabal standard:
//!
//! * `Shabal192`, which is the `Shabal` algorithm with the result truncated to 192 bits
//! * `Shabal224`, which is the `Shabal` algorithm with the result truncated to 224 bits
//! * `Shabal256`, which is the `Shabal` algorithm with the result truncated to 256 bits.
//! * `Shabal384`, which is the `Shabal` algorithm with the result truncated to 384 bits.
//! * `Shabal512`, which is the `Shabal` algorithm with the result not truncated.
//!
//! There is a single Shabal algorithm. All variants have different initialisation and apart
//! from Shabal512 all truncate the result.
//!
//! # Usage
//!
//! ```rust
//! use hex_literal::hex;
//! use shabal::{Shabal256, Digest};
//!
//! // create a Shabal256 hasher instance
//! let mut hasher = Shabal256::new();
//!
//! // process input message
//! hasher.update(b"helloworld");
//!
//! // acquire hash digest in the form of GenericArray,
//! // which in this case is equivalent to [u8; 32]
//! let result = hasher.finalize();
//! assert_eq!(result[..], hex!("
//!     d945dee21ffca23ac232763aa9cac6c15805f144db9d6c97395437e01c8595a8
//! ")[..]);
//! ```
//!
//! Also see [RustCrypto/hashes][2] readme.
//!
//! [1]: https://www.cs.rit.edu/~ark/20090927/Round2Candidates/Shabal.pdf
//! [2]: https://github.com/RustCrypto/hashes

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "std")]
extern crate std;

#[rustfmt::skip]
mod consts;
mod core_api;

pub use core_api::ShabalVarCore;
pub use digest::{self, Digest};

use digest::{
    consts::{U24, U28, U32, U48, U64},
    core_api::{CoreWrapper, CtVariableCoreWrapper},
};

/// Shabal192 hasher.
pub type Shabal192 = CoreWrapper<CtVariableCoreWrapper<ShabalVarCore, U24>>;
/// Shabal224 hasher.
pub type Shabal224 = CoreWrapper<CtVariableCoreWrapper<ShabalVarCore, U28>>;
/// Shabal256 hasher.
pub type Shabal256 = CoreWrapper<CtVariableCoreWrapper<ShabalVarCore, U32>>;
/// Shabal384 hasher.
pub type Shabal384 = CoreWrapper<CtVariableCoreWrapper<ShabalVarCore, U48>>;
/// Shabal512 hasher.
pub type Shabal512 = CoreWrapper<CtVariableCoreWrapper<ShabalVarCore, U64>>;
