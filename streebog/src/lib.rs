//! An implementation of the [Streebog] cryptographic hash function defined
//! in GOST R 34.11-2012.
//!
//! # Usage
//! ```rust
//! use streebog::{Digest, Streebog256, Streebog512};
//! use hex_literal::hex;
//!
//! // create Streebog256 hasher state
//! let mut hasher = Streebog256::new();
//! // write input message
//! hasher.update("The quick brown fox jumps over the lazy dog");
//! // read hash digest (it will consume hasher)
//! let result = hasher.finalize();
//!
//! assert_eq!(result[..], hex!("
//!     3e7dea7f2384b6c5a3d0e24aaa29c05e89ddd762145030ec22c71a6db8b2c1f4
//! ")[..]);
//!
//! // same for Streebog512
//! let mut hasher = Streebog512::new();
//! hasher.update("The quick brown fox jumps over the lazy dog.");
//! let result = hasher.finalize();
//!
//! assert_eq!(result[..], hex!("
//!     fe0c42f267d921f940faa72bd9fcf84f9f1bd7e9d055e9816e4c2ace1ec83be8
//!     2d2957cd59b86e123d8f5adee80b3ca08a017599a9fc1a14d940cf87c77df070
//! ")[..]);
//! ```
//!
//! See [RustCrypto/hashes][1] readme for additional examples.
//!
//! [Streebog]: https://en.wikipedia.org/wiki/Streebog
//! [1]: https://github.com/RustCrypto/hashes/blob/master/README.md#usage

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "std")]
extern crate std;

mod consts;
mod streebog;
mod streebog256;
mod streebog512;
mod table;

pub use digest::{self, Digest};
pub use streebog256::{Streebog256, Streebog256Core};
pub use streebog512::{Streebog512, Streebog512Core};
