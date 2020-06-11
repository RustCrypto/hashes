//! An implementation of the [Streebog][1] cryptographic hash function. It's
//! officially known as GOST R 34.11-2012.
//!
//! This implementation returns digest result using little-endian encoding
//! in the form of array with least significant octets first, thus compared to
//! specifications which uses big-endian result will have "reversed" order of
//! octets.
//!
//! # Usage
//!
//! An example of using `Streebog256` and `Streebog256` is:
//!
//! ```rust
//! use streebog::{Digest, Streebog256, Streebog512};
//! use hex_literal::hex;
//!
//! // create a hasher object, to use it do not forget to import `Digest` trait
//! let mut hasher = Streebog256::new();
//! // write input message
//! hasher.update(b"my message");
//! // read hash digest (it will consume hasher)
//! let result = hasher.finalize();
//!
//! assert_eq!(result[..], hex!("
//!     a47752ba9491bd1d52dd5dcea6d8c08e9b1ee70c42a2fc3e0d1a2852468c1329
//! ")[..]);
//!
//! // same for Streebog512
//! let mut hasher = Streebog512::new();
//! hasher.update(b"my message");
//! let result = hasher.finalize();
//!
//! assert_eq!(result[..], hex!("
//!     c40cc26c37a683c74459820d884b766d9c96697a8d168c0272db8f4ecca2935b
//!     4164ede98fc9c8d2bafb1249b238676c81f5b97f98c393b99fdf2dc961391484
//! ")[..]);
//! ```
//!
//! Also see [RustCrypto/hashes][2] readme.
//!
//! [1]: https://en.wikipedia.org/wiki/Streebog
//! [2]: https://github.com/RustCrypto/hashes

#![no_std]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "std")]
extern crate std;

mod consts;
mod streebog;
mod table;

use digest::consts::{U32, U64};
pub use digest::{self, Digest};

#[cfg(feature = "std")]
use digest::Update;

/// Streebog256
pub type Streebog256 = streebog::Streebog<U32>;

/// Streebog512
pub type Streebog512 = streebog::Streebog<U64>;

opaque_debug::implement!(Streebog512);
opaque_debug::implement!(Streebog256);

digest::impl_write!(Streebog512);
digest::impl_write!(Streebog256);
