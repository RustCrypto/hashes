//! An implementation of the [GOST R 34.11-94][1] cryptographic hash algorithm.
//!
//! # Usage
//!
//! ```rust
//! # #[macro_use] extern crate hex_literal;
//! # extern crate gost94;
//! # fn main() {
//! use gost94::{Gost94Test, Digest};
//!
//! // create a Gost94 hasher instance with test S-box
//! let mut hasher = Gost94Test::new();
//!
//! // process input message
//! hasher.input(b"hello world");
//!
//! // acquire hash digest in the form of GenericArray,
//! // which in this case is equivalent to [u8; 32]
//! let result = hasher.result();
//! assert_eq!(result[..], hex!("
//!     1bb6ce69d2e895a78489c87a0712a2f40258d1fae3a4666c23f8f487bef0e22a
//! "));
//! # }
//! ```
//!
//! Also see [RustCrypto/hashes][2] readme.
//!
//! [1]: https://en.wikipedia.org/wiki/GOST_(hash_function)
//! [2]: https://github.com/RustCrypto/hashes
#![no_std]
#![doc(html_logo_url =
    "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
extern crate block_buffer;
#[macro_use] pub extern crate digest;
#[macro_use] extern crate opaque_debug;
#[cfg(feature = "std")]
extern crate std;

#[macro_use]
mod macros;

mod gost94;
mod s2015;
mod cryptopro;
mod test_param;

pub use digest::Digest;

pub use gost94::Gost94;
pub use s2015::Gost94s2015;
pub use cryptopro::Gost94CryptoPro;
pub use test_param::Gost94Test;
