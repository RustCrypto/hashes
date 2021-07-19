//! An implementation of the [SM3] cryptographic hash function defined
//! in OSCCA GM/T 0004-2012.
//!
//! # Usage
//! Hasher functionality is expressed via traits defined in the [`digest`]
//! crate.
//!
//! ```rust
//! use hex_literal::hex;
//! use sm3::{Digest, Sm3};
//!
//! // create a hasher object, to use it do not forget to import `Digest` trait
//! let mut hasher = Sm3::new();
//!
//! // write input message
//! hasher.update(b"hello world");
//!
//! // read hash digest and consume hasher
//! let result = hasher.finalize();
//!
//! assert_eq!(result[..], hex!("
//!     44f0061e69fa6fdfc290c494654a05dc0c053da7e5c52b84ef93a9d67d3fff88
//! ")[..]);
//! ```
//!
//! Also see [RustCrypto/hashes][2] readme.
//!
//! [1]: https://zh.wikipedia.org/zh-hans/SM3
//! [2]: https://github.com/RustCrypto/hashes

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "std")]
extern crate std;

mod consts;
mod sm3;

pub use digest::{self, Digest};

#[cfg(feature = "std")]
use digest::Update;

pub use crate::sm3::Sm3;

opaque_debug::implement!(Sm3);

digest::impl_write!(Sm3);
