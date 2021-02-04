//! An implementation of the [BLAKE2][1] hash functions.

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![warn(missing_docs, rust_2018_idioms)]
// TODO(tarcieri): re-enable this and address the issues or disable at module-level
#![allow(clippy::ptr_offset_with_cast)]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "blake2b")]
pub mod blake2b;

#[cfg(feature = "blake2b")]
pub mod blake2bp;

#[cfg(feature = "blake2s")]
pub mod blake2s;

#[cfg(feature = "blake2s")]
pub mod blake2sp;
