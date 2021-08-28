//! Pure Rust implementation of the BLAKE2 family of hash functions, including
//! BLAKE2b, BLAKE2bp, BLAKE2s, and BLAKE2sp.
//!
//! # About
//!
//! - 100% stable Rust.
//! - Based on the [`blake2b_simd`] and [`blake2s_simd`] crates.
//! - SIMD implementations based on Samuel Neves' [`blake2-avx2`] which provides high performance
//!   on Intel-compatible CPUs.
//! - Portable, safe implementations for other platforms.
//! - Dynamic CPU feature detection. Binaries include multiple implementations by default and
//!   choose the fastest one the processor supports at runtime.
//! - All the features from the [the BLAKE2 spec], like adjustable length, keying, and associated
//!   data for tree hashing.
//! - `no_std` support. The `std` Cargo feature is on by default, for CPU feature detection and
//!   for implementing `std::io::Write`.
//! - Support for computing multiple BLAKE2b/BLAKE2s hashes in parallel, matching the efficiency of
//!   BLAKE2bp/BLAKE2sp. See the [`blake2b::many`] and [`blake2s::many`] modules.
//!
//! [`blake2b_simd`]: https://crates.io/crates/blake2b_simd
//! [`blake2s_simd`]: https://crates.io/crates/blake2b_simd
//! [`blake2-avx2`]: https://github.com/sneves/blake2-avx2
//! [the BLAKE2 spec]: https://blake2.net/blake2.pdf

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
