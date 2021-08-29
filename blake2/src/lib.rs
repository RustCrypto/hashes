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
//! # Usage
//!
//! [`Blake2b`] can be used in the following way:
//!
//! ```rust
//! use blake2::{Blake2b, Blake2s, Digest};
//! use hex_literal::hex;
//!
//! // create a Blake2b object
//! let mut hasher = Blake2b::new();
//!
//! // write input message
//! hasher.update(b"hello world");
//!
//! // read hash digest and consume hasher
//! let res = hasher.finalize();
//! assert_eq!(res[..], hex!("
//!     021ced8799296ceca557832ab941a50b4a11f83478cf141f51f933f653ab9fbc
//!     c05a037cddbed06e309bf334942c4e58cdf1a46e237911ccd7fcf9787cbc7fd0
//! ")[..]);
//!
//! // same example for `Blake2s`:
//! let mut hasher = Blake2s::new();
//! hasher.update(b"hello world");
//! let res = hasher.finalize();
//! assert_eq!(res[..], hex!("
//!     9aec6806794561107e594b1f6a8a6b0c92a0cba9acf5e5e93cca06f781813b0b
//! ")[..]);
//! ```
//!
//! Also see [RustCrypto/hashes](https://github.com/RustCrypto/hashes) README.
//!
//! ## Variable output size
//!
//! If you need variable sized output you can use [`VarBlake2b`] and [`VarBlake2s`]
//! which support variable output sizes through `VariableOutput` trait. `Update`
//! trait has to be imported as well.
//!
//! ```rust
//! use blake2::VarBlake2b;
//! use blake2::digest::{Update, VariableOutput};
//!
//! let mut hasher = VarBlake2b::new(10).unwrap();
//! hasher.update(b"my_input");
//! hasher.finalize_variable(|res| {
//!     assert_eq!(res, [44, 197, 92, 132, 228, 22, 146, 78, 100, 0])
//! })
//! ```
//!
//! ## Message Authentication Code (MAC)
//!
//! BLAKE2 can be used as a MAC without any additional constructs:
//!
//! ```rust
//! use blake2::Blake2b;
//! use blake2::crypto_mac::{Mac, NewMac};
//!
//! let mut hasher = Blake2b::new_varkey(b"my key").unwrap();
//! hasher.update(b"hello world");
//!
//! // `result` has type `crypto_mac::Output` which is a thin wrapper around
//! // a byte array and provides a constant time equality check
//! let result = hasher.finalize();
//! // To get underlying array use the `into_bytes` method, but be careful,
//! // since incorrect use of the code value may permit timing attacks which
//! // defeat the security provided by the `crypto_mac::Output`
//! let code_bytes = result.into_bytes();
//!
//! // To verify the message it's recommended to use `verify` method
//! let mut hasher = Blake2b::new_varkey(b"my key").unwrap();
//! hasher.update(b"hello world");
//! // `verify` return `Ok(())` if code is correct, `Err(MacError)` otherwise
//! hasher.verify(&code_bytes).unwrap();
//! ```
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

pub use crypto_mac;
pub use digest::{self, Digest};

#[cfg(feature = "blake2b")]
pub use crate::blake2b::{Blake2b, VarBlake2b};

#[cfg(feature = "blake2s")]
pub use crate::blake2s::{Blake2s, VarBlake2s};
