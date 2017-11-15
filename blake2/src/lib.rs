//! An implementation of the [BLAKE2][1] hash functions.
//!
//! Based on the [blake2-rfc][2] crate.
//!
//! # Usage
//!
//! `Blake2b` can be used in the following way:
//!
//! ```rust
//! use blake2::{Blake2b, Digest};
//!
//! // create a Blake2b object
//! let mut hasher = Blake2b::new();
//!
//! // write input message
//! hasher.input(b"hello world");
//!
//! // read hash digest and consume hasher
//! let output = hasher.result();
//! println!("{:x}", output);
//! ```
//!
//! Same example for `Blake2s`:
//!
//! ```rust
//! use blake2::{Blake2s, Digest};
//!
//! let mut hasher = Blake2s::new();
//! hasher.input(b"hello world");
//! let output = hasher.result();
//! println!("{:x}", output);
//! ```
//!
//! ## Variable output size
//!
//! Both `Blake2b` and `Blake2s` support variable output sizes through
//! `VariableOutput` trait. `Input` trait has to be imported as well.
//!
//! ```rust
//! use blake2::Blake2b;
//! use blake2::digest::{Input, VariableOutput};
//!
//! let mut hasher = Blake2b::new(10).unwrap();
//! // instead of `input` method here we should use `process`
//! hasher.process(b"my_input");
//! let mut buf = [0u8; 10];
//! hasher.variable_result(&mut buf).unwrap();
//! assert_eq!(buf, [44, 197, 92, 132, 228, 22, 146, 78, 100, 0])
//! ```
//!
//! ## Message Authentication Code (MAC)
//!
//! BLAKE2 can be used as a MAC without any additionall constructs:
//!
//! ```rust
//! use blake2::Blake2b;
//! use blake2::crypto_mac::Mac;
//!
//! let mut hasher = Blake2b::new(b"my key").unwrap();
//! hasher.input(b"hello world");
//!
//! // `result` has type `MacResult` which is a thin wrapper around array of
//! // bytes for providing constant time equality check
//! let result = hasher.result();
//! // To get underlying array use `code` method, but be carefull, since
//! // incorrect use of the code value may permit timing attacks which defeat
//! // the security provided by the `MacResult`
//! let code_bytes = result.code();
//!
//! // To verify the message it's recommended to use `verify` method
//! let mut hasher = Blake2b::new(b"my key").unwrap();
//! hasher.input(b"hello world");
//! // `verify` return `Ok(())` if code is correct, `Err(MacError)` otherwise
//! hasher.verify(&code_bytes).unwrap();
//! ```
//!
//! [1]: https://en.wikipedia.org/wiki/BLAKE_(hash_function)#BLAKE2
//! [2]: https://github.com/cesarb/blake2-rfc
#![no_std]
#![warn(missing_docs)]

#![cfg_attr(feature = "simd", feature(platform_intrinsics, repr_simd))]
#![cfg_attr(feature = "simd_opt", feature(cfg_target_feature))]
#![cfg_attr(feature = "simd_asm", feature(asm))]

extern crate byte_tools;
#[macro_use]
pub extern crate digest;
pub extern crate crypto_mac;

mod consts;
mod as_bytes;

mod simd;


#[macro_use]
mod blake2;

mod blake2b;
mod blake2s;

pub use digest::Digest;
pub use blake2b::Blake2b;
pub use blake2s::Blake2s;
