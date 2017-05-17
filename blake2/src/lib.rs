//! An implementation of the [BLAKE2][1] hash functions.
//!
//! Based on the [work][2] of Cesar Barros.
//!
//! # Usage
//!
//! An example of using `Blake2b` is:
//!
//! ```rust
//! use blake2::{Blake2b, Digest};
//!
//! // create a Blake2b object
//! let mut hasher = Blake2b::default();
//!
//! // write input message
//! hasher.input(b"hello world");
//!
//! // read hash digest and consume hasher
//! let output = hasher.result();
//! println!("{:x}", output);
//! ```
//!
//! Same for `Blake2s`:
//!
//! ```rust
//! use blake2::{Blake2s, Digest};
//!
//! let mut hasher = Blake2s::default();
//! hasher.input(b"hello world");
//! let output = hasher.result();
//! println!("{:x}", output);
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
extern crate digest;
extern crate crypto_mac;
extern crate generic_array;

mod consts;
mod as_bytes;
mod bytes;

mod simdty;
mod simdint;
mod simdop;
mod simd_opt;
mod simd;


#[macro_use]
mod blake2;

mod blake2b;
mod blake2s;

pub use digest::Digest;
pub use blake2b::Blake2b;
pub use blake2s::Blake2s;
