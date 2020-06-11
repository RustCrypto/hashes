//! An implementation of the [Grøstl][1] cryptographic hash function.
//!
//! # Usage
//!
//! Groestl can produce a digest of any size between 1 and 64 bytes inclusive.
//! This crate defines the common digest sizes (`Groestl224`, `Groestl256`,
//! `Groestl384`, and `Groestl512`), but allows you to specify a custom size
//! with the `GroestlSmall` and `GroestlBig` structs. `GroestlSmall` allows you
//! to specify a digest size between 1 and 32 inclusive, and `GroestlBig` allows
//! you to specify a digest size between 33 and 64 inclusive.
//!
//! ```rust
//! use groestl::{Digest, Groestl256};
//! use hex_literal::hex;
//!
//! // create a Groestl-256 hasher instance
//! let mut hasher = Groestl256::default();
//!
//! // process input message
//! hasher.update(b"my message");
//!
//! // acquire hash digest in the form of GenericArray,
//! // which in this case is equivalent to [u8; 32]
//! let result = hasher.finalize();
//! assert_eq!(result[..], hex!("
//!     dc0283ca481efa76b7c19dd5a0b763dff0e867451bd9488a9c59f6c8b8047a86
//! "));
//! ```
//!
//! Also see [RustCrypto/hashes][2] readme.
//!
//! [1]: https://en.wikipedia.org/wiki/Grøstl
//! [2]: https://github.com/RustCrypto/hashes

#![no_std]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![deny(unsafe_code)]
#![warn(rust_2018_idioms)]

#[cfg(feature = "std")]
extern crate std;

pub use digest::{self, Digest};

mod consts;
mod groestl;
mod matrix;
mod state;
#[macro_use]
mod macros;

use crate::groestl::Groestl;
use digest::consts::{U128, U28, U32, U48, U64};
use digest::generic_array::typenum::Unsigned;
use digest::{BlockInput, FixedOutputDirty, InvalidOutputSize, Reset, Update, VariableOutputDirty};

impl_groestl!(Groestl512, U64, U128);
impl_groestl!(Groestl384, U48, U128);
impl_groestl!(Groestl256, U32, U64);
impl_groestl!(Groestl224, U28, U64);

impl_variable_groestl!(GroestlBig, U128, 32, 64);
impl_variable_groestl!(GroestlSmall, U64, 0, 32);
