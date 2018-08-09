//! An implementation of the [Streebog][1] cryptographic hash function. It's
//! officially known as GOST R 34.11-2012.
//!
//! [1]: https://en.wikipedia.org/wiki/Streebog
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
//!
//! // create a hasher object, to use it do not forget to import `Digest` trait
//! let mut hasher = Streebog256::default();
//! // write input message
//! hasher.input(b"my message");
//! // read hash digest (it will consume hasher)
//! let result = hasher.result();
//!
//! // same for Streebog512
//! let mut hasher = Streebog512::default();
//! hasher.input(b"my message");
//! let result = hasher.result();
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
extern crate block_buffer;
extern crate byte_tools;
#[macro_use] extern crate digest;
#[macro_use] extern crate opaque_debug;

pub use digest::Digest;
use digest::generic_array::typenum::{U32, U64};
#[cfg(feature = "std")]
use digest::Input;

mod consts;
mod table;
mod streebog;

pub type Streebog256 = streebog::Streebog<U32>;
pub type Streebog512 = streebog::Streebog<U64>;

impl_opaque_debug!(Streebog512);
impl_opaque_debug!(Streebog256);

impl_write!(Streebog512);
impl_write!(Streebog256);
