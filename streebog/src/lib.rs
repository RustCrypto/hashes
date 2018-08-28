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
//! # #[macro_use] extern crate hex_literal;
//! # extern crate streebog;
//! # fn main() {
//! use streebog::{Digest, Streebog256, Streebog512};
//!
//! // create a hasher object, to use it do not forget to import `Digest` trait
//! let mut hasher = Streebog256::new();
//! // write input message
//! hasher.input(b"my message");
//! // read hash digest (it will consume hasher)
//! let result = hasher.result();
//!
//! assert_eq!(result[..], hex!("
//!     a47752ba9491bd1d52dd5dcea6d8c08e9b1ee70c42a2fc3e0d1a2852468c1329
//! ")[..]);
//!
//! // same for Streebog512
//! let mut hasher = Streebog512::new();
//! hasher.input(b"my message");
//! let result = hasher.result();
//!
//! assert_eq!(result[..], hex!("
//!     c40cc26c37a683c74459820d884b766d9c96697a8d168c0272db8f4ecca2935b
//!     4164ede98fc9c8d2bafb1249b238676c81f5b97f98c393b99fdf2dc961391484
//! ")[..]);
//! # }
//! ```
//!
//! Also see [RustCrypto/hashes][2] readme.
//!
//! [1]: https://en.wikipedia.org/wiki/Streebog
//! [2]: https://github.com/RustCrypto/hashes
#![no_std]
#![doc(html_logo_url =
    "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
extern crate block_buffer;
extern crate byte_tools;
#[macro_use] pub extern crate digest;
#[macro_use] extern crate opaque_debug;
#[cfg(feature = "std")]
extern crate std;

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
