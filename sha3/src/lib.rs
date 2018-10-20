//! An implementation of the [SHA-3][1] cryptographic hash algorithms.
//!
//! There are 6 standard algorithms specified in the SHA-3 standard:
//!
//! * `SHA3-224`
//! * `SHA3-256`
//! * `SHA3-384`
//! * `SHA3-512`
//! * `SHAKE128`, an extendable output function (XOF)
//! * `SHAKE256`, an extendable output function (XOF)
//! * `Keccak224`, `Keccak256`, `Keccak384`, `Keccak512` (NIST submission
//!    without padding changes)
//!
//! # Usage
//!
//! An example of using `SHA3-256` is:
//!
//! ```rust
//! # #[macro_use] extern crate hex_literal;
//! # extern crate sha3;
//! # fn main() {
//! use sha3::{Digest, Sha3_256};
//!
//! // create a SHA3-256 object
//! let mut hasher = Sha3_256::new();
//!
//! // write input message
//! hasher.input(b"abc");
//!
//! // read hash digest
//! let result = hasher.result();
//!
//! assert_eq!(result[..], hex!("
//!     3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
//! ")[..]);
//! # }
//! ```
//!
//! Also see [RustCrypto/hashes][2] readme.
//!
//! [1]: https://en.wikipedia.org/wiki/SHA-3
//! [2]: https://github.com/RustCrypto/hashes
#![no_std]
#![doc(html_logo_url =
    "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
extern crate keccak;
extern crate block_buffer;
extern crate byte_tools;
#[macro_use] extern crate opaque_debug;
#[macro_use] pub extern crate digest;
#[cfg(feature = "std")]
extern crate std;

pub use digest::Digest;
use digest::{Input, BlockInput, FixedOutput, ExtendableOutput, Reset};
use block_buffer::BlockBuffer;
use digest::generic_array::GenericArray;
use digest::generic_array::typenum::{
    U28, U32, U48, U64, U72, U104, U136, U144, U168, U200, Unsigned,
};

mod paddings;
#[macro_use]
mod macros;
mod reader;
mod state;

pub use reader::Sha3XofReader;
use state::Sha3State;

sha3_impl!(Keccak224, U28, U144, paddings::Keccak);
sha3_impl!(Keccak256, U32, U136, paddings::Keccak);
sha3_impl!(Keccak384, U48, U104, paddings::Keccak);
sha3_impl!(Keccak512, U64, U72, paddings::Keccak);

sha3_impl!(Keccak256Full, U200, U136, paddings::Keccak);

sha3_impl!(Sha3_224, U28, U144, paddings::Sha3);
sha3_impl!(Sha3_256, U32, U136, paddings::Sha3);
sha3_impl!(Sha3_384, U48, U104, paddings::Sha3);
sha3_impl!(Sha3_512, U64, U72, paddings::Sha3);

shake_impl!(Shake128, U168, paddings::Shake);
shake_impl!(Shake256, U136, paddings::Shake);
