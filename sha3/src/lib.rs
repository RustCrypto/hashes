//! An implementation of the SHA-3 cryptographic hash algorithms.
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
//! use sha3::{Digest, Sha3_256};
//!
//! // create a SHA3-256 object
//! let mut hasher = Sha3_256::default();
//!
//! // write input message
//! hasher.input(b"abc");
//!
//! // read hash digest
//! let out = hasher.result();
//!
//! println!("{:x}", out);
//! ```

#![no_std]
extern crate byte_tools;
#[macro_use]
extern crate digest;
extern crate block_buffer;

pub use digest::Digest;
use block_buffer::{
    BlockBuffer576, BlockBuffer832, BlockBuffer1152, BlockBuffer1088,
    BlockBuffer1344,
};
use digest::generic_array::GenericArray;
use digest::generic_array::typenum::{
    U28, U32, U48, U64, U72, U104, U136, U144, U168, Unsigned,
};

use byte_tools::write_u64v_le;
use core::mem::transmute;

mod keccak;
mod consts;
mod paddings;
#[macro_use]
mod macros;
mod reader;
mod state;

pub use reader::Sha3XofReader;
use consts::PLEN;
use state::Sha3State;

sha3_impl!(Keccak224, U28, U144, BlockBuffer1152, paddings::Keccak);
sha3_impl!(Keccak256, U32, U136, BlockBuffer1088, paddings::Keccak);
sha3_impl!(Keccak384, U48, U104, BlockBuffer832, paddings::Keccak);
sha3_impl!(Keccak512, U64, U72, BlockBuffer576, paddings::Keccak);

sha3_impl!(Sha3_224, U28, U144, BlockBuffer1152, paddings::Sha3);
sha3_impl!(Sha3_256, U32, U136, BlockBuffer1088, paddings::Sha3);
sha3_impl!(Sha3_384, U48, U104, BlockBuffer832, paddings::Sha3);
sha3_impl!(Sha3_512, U64, U72, BlockBuffer576, paddings::Sha3);

shake_impl!(Shake128, U168, BlockBuffer1344, paddings::Shake);
shake_impl!(Shake256, U136, BlockBuffer1088, paddings::Shake);
