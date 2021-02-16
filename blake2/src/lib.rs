//! An implementation of the [BLAKE2][1] hash functions.
//!
//! # Usage
//!
//! `Blake2b` can be used in the following way:
//!
//! ```rust
//! use blake2::{Blake2b512, Blake2s256, Digest};
//! use hex_literal::hex;
//!
//! // create a Blake2b512 object
//! let mut hasher = Blake2b512::new();
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
//! // same example for Blake2s256:
//! let mut hasher = Blake2s256::new();
//! hasher.update(b"hello world");
//! let res = hasher.finalize();
//! assert_eq!(res[..], hex!("
//!     9aec6806794561107e594b1f6a8a6b0c92a0cba9acf5e5e93cca06f781813b0b
//! ")[..]);
//! ```
//!
//! Also see [RustCrypto/hashes](https://github.com/RustCrypto/hashes) readme.
//!
//! ## Variable output size
//!
//! If you need variable sized output you can use `VarBlake2b` and `VarBlake2s`
//! which support variable output sizes through `VariableOutput` trait. `Update`
//! trait has to be imported as well.
//!
//! ```rust
//! use blake2::Blake2bVar;
//! use blake2::digest::{Update, VariableOutput};
//! use hex_literal::hex;
//!
//! let mut hasher = Blake2bVar::new(10).unwrap();
//! hasher.update(b"my_input");
//! hasher.finalize_variable(|res| {
//!     assert_eq!(res, hex!("2cc55c84e416924e6400"))
//! })
//! ```
//!
//! ## Message Authentication Code (MAC)
//!
//! BLAKE2 can be used as a MAC without any additional constructs:
//!
//! ```rust,ignore
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
//! # Acknowledgment
//! Based on the [blake2-rfc][2] crate.
//!
//! [1]: https://en.wikipedia.org/wiki/BLAKE_(hash_function)#BLAKE2
//! [2]: https://github.com/cesarb/blake2-rfc

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![warn(missing_docs, rust_2018_idioms)]
#![cfg_attr(feature = "simd", feature(platform_intrinsics, repr_simd))]
#![cfg_attr(feature = "simd_asm", feature(asm))]

#[cfg(feature = "std")]
extern crate std;

pub use crypto_mac;
pub use digest::{self, Digest};

use core::{convert::TryInto, ops::Div};
// use crypto_mac::{InvalidKeyLength, Mac, NewMac, FromKey};
use core::fmt;
use digest::{
    block_buffer::LazyBlockBuffer,
    core_api::{
        AlgorithmName, CoreWrapper, CtVariableCoreWrapper, RtVariableCoreWrapper, UpdateCore,
        VariableOutputCore,
    },
    generic_array::{
        typenum::{Unsigned, U128, U32, U4, U64},
        GenericArray,
    },
    InvalidOutputSize,
};

mod as_bytes;
mod consts;

mod simd;

#[macro_use]
mod macros;

// mod blake2b;
// mod blake2s;

use as_bytes::AsBytes;
use consts::{BLAKE2B_IV, BLAKE2S_IV};
use simd::{u32x4, u64x4, Vector4};

blake2_impl!(
    Blake2bVarCore,
    "Blake2b",
    u64,
    u64x4,
    U64,
    U128,
    32,
    24,
    16,
    63,
    BLAKE2B_IV,
    "Blake2b instance with a variable output.",
    "Blake2b instance with a fixed output.",
);

/// BLAKE2b which allows to choose output size at runtime.
pub type Blake2bVar = RtVariableCoreWrapper<Blake2bVarCore>;
/// Core hasher state of BLAKE2b generic over output size.
pub type Blake2bCore<OutSize> = CtVariableCoreWrapper<Blake2bVarCore, OutSize>;
/// BLAKE2b generic over output size.
pub type Blake2b<OutSize> = CoreWrapper<Blake2bCore<OutSize>>;
/// BLAKE2b-512 hasher state.
pub type Blake2b512 = Blake2b<U64>;

blake2_impl!(
    Blake2sVarCore,
    "Blake2s",
    u32,
    u32x4,
    U32,
    U64,
    16,
    12,
    8,
    7,
    BLAKE2S_IV,
    "Blake2s instance with a variable output.",
    "Blake2s instance with a fixed output.",
);

/// BLAKE2s which allows to choose output size at runtime.
pub type Blake2sVar = RtVariableCoreWrapper<Blake2sVarCore>;
/// Core hasher state of BLAKE2s generic over output size.
pub type Blake2sCore<OutSize> = CtVariableCoreWrapper<Blake2sVarCore, OutSize>;
/// BLAKE2s generic over output size.
pub type Blake2s<OutSize> = CoreWrapper<Blake2sCore<OutSize>>;
/// BLAKE2s-256 hasher state.
pub type Blake2s256 = Blake2s<U32>;
