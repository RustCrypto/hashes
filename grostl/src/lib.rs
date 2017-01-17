//! An implementation of the [Grostl][1] cryptographic hash function.
//!
//! [1]: http://www.groestl.info/
//!
//! # Usage
//!
//! Grostl can produce a digest of any size between 1 and 64 bytes inclusive.
//! This crate defines the common digest sizes (`Grostl224`, `Grostl256`,
//! `Grostl384`, and `Grostl512`), but allows you to specify a custom size with
//! the `GrostlSmall` and `GrostlBig` structs. `GrostlSmall` allows you to
//! specify a digest size between 1 and 32 inclusive, and `GrostlBig` allows you
//! to specify a digest size between 33 and 64 inclusive.
//!
//! ```rust
//! use grostl::{Digest, Grostl256};
//!
//! let mut hasher = Grostl256::new();
//! hasher.input(b"my message");
//! let result = hasher.result();
//! ```
//!
//! ```rust,ignore
//! use grostl::{Digest, Grostl256};
//! use typenum::{U8, U52};
//!
//! let mut hasher = GrostlSmall::<U8>::new();
//! hasher.input(b"my message");
//! let result = hasher.result();
//!
//! let mut hasher = GrostlBig::<U52>::new();
//! hasher.input(b"my message");
//! let result = hasher.result();
//!}
//! ```

#![no_std]
extern crate byte_tools;
extern crate digest;
extern crate digest_buffer;
extern crate generic_array;

pub use digest::Digest;
use generic_array::ArrayLength;
use generic_array::typenum::{
    Cmp, Compare, Greater, Less, Same,
    U28, U32, U33, U48, U64, U65, U128,
};

mod grostl;
mod matrix;

pub type GrostlSmall<OutputSize>
    where OutputSize: ArrayLength<u8> + Cmp<U64>,
          Compare<OutputSize, U33>: Same<Less>
    = grostl::Grostl<OutputSize, U64>;

pub type GrostlBig<OutputSize>
    where OutputSize: ArrayLength<u8> + Cmp<U64>,
          Compare<OutputSize, U32>: Same<Greater>,
          Compare<OutputSize, U65>: Same<Less>
    = grostl::Grostl<OutputSize, U128>;

pub type Grostl224 = GrostlSmall<U28>;
pub type Grostl256 = GrostlSmall<U32>;
pub type Grostl384 = GrostlSmall<U48>;
pub type Grostl512 = GrostlSmall<U64>;
