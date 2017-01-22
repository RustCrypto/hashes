//! An implementation of the [Groestl][1] cryptographic hash function.
//!
//! [1]: http://www.groestl.info/
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
//!
//! let mut hasher = Groestl256::new();
//! hasher.input(b"my message");
//! let result = hasher.result();
//! ```
//!
//! ```rust,ignore
//! use groestl::{Digest, GroestlSmall, GroestlBig};
//! use typenum::{U8, U52};
//!
//! let mut hasher = GroestlSmall::<U8>::new();
//! hasher.input(b"my message");
//! let result = hasher.result();
//!
//! let mut hasher = GroestlBig::<U52>::new();
//! hasher.input(b"my message");
//! let result = hasher.result();
//! ```

#![no_std]
extern crate byte_tools;
extern crate digest;
extern crate digest_buffer;
extern crate generic_array;

pub use digest::Digest;
use generic_array::{ArrayLength, GenericArray};
use generic_array::typenum::{
    Cmp, Compare, Greater, Less, Same,
    U0, U28, U32, U33, U48, U64, U65, U128,
};

mod consts;
mod groestl;
mod matrix;

#[derive(Copy, Clone, Default)]
pub struct GroestlSmall<OutputSize>
    where OutputSize: ArrayLength<u8> + Cmp<U0> + Cmp<U33>,
          Compare<OutputSize, U0>: Same<Greater>,
          Compare<OutputSize, U33>: Same<Less>,
{
    groestl: groestl::Groestl<OutputSize, U64>,
}

impl<OutputSize> GroestlSmall<OutputSize>
    where OutputSize: ArrayLength<u8> + Cmp<U0> + Cmp<U33> + Default,
          Compare<OutputSize, U0>: Same<Greater>,
          Compare<OutputSize, U33>: Same<Less>,
{
    pub fn new() -> Self {
        GroestlSmall::default()
    }
}

impl<OutputSize> Digest for GroestlSmall<OutputSize>
    where OutputSize: ArrayLength<u8> + Cmp<U0> + Cmp<U33>,
          Compare<OutputSize, U0>: Same<Greater>,
          Compare<OutputSize, U33>: Same<Less>,
{
    type OutputSize = OutputSize;
    type BlockSize = U64;

    fn input(&mut self, input: &[u8]) {
        self.groestl.process(input);
    }

    fn result(self) -> GenericArray<u8, Self::OutputSize> {
        self.groestl.finalize()
    }
}

#[derive(Copy, Clone, Default)]
pub struct GroestlBig<OutputSize>
    where OutputSize: ArrayLength<u8> + Cmp<U32> + Cmp<U65>,
          Compare<OutputSize, U32>: Same<Greater>,
          Compare<OutputSize, U65>: Same<Less>,
{
    groestl: groestl::Groestl<OutputSize, U128>,
}

impl<OutputSize> GroestlBig<OutputSize>
    where OutputSize: ArrayLength<u8> + Cmp<U32> + Cmp<U65> + Default,
          Compare<OutputSize, U32>: Same<Greater>,
          Compare<OutputSize, U65>: Same<Less>,
{
    pub fn new() -> Self {
        GroestlBig::default()
    }
}

impl<OutputSize> Digest for GroestlBig<OutputSize>
    where OutputSize: ArrayLength<u8> + Cmp<U32> + Cmp<U65>,
          Compare<OutputSize, U32>: Same<Greater>,
          Compare<OutputSize, U65>: Same<Less>,
{
    type OutputSize = OutputSize;
    type BlockSize = U128;

    fn input(&mut self, input: &[u8]) {
        self.groestl.process(input);
    }

    fn result(self) -> GenericArray<u8, Self::OutputSize> {
        self.groestl.finalize()
    }
}

pub type Groestl224 = GroestlSmall<U28>;
pub type Groestl256 = GroestlSmall<U32>;
pub type Groestl384 = GroestlBig<U48>;
pub type Groestl512 = GroestlBig<U64>;
