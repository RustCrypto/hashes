//! Assembly implementation of [Whirlpool][1] compression function.
//!
//! For full Whirlpool hash function with this implementation of compression
//! function use [whirlpool](https://crates.io/crates/whirlpool) crate with
//! the enabled "asm" feature.
//! 
//! Only x86 and x86-64 architectures are currently supported.
//! 
//! [1]: https://en.wikipedia.org/wiki/Whirlpool_(cryptography)

#![no_std]
extern crate generic_array;

use generic_array::GenericArray;
use generic_array::typenum::U64;
use core::mem;

type Block = GenericArray<u8, U64>;

#[link(name="whirlpool", kind="static")]
extern "C" {
    fn whirlpool_compress(state: &mut [u8; 64], block: &[u8; 64]);
}

/// Safe wrapper around assembly implementation of Whirlpool compression function
#[inline]
pub fn compress(state: &mut Block, block: &Block) {
    unsafe {
        whirlpool_compress(mem::transmute(state), mem::transmute(block));
    }
}
