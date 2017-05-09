//! Assembly implementation of [SHA-2][1] compression functions.
//!
//! For full SHA-2 hash functions with this implementation of compression
//! functions use [sha-2](https://crates.io/crates/sha-2) crate with
//! the enabled "asm" feature.
//! 
//! Only x86 and x86-64 architectures are currently supported.
//! 
//! [1]: https://en.wikipedia.org/wiki/SHA-2

#![no_std]
extern crate generic_array;

use generic_array::GenericArray;
use generic_array::typenum::{U64, U128};
use core::mem;

#[link(name="sha256", kind="static")]
extern "C" {
    fn sha256_compress(state: &mut [u32; 8], block: &[u8; 64]);
}

/// Safe wrapper around assembly implementation of SHA256 compression function
#[inline]
pub fn compress256(state: &mut [u32; 8], block: &GenericArray<u8, U64>) {
    unsafe {
        sha256_compress(state, mem::transmute(block));
    }
}

#[link(name="sha512", kind="static")]
extern "C" {
    fn sha512_compress(state: &mut [u64; 8], block: &[u8; 128]);
}

/// Safe wrapper around assembly implementation of SHA512 compression function
#[inline]
pub fn compress512(state: &mut [u64; 8], block: &GenericArray<u8, U128>) {
    unsafe {
        sha512_compress(state, mem::transmute(block));
    }
}
