//! Assembly implementation of [SHA-1][1] compression function.
//!
//! For full SHA-1 hash function with this implementation of compression function
//! use [sha-1](https://crates.io/crates/sha-1) crate with
//! the enabled "asm" feature.
//!
//! Only x86 and x86-64 architectures are currently supported.
//!
//! [1]: https://en.wikipedia.org/wiki/SHA-1

#![no_std]
#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
compile_error!("crate can only be used on x86 and x86-64 architectures");

#[link(name="sha1", kind="static")]
extern "C" {
    fn sha1_compress(state: &mut [u32; 5], block: &[u8; 64]);
}

/// Safe wrapper around assembly implementation of SHA-1 compression function
#[inline]
pub fn compress(state: &mut [u32; 5], block: &[u8; 64]) {
    unsafe { sha1_compress(state, block); }
}
