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
#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
compile_error!("crate can only be used on x86 and x86-64 architectures");

#[link(name="sha256", kind="static")]
extern "C" {
    fn sha256_compress(state: &mut [u32; 8], block: &[u8; 64]);
}

/// Safe wrapper around assembly implementation of SHA256 compression function
#[inline]
pub fn compress256(state: &mut [u32; 8], block: &[u8; 64]) {
    unsafe { sha256_compress(state, block) }
}

#[link(name="sha512", kind="static")]
extern "C" {
    fn sha512_compress(state: &mut [u64; 8], block: &[u8; 128]);
}

/// Safe wrapper around assembly implementation of SHA512 compression function
#[inline]
pub fn compress512(state: &mut [u64; 8], block: &[u8; 128]) {
    unsafe { sha512_compress(state, block) }
}
