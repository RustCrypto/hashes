//! Assembly implementation of [MD5][1] compression function.
//!
//! For full MD5 hash function with this implementation of compression function
//! use [md-5](https://crates.io/crates/md-5) crate with
//! the enabled "asm" feature.
//!
//! Only x86 and x86-64 architectures are currently supported.
//!
//! [1]: https://en.wikipedia.org/wiki/MD5

#![no_std]
#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
compile_error!("crate can only be used on x86 and x86-64 architectures");

#[link(name="md5", kind="static")]
extern "C" {
    fn md5_compress(state: &mut [u32; 4], block: &[u8; 64]);
}

/// Safe wrapper around assembly implementation of MD5 compression function
#[inline]
pub fn compress(state: &mut [u32; 4], block: &[u8; 64]) {
    unsafe {
        md5_compress(state, block);
    }
}
