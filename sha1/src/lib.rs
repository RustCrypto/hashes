//! An implementation of the [SHA-1][1] cryptographic hash algorithm.
//!
//! # Usage
//!
//! ```rust
//! use hex_literal::hex;
//! use sha1::{Sha1, Digest};
//!
//! // create a Sha1 object
//! let mut hasher = Sha1::new();
//!
//! // process input message
//! hasher.update(b"hello world");
//!
//! // acquire hash digest in the form of GenericArray,
//! // which in this case is equivalent to [u8; 20]
//! let result = hasher.finalize();
//! assert_eq!(result[..], hex!("2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"));
//! ```
//!
//! Also see [RustCrypto/hashes][2] readme.
//!
//! [1]: https://en.wikipedia.org/wiki/SHA-1
//! [2]: https://github.com/RustCrypto/hashes

#![no_std]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

// Give relevant error messages if the user tries to enable AArch64 asm on unsupported platforms.
#[cfg(all(
    feature = "asm-aarch64",
    target_arch = "aarch64",
    not(target_os = "linux")
))]
compile_error!("Your OS isn’t yet supported for runtime-checking of AArch64 features.");

#[cfg(all(feature = "asm-aarch64", not(target_arch = "aarch64")))]
compile_error!("Enable the \"asm\" feature instead of \"asm-aarch64\" on non-AArch64 systems.");
#[cfg(all(
    feature = "asm-aarch64",
    target_arch = "aarch64",
    target_feature = "crypto"
))]
compile_error!("Enable the \"asm\" feature instead of \"asm-aarch64\" when building for AArch64 systems with crypto extensions.");

#[cfg(all(
    not(feature = "asm-aarch64"),
    feature = "asm",
    target_arch = "aarch64",
    not(target_feature = "crypto"),
    target_os = "linux"
))]
compile_error!("Enable the \"asm-aarch64\" feature on AArch64 if you want to use asm detected at runtime, or build with the crypto extensions support, for instance with RUSTFLAGS='-C target-cpu=native' on a compatible CPU.");

#[cfg(feature = "asm")]
extern crate sha1_asm;
#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "asm-aarch64")]
mod aarch64;
mod consts;
#[cfg(any(not(feature = "asm"), feature = "asm-aarch64"))]
mod utils;

pub use digest::{self, Digest};

use crate::consts::{H, STATE_LEN};
use block_buffer::BlockBuffer;
use digest::consts::{U20, U64};
use digest::{BlockInput, FixedOutputDirty, Reset, Update};

#[cfg(not(feature = "asm"))]
use crate::utils::compress;

#[cfg(feature = "asm")]
use digest::generic_array::GenericArray;

/// Structure representing the state of a SHA-1 computation
#[derive(Clone)]
pub struct Sha1 {
    h: [u32; STATE_LEN],
    len: u64,
    buffer: BlockBuffer<U64>,
}

impl Default for Sha1 {
    fn default() -> Self {
        Sha1 {
            h: H,
            len: 0u64,
            buffer: Default::default(),
        }
    }
}

impl BlockInput for Sha1 {
    type BlockSize = U64;
}

impl Update for Sha1 {
    fn update(&mut self, input: impl AsRef<[u8]>) {
        let input = input.as_ref();
        // Assumes that `length_bits<<3` will not overflow
        self.len += input.len() as u64;
        let state = &mut self.h;
        self.buffer.input_block(input, |d| compress(state, d));
    }
}

impl FixedOutputDirty for Sha1 {
    type OutputSize = U20;

    fn finalize_into_dirty(&mut self, out: &mut digest::Output<Self>) {
        let s = &mut self.h;
        let l = self.len << 3;
        self.buffer.len64_padding_be(l, |d| compress(s, d));
        for (chunk, v) in out.chunks_exact_mut(4).zip(self.h.iter()) {
            chunk.copy_from_slice(&v.to_be_bytes());
        }
    }
}

impl Reset for Sha1 {
    fn reset(&mut self) {
        self.h = H;
        self.len = 0;
        self.buffer.reset();
    }
}

#[cfg(all(feature = "asm", not(feature = "asm-aarch64")))]
#[inline(always)]
fn compress(state: &mut [u32; 5], block: &GenericArray<u8, U64>) {
    #[allow(unsafe_code)]
    let block: &[u8; 64] = unsafe { core::mem::transmute(block) };
    sha1_asm::compress(state, block);
}

#[cfg(feature = "asm-aarch64")]
#[inline(always)]
fn compress(state: &mut [u32; 5], block: &GenericArray<u8, U64>) {
    // TODO: Replace this platform-specific call with is_aarch64_feature_detected!("sha1") once
    // that macro is stabilised and https://github.com/rust-lang/rfcs/pull/2725 is implemented
    // to let us use it on no_std.
    if aarch64::sha1_supported() {
        #[allow(unsafe_code)]
        let block: &[u8; 64] = unsafe { core::mem::transmute(block) };
        sha1_asm::compress(state, block);
    } else {
        utils::compress(state, block);
    }
}

opaque_debug::implement!(Sha1);
digest::impl_write!(Sha1);
