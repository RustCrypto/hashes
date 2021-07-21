//! An implementation of the [FSB][1] cryptographic hash algorithms.
//! The FSB hash function was one of the submissions to SHA-3,
//! the cryptographic hash algorithm competition organized by the NIST.
//!
//! There are 5 standard versions of the FSB hash function:
//!
//! * `FSB-160`
//! * `FSB-224`
//! * `FSB-256`
//! * `FSB-384`
//! * `FSB-512`
//!
//! # Examples
//!
//! Output size of FSB-256 is fixed, so its functionality is usually
//! accessed via the `Digest` trait:
//!
//! ```
//! use hex_literal::hex;
//! use fsb::{Digest, Fsb256};
//!
//! // create a FSB-256 object
//! let mut hasher = Fsb256::new();
//!
//! // write input message
//! hasher.update(b"hello");
//!
//! // read hash digest
//! let result = hasher.finalize();
//!
//! assert_eq!(result[..], hex!("
//!     0f036dc3761aed2cba9de586a85976eedde6fa8f115c0190763decc02f28edbc
//! ")[..]);
//! ```
//! Also see [RustCrypto/hashes][2] readme.
//!
//! [1]: https://www.paris.inria.fr/secret/CBCrypto/index.php?pg=fsb
//! [2]: https://github.com/RustCrypto/hashes

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
#![allow(non_snake_case)]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::vec;

#[macro_use]
mod macros;

pub use digest::{self, Digest};
use whirlpool::Whirlpool;

use core::convert::TryInto;

// Double check this contains all values in the reference implementation
static PI: &[u8; 272384] = include_bytes!("pi.bin");

use block_buffer::BlockBuffer;
use digest::generic_array::GenericArray;
use digest::{BlockInput, FixedOutputDirty, Reset, Update};

// FSB-160
fsb_impl!(
    Fsb160,
    160,
    U60,
    U20,
    5 << 18,
    80,
    640,
    653,
    1120,
    "FSB-160 hash function."
);

// FSB-224
fsb_impl!(
    Fsb224,
    224,
    U84,
    U28,
    7 << 18,
    112,
    896,
    907,
    1568,
    "FSB-224 hash function."
);

// FSB-256
fsb_impl!(
    Fsb256,
    256,
    U96,
    U32,
    1 << 21,
    128,
    1024,
    1061,
    1792,
    "FSB-256 hash function."
);

// FSB-384
fsb_impl!(
    Fsb384,
    384,
    U115,
    U48,
    23 << 16,
    184,
    1472,
    1483,
    2392,
    "FSB-384 hash function."
);

// FSB-512
fsb_impl!(
    Fsb512,
    512,
    U155,
    U64,
    31 << 16,
    248,
    1984,
    1987,
    3224,
    "FSB-512 hash function."
);
