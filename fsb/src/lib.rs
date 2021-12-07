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
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_root_url = "https://docs.rs/fsb/0.1.0"
)]
#![warn(missing_docs, rust_2018_idioms)]
#![allow(non_snake_case)]

#[macro_use]
mod macros;

use core::fmt;
pub use digest::{self, Digest};

// Double check this contains all values in the reference implementation
static PI: &[u8; 272384] = include_bytes!("pi.bin");

use digest::{
    block_buffer::Eager,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore,
        OutputSizeUser, Reset, UpdateCore,
    },
    generic_array::{typenum::Unsigned, GenericArray},
    HashMarker, Output,
};

// FSB-160
fsb_impl!(
    Fsb160,
    Fsb160Core,
    160,
    U60,
    U20,
    5 << 18,
    80,
    640,
    653,
    1120,
    "FSB-160 hasher state",
    "Core FSB-160 hasher state",
);

// FSB-224
fsb_impl!(
    Fsb224,
    Fsb224Core,
    224,
    U84,
    U28,
    7 << 18,
    112,
    896,
    907,
    1568,
    "FSB-224 hasher state",
    "Core FSB-224 hasher state",
);

// FSB-256
fsb_impl!(
    Fsb256,
    Fsb256Core,
    256,
    U96,
    U32,
    1 << 21,
    128,
    1024,
    1061,
    1792,
    "FSB-256 hasher state",
    "Core FSB-256 hasher state",
);

// FSB-384
fsb_impl!(
    Fsb384,
    Fsb384Core,
    384,
    U115,
    U48,
    23 << 16,
    184,
    1472,
    1483,
    2392,
    "FSB-384 hasher state",
    "Core FSB-384 hasher state",
);

// FSB-512
fsb_impl!(
    Fsb512,
    Fsb512Core,
    512,
    U155,
    U64,
    31 << 16,
    248,
    1984,
    1987,
    3224,
    "FSB-512 hasher state",
    "Core FSB-512 hasher state",
);
