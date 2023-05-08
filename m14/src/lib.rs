//! Rust implementation of the MarsupilamiFourteen cryptographic hash algorithm.
//! MarsupilamiFourteen is a variant of KangarooTwelve aiming for 256-bit security
//! strength (compared to 128-bit security strength of KangarooTwelve).
//! The implementation is based on the reference implementation:
//!
//! <https://datatracker.ietf.org/doc/draft-irtf-cfrg-kangarootwelve/>

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub use digest;

use core::fmt;
use digest::block_buffer::Eager;
use digest::consts::{U128, U136};
use digest::core_api::{
    AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper, ExtendableOutputCore,
    UpdateCore, XofReaderCore, XofReaderCoreWrapper,
};
use digest::{ExtendableOutputReset, HashMarker, Reset, Update, XofReader};

use k12::impl_tree_hash;

use sha3::{TurboShake256, TurboShake256Core, TurboShake256ReaderCore};

const M14_ROUND_COUNT: usize = 14;
const M14_CHAINING_VALUE_SIZE: usize = 64;

impl_tree_hash!(
    MarsupilamiFourteenCore,
    MarsupilamiFourteen,
    MarsupilamiFourteenReaderCore,
    MarsupilamiFourteenReader,
    TurboShake256Core,
    TurboShake256,
    TurboShake256ReaderCore,
    U136,
    M14_ROUND_COUNT,
    M14_CHAINING_VALUE_SIZE,
    "MarsupilamiFourteen",
);
