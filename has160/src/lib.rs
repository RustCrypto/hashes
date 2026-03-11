#![no_std]
#![warn(missing_docs, unreachable_pub)]

//! HAS-160 hash function.

pub use digest::{self, Digest};

/// Block-level types
pub mod block_api;
mod compress;
mod consts;

digest::buffer_fixed!(
    /// HAS-160 hasher.
    pub struct Has160(block_api::Has160Core);
    // NOTE: couldn't find an OID
    impl: FixedHashTraits;
);
