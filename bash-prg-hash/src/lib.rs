#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rust_2018_idioms)]
#![forbid(unsafe_code)]

pub use digest::{self, Digest};

/// Block-level types
pub mod block_api;
#[cfg(feature = "oid")]
mod oids;
mod variants;

use core::fmt;
use digest::{ExtendableOutput, ExtendableOutputReset, Reset, Update, XofReader};

pub use block_api::BashPrgHashCore;
pub use variants::{Cap1, Cap2, Capacity, Level128, Level192, Level256, SecurityLevel};

/// bash-prg-hash hasher generic over security level and capacity.
#[derive(Clone)]
pub struct BashPrgHash<L: SecurityLevel, D: Capacity> {
    core: BashPrgHashCore<L, D>,
    finalized: bool,
}

/// Helper trait to extract security level from hash type
pub trait HashLevel {
    /// Security level from specification
    type Level: SecurityLevel;
}

impl<L: SecurityLevel, D: Capacity> HashLevel for BashPrgHash<L, D> {
    type Level = L;
}

impl<L: SecurityLevel, D: Capacity> BashPrgHash<L, D> {
    /// Create a new hasher with an announcement (header).
    pub fn new(header: &[u8]) -> Self {
        Self {
            core: BashPrgHashCore::new(header),
            finalized: false,
        }
    }

    /// Create a new hasher with an empty announcement.
    pub fn new_with_empty_header() -> Self {
        Self::new(&[])
    }
}

impl<L: SecurityLevel, D: Capacity> Default for BashPrgHash<L, D> {
    fn default() -> Self {
        Self::new_with_empty_header()
    }
}

impl<L: SecurityLevel, D: Capacity> Update for BashPrgHash<L, D> {
    fn update(&mut self, data: &[u8]) {
        assert!(!self.finalized, "Cannot update after finalization");
        self.core.absorb(data);
    }
}

impl<L: SecurityLevel, D: Capacity> ExtendableOutput for BashPrgHash<L, D> {
    type Reader = BashPrgHashReader<L, D>;

    fn finalize_xof(mut self) -> Self::Reader {
        self.core.finalize();
        self.finalized = true;
        BashPrgHashReader { core: self.core }
    }
}

impl<L: SecurityLevel, D: Capacity> ExtendableOutputReset for BashPrgHash<L, D> {
    fn finalize_xof_reset(&mut self) -> Self::Reader {
        let mut core_clone = self.core.clone();
        core_clone.finalize();
        self.reset();
        BashPrgHashReader { core: core_clone }
    }
}

impl<L: SecurityLevel, D: Capacity> Reset for BashPrgHash<L, D> {
    fn reset(&mut self) {
        self.core = BashPrgHashCore::default();
        self.finalized = false;
    }
}

impl<L: SecurityLevel, D: Capacity> fmt::Debug for BashPrgHash<L, D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BashPrgHash { ... }")
    }
}

#[cfg(feature = "zeroize")]
impl<L: SecurityLevel, D: Capacity> digest::zeroize::ZeroizeOnDrop for BashPrgHash<L, D> {}

/// Reader for bash-prg-hash XOF output.
pub struct BashPrgHashReader<L: SecurityLevel, D: Capacity> {
    core: BashPrgHashCore<L, D>,
}

impl<L: SecurityLevel, D: Capacity> XofReader for BashPrgHashReader<L, D> {
    fn read(&mut self, buffer: &mut [u8]) {
        self.core.squeeze(buffer);
    }
}

impl<L: SecurityLevel, D: Capacity> Clone for BashPrgHashReader<L, D> {
    fn clone(&self) -> Self {
        Self {
            core: self.core.clone(),
        }
    }
}

#[cfg(feature = "zeroize")]
impl<L: SecurityLevel, D: Capacity> digest::zeroize::ZeroizeOnDrop for BashPrgHashReader<L, D> {}

/// bash-prg-hash with ℓ = 128 and 𝑑 = 1
pub type BashPrgHash1281 = BashPrgHash<Level128, Cap1>;
/// bash-prg-hash with ℓ = 128 and 𝑑 = 2
pub type BashPrgHash1282 = BashPrgHash<Level128, Cap2>;
/// bash-prg-hash with ℓ = 192 and 𝑑 = 1
pub type BashPrgHash1921 = BashPrgHash<Level192, Cap1>;
/// bash-prg-hash with ℓ = 192 and 𝑑 = 2
pub type BashPrgHash1922 = BashPrgHash<Level192, Cap2>;
/// bash-prg-hash with ℓ = 256 and 𝑑 = 1
pub type BashPrgHash2561 = BashPrgHash<Level256, Cap1>;
/// bash-prg-hash with ℓ = 256 and 𝑑 = 2
pub type BashPrgHash2562 = BashPrgHash<Level256, Cap2>;
