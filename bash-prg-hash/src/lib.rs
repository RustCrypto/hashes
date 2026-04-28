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

pub use block_api::BashPrgHashState;
use core::fmt;
use core::ops::Div;
use digest::typenum::Unsigned;
use digest::{
    ExtendableOutput, ExtendableOutputReset, Reset, Update, XofReader,
    typenum::{U1, U2, U128, U192, U256},
};
pub use variants::{Capacity, SecurityLevel};

/// bash-prg-hash hasher generic over security level and capacity.
///
/// # Generic Parameters
///
/// - `L`: Security level ℓ ∈ {128, 192, 256}. Use `U128`, `U192`, or `U256` from `digest::typenum`.
/// - `D`: Capacity d ∈ {1, 2}. Use `U1` or `U2` from `digest::typenum`.
///
/// # Examples
///
/// ```
/// use bash_prg_hash::{BashPrgHash1281, digest::{ExtendableOutput, Update, XofReader}};
///
/// let mut hasher = BashPrgHash1281::default();
/// hasher.update(b"hello world");
/// let mut reader = hasher.finalize_xof();
/// let mut output = [0u8; 32];
/// reader.read(&mut output);
/// ```
#[derive(Clone)]
pub struct BashPrgHash<L: SecurityLevel, D: Capacity> {
    state: BashPrgHashState<L, D>,
}

impl<L: SecurityLevel, D: Capacity> Default for BashPrgHash<L, D> {
    fn default() -> Self {
        Self {
            state: BashPrgHashState::default(),
        }
    }
}

impl<L: SecurityLevel, D: Capacity> Update for BashPrgHash<L, D> {
    fn update(&mut self, data: &[u8]) {
        self.state.absorb(data);
    }
}

impl<L: SecurityLevel, D: Capacity> ExtendableOutput for BashPrgHash<L, D> {
    type Reader = BashPrgHashReader<L, D>;

    fn finalize_xof(mut self) -> Self::Reader {
        self.state.finalize();
        BashPrgHashReader { state: self.state }
    }
}

impl<L: SecurityLevel, D: Capacity> ExtendableOutputReset for BashPrgHash<L, D> {
    fn finalize_xof_reset(&mut self) -> Self::Reader {
        let mut state_clone = self.state.clone();
        state_clone.finalize();
        self.reset();
        BashPrgHashReader { state: state_clone }
    }
}

impl<L: SecurityLevel, D: Capacity> Reset for BashPrgHash<L, D> {
    fn reset(&mut self) {
        self.state = BashPrgHashState::default();
    }
}

impl<L: SecurityLevel, D: Capacity> fmt::Debug for BashPrgHash<L, D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BashPrgHash { ... }")
    }
}

impl<L: SecurityLevel, D: Capacity> digest::CollisionResistance for BashPrgHash<L, D>
where
    L: Div<digest::typenum::U8>,
    <L as Div<digest::typenum::U8>>::Output: Unsigned,
{
    type CollisionResistance = <L as Div<digest::typenum::U8>>::Output;
}

#[cfg(feature = "zeroize")]
impl<L: SecurityLevel, D: Capacity> digest::zeroize::ZeroizeOnDrop for BashPrgHash<L, D> {}

/// Reader for bash-prg-hash XOF output.
#[derive(Clone)]
pub struct BashPrgHashReader<L: SecurityLevel, D: Capacity> {
    state: BashPrgHashState<L, D>,
}

impl<L: SecurityLevel, D: Capacity> XofReader for BashPrgHashReader<L, D> {
    fn read(&mut self, buffer: &mut [u8]) {
        self.state.squeeze(buffer);
    }
}

#[cfg(feature = "zeroize")]
impl<L: SecurityLevel, D: Capacity> digest::zeroize::ZeroizeOnDrop for BashPrgHashReader<L, D> {}

/// bash-prg-hash with ℓ = 128 and d = 1
pub type BashPrgHash1281 = BashPrgHash<U128, U1>;
/// bash-prg-hash with ℓ = 128 and d = 2
pub type BashPrgHash1282 = BashPrgHash<U128, U2>;
/// bash-prg-hash with ℓ = 192 and d = 1
pub type BashPrgHash1921 = BashPrgHash<U192, U1>;
/// bash-prg-hash with ℓ = 192 and d = 2
pub type BashPrgHash1922 = BashPrgHash<U192, U2>;
/// bash-prg-hash with ℓ = 256 and d = 1
pub type BashPrgHash2561 = BashPrgHash<U256, U1>;
/// bash-prg-hash with ℓ = 256 and d = 2
pub type BashPrgHash2562 = BashPrgHash<U256, U2>;
