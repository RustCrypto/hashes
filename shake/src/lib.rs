#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]
#![warn(unreachable_pub)]

pub use digest;
pub use digest::{ExtendableOutput, Update, XofReader};

use core::fmt;
use digest::{
    CollisionResistance, ExtendableOutputReset, HashMarker, Reset,
    common::AlgorithmName,
    consts::{U16, U32},
};
use keccak::{Keccak, State1600};
use sponge_cursor::SpongeCursor;

/// SHAKE128 hasher.
pub type Shake128 = Shake<168>;
/// SHAKE256 hasher.
pub type Shake256 = Shake<136>;

/// SHAKE128 XOF reader.
pub type Shake128Reader = ShakeReader<168>;
/// SHAKE256 XOF reader.
pub type Shake256Reader = ShakeReader<136>;

/// SHAKE hasher generic over rate.
///
/// Rate MUST be either 168 or 136 for SHAKE128 and SHAKE256 respectively.
#[derive(Clone)]
pub struct Shake<const RATE: usize> {
    state: State1600,
    cursor: SpongeCursor<RATE>,
    keccak: Keccak,
}

impl<const RATE: usize> Default for Shake<RATE> {
    #[inline]
    fn default() -> Self {
        const { assert!(matches!(RATE, 136 | 168)) }

        Self {
            state: Default::default(),
            cursor: Default::default(),
            keccak: Keccak::new(),
        }
    }
}

impl<const RATE: usize> HashMarker for Shake<RATE> {}

impl<const RATE: usize> Update for Shake<RATE> {
    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.keccak.with_f1600(|f1600| {
            self.cursor.absorb_u64_le(&mut self.state, f1600, data);
        });
    }
}

impl<const RATE: usize> Reset for Shake<RATE> {
    #[inline]
    fn reset(&mut self) {
        self.state = Default::default();
        self.cursor = Default::default();
    }
}

impl<const RATE: usize> Shake<RATE> {
    fn pad(&mut self) {
        const SHAKE_PAD: u8 = 0x1F;

        let pos = self.cursor.pos();
        let word_offset = pos / 8;
        let byte_offset = pos % 8;

        let pad = u64::from(SHAKE_PAD) << (8 * byte_offset);
        self.state[word_offset] ^= pad;
        self.state[RATE / 8 - 1] ^= 1 << 63;
    }
}

impl<const RATE: usize> ExtendableOutput for Shake<RATE> {
    type Reader = ShakeReader<RATE>;

    #[inline]
    fn finalize_xof(mut self) -> Self::Reader {
        self.pad();
        // Note that `ShakeReader` applies the permutation to the state before reading from it
        Self::Reader {
            state: self.state,
            cursor: Default::default(),
            keccak: self.keccak,
        }
    }
}

impl<const RATE: usize> ExtendableOutputReset for Shake<RATE> {
    #[inline]
    fn finalize_xof_reset(&mut self) -> Self::Reader {
        self.pad();
        let state = self.state;
        self.reset();
        // Note that `ShakeReader` applies the permutation to the state before reading from it
        Self::Reader {
            state,
            cursor: Default::default(),
            keccak: self.keccak,
        }
    }
}

impl<const RATE: usize> AlgorithmName for Shake<RATE> {
    #[inline]
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let alg_name = match RATE {
            168 => "SHAKE128",
            136 => "SHAKE256",
            _ => unreachable!(),
        };
        f.write_str(alg_name)
    }
}

impl<const RATE: usize> fmt::Debug for Shake<RATE> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let debug_str = match RATE {
            168 => "Shake128 { ... }",
            136 => "Shake256 { ... }",
            _ => unreachable!(),
        };
        f.write_str(debug_str)
    }
}

impl<const RATE: usize> Drop for Shake<RATE> {
    #[inline]
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use digest::zeroize::Zeroize;
            self.state.zeroize();
            self.cursor.zeroize();
        }
    }
}

#[cfg(feature = "zeroize")]
impl<const RATE: usize> digest::zeroize::ZeroizeOnDrop for Shake<RATE> {}

/// SHAKE XOF reader generic over rate.
#[derive(Clone)]
pub struct ShakeReader<const RATE: usize> {
    state: State1600,
    cursor: SpongeCursor<RATE>,
    keccak: Keccak,
}

impl<const RATE: usize> XofReader for ShakeReader<RATE> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) {
        self.keccak.with_f1600(|f1600| {
            self.cursor.squeeze_read_u64_le(&mut self.state, f1600, buf);
        });
    }
}

impl<const RATE: usize> fmt::Debug for ShakeReader<RATE> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let debug_str = match RATE {
            168 => "ShakeReader128 { ... }",
            136 => "ShakeReader256 { ... }",
            _ => unreachable!(),
        };
        f.write_str(debug_str)
    }
}

impl<const RATE: usize> Drop for ShakeReader<RATE> {
    #[inline]
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use digest::zeroize::Zeroize;
            self.state.zeroize();
            self.cursor.zeroize();
        }
    }
}

// See Section 8.3 of NIST SP 800-185:
// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
impl CollisionResistance for Shake128 {
    type CollisionResistance = U16;
}

impl CollisionResistance for Shake256 {
    type CollisionResistance = U32;
}
