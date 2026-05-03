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
use keccak::{Keccak, State1600};
use sponge_cursor::SpongeCursor;

use core::fmt;
use digest::{
    CollisionResistance, ExtendableOutput, ExtendableOutputReset, HashMarker, Reset, Update,
    XofReader,
    array::ArraySize,
    common::{AlgorithmName, BlockSizeUser},
    consts::{U16, U32, U136, U168},
};

/// Number of Keccak rounds used by TurboSHAKE.
const ROUNDS: usize = 12;

/// Default domain separator value.
pub const DEFAULT_DS: u8 = 0x1F;

/// TurboSHAKE hasher generic over rate and domain separator.
///
/// Domain separator `DS` MUST be in the range `0x01..=0x7f`.
/// Use [`DEFAULT_DS`] if you want the default value.
///
/// Rate MUST be either [`U168`] or [`U136`] for TurboSHAKE128 and TurboSHAKE256 respectively.
#[derive(Clone)]
pub struct TurboShake<Rate: ArraySize, const DS: u8> {
    state: State1600,
    cursor: SpongeCursor<Rate>,
    keccak: Keccak,
}

impl<Rate: ArraySize, const DS: u8> Default for TurboShake<Rate, DS> {
    #[inline]
    fn default() -> Self {
        const {
            assert!(DS >= 0x01 && DS <= 0x7F, "invalid domain separator");
            assert!(Rate::USIZE == 168 || Rate::USIZE == 136, "unsupported rate");
        }
        Self {
            state: Default::default(),
            cursor: Default::default(),
            keccak: Keccak::new(),
        }
    }
}

impl<Rate: ArraySize, const DS: u8> HashMarker for TurboShake<Rate, DS> {}

impl<Rate: ArraySize, const DS: u8> BlockSizeUser for TurboShake<Rate, DS> {
    type BlockSize = Rate;
}

impl<Rate: ArraySize, const DS: u8> Update for TurboShake<Rate, DS> {
    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.keccak.with_p1600::<ROUNDS>(|p1600| {
            self.cursor.absorb_u64_le(&mut self.state, p1600, data);
        });
    }
}

impl<Rate: ArraySize, const DS: u8> TurboShake<Rate, DS> {
    fn pad(&mut self) {
        let pos = self.cursor.pos();
        let word_offset = pos / 8;
        let byte_offset = pos % 8;

        let pad = u64::from(DS) << (8 * byte_offset);
        self.state[word_offset] ^= pad;
        self.state[Rate::USIZE / 8 - 1] ^= 1 << 63;
    }
}

impl<Rate: ArraySize, const DS: u8> ExtendableOutput for TurboShake<Rate, DS> {
    type Reader = TurboShakeReader<Rate>;

    #[inline]
    fn finalize_xof(mut self) -> Self::Reader {
        self.pad();
        Self::Reader {
            state: self.state,
            cursor: Default::default(),
            keccak: self.keccak,
        }
    }
}

impl<Rate: ArraySize, const DS: u8> ExtendableOutputReset for TurboShake<Rate, DS> {
    #[inline]
    fn finalize_xof_reset(&mut self) -> Self::Reader {
        self.pad();
        let reader = Self::Reader {
            state: self.state,
            cursor: Default::default(),
            keccak: self.keccak,
        };
        self.reset();
        reader
    }
}

impl<Rate: ArraySize, const DS: u8> Reset for TurboShake<Rate, DS> {
    #[inline]
    fn reset(&mut self) {
        self.state = Default::default();
        self.cursor = Default::default();
    }
}

impl<Rate: ArraySize, const DS: u8> AlgorithmName for TurboShake<Rate, DS> {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let alg_name = match Rate::USIZE {
            168 => "TurboSHAKE128",
            136 => "TurboSHAKE256",
            _ => unreachable!(),
        };
        f.write_str(alg_name)
    }
}

impl<Rate: ArraySize, const DS: u8> fmt::Debug for TurboShake<Rate, DS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let debug_str = match Rate::USIZE {
            168 => "TurboShake128 { ... }",
            136 => "TurboShake256 { ... }",
            _ => unreachable!(),
        };
        f.write_str(debug_str)
    }
}

impl<Rate: ArraySize, const DS: u8> Drop for TurboShake<Rate, DS> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use digest::zeroize::Zeroize;
            self.state.zeroize();
            // self.buffer is zeroized by its `Drop`
        }
    }
}

#[cfg(feature = "zeroize")]
impl<Rate: ArraySize, const DS: u8> digest::zeroize::ZeroizeOnDrop for TurboShake<Rate, DS> {}

/// Generic TurboSHAKE XOF reader
#[derive(Clone)]
pub struct TurboShakeReader<Rate: ArraySize> {
    state: State1600,
    cursor: SpongeCursor<Rate>,
    keccak: Keccak,
}

impl<Rate: ArraySize> XofReader for TurboShakeReader<Rate> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) {
        self.keccak.with_p1600::<ROUNDS>(|p1600| {
            self.cursor.squeeze_u64_le(&mut self.state, p1600, buf);
        });
    }
}

impl<Rate: ArraySize> fmt::Debug for TurboShakeReader<Rate> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let debug_str = match Rate::USIZE {
            168 => "TurboShakeReader128 { ... }",
            136 => "TurboShakeReader256 { ... }",
            _ => unreachable!(),
        };
        f.write_str(debug_str)
    }
}

impl<Rate: ArraySize> Drop for TurboShakeReader<Rate> {
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
impl<Rate: ArraySize> digest::zeroize::ZeroizeOnDrop for TurboShakeReader<Rate> {}

/// TurboSHAKE128 hasher with domain separator.
pub type TurboShake128<const DS: u8 = DEFAULT_DS> = TurboShake<U168, DS>;
/// TurboSHAKE256 hasher with domain separator.
pub type TurboShake256<const DS: u8 = DEFAULT_DS> = TurboShake<U136, DS>;

/// TurboSHAKE128 XOF reader.
pub type TurboShake128Reader = TurboShakeReader<U168>;
/// TurboSHAKE256 XOF reader.
pub type TurboShake256Reader = TurboShakeReader<U136>;

impl<const DS: u8> CollisionResistance for TurboShake128<DS> {
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-kangarootwelve-17.html#section-7-7
    type CollisionResistance = U16;
}

impl<const DS: u8> CollisionResistance for TurboShake256<DS> {
    // https://www.ietf.org/archive/id/draft-irtf-cfrg-kangarootwelve-17.html#section-7-8
    type CollisionResistance = U32;
}
