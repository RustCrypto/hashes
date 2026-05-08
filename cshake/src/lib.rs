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

use core::fmt;
use digest::{
    CollisionResistance, CustomizedInit, ExtendableOutput, HashMarker, Update, XofReader,
    common::{AlgorithmName, BlockSizeUser},
    consts::{U16, U32, U136, U168},
};
use keccak::{Keccak, State1600};
use sponge_cursor::SpongeCursor;

const SHAKE_PAD: u8 = 0x1F;
const CSHAKE_PAD: u8 = 0x04;

/// cSHAKE128 hasher.
pub type CShake128 = CShake<168>;
/// cSHAKE256 hasher.
pub type CShake256 = CShake<136>;

/// cSHAKE hasher generic over rate.
///
/// Rate MUST be either 168 or 136 for cSHAKE128 and cSHAKE256 respectively.
#[derive(Clone)]
pub struct CShake<const RATE: usize> {
    state: State1600,
    cursor: SpongeCursor<RATE>,
    pad: u8,
    keccak: Keccak,
}

impl<const RATE: usize> Default for CShake<RATE> {
    #[inline]
    fn default() -> Self {
        Self::new_with_function_name(b"", b"")
    }
}

impl<const RATE: usize> CShake<RATE> {
    /// Creates a new cSHAKE instance with the given function name and customization.
    ///
    /// Note that the function name is intended for use by NIST and should only be set to
    /// values defined by NIST. You probably don't need to use this function.
    pub fn new_with_function_name(function_name: &[u8], customization: &[u8]) -> Self {
        const {
            assert!(RATE == 168 || RATE == 136, "unsupported rate");
        }

        let keccak = Keccak::new();
        let mut state = State1600::default();

        if function_name.is_empty() && customization.is_empty() {
            return Self {
                state,
                cursor: Default::default(),
                pad: SHAKE_PAD,
                keccak,
            };
        }

        #[inline(always)]
        fn left_encode(val: u64, b: &mut [u8; 9]) -> &[u8] {
            b[1..].copy_from_slice(&val.to_be_bytes());
            let i = b[1..8].iter().take_while(|&&a| a == 0).count();
            b[i] = (8 - i) as u8;
            &b[i..]
        }

        keccak.with_f1600(|f1600| {
            let mut cursor: SpongeCursor<RATE> = Default::default();
            let state = &mut state;
            let mut b = [0u8; 9];

            let rate_u64 = u64::try_from(RATE).expect("RATE is smaller than 200");
            cursor.absorb_u64_le(state, f1600, left_encode(rate_u64, &mut b));

            let mut encode_str = |str: &[u8]| {
                let str_bits_len = 8 * u64::try_from(str.len())
                    .expect("in practice strings can not be longer than u64::MAX");
                let encoded_len = left_encode(str_bits_len, &mut b);
                cursor.absorb_u64_le(state, f1600, encoded_len);
                cursor.absorb_u64_le(state, f1600, str);
            };

            encode_str(function_name);
            encode_str(customization);

            if cursor.pos() != 0 {
                f1600(state);
            }
        });

        Self {
            state,
            cursor: Default::default(),
            pad: CSHAKE_PAD,
            keccak,
        }
    }
}

impl<const RATE: usize> CustomizedInit for CShake<RATE> {
    #[inline]
    fn new_customized(customization: &[u8]) -> Self {
        Self::new_with_function_name(&[], customization)
    }
}

impl<const RATE: usize> HashMarker for CShake<RATE> {}

impl<const RATE: usize> Update for CShake<RATE> {
    fn update(&mut self, data: &[u8]) {
        self.keccak.with_f1600(|f1600| {
            self.cursor.absorb_u64_le(&mut self.state, f1600, data);
        });
    }
}

impl<const RATE: usize> ExtendableOutput for CShake<RATE> {
    type Reader = CShakeReader<RATE>;

    #[inline]
    fn finalize_xof(mut self) -> Self::Reader {
        let pos = self.cursor.pos();
        let word_offset = pos / 8;
        let byte_offset = pos % 8;

        let pad = u64::from(self.pad) << (8 * byte_offset);
        self.state[word_offset] ^= pad;
        self.state[RATE / 8 - 1] ^= 1 << 63;

        // Note that `CShakeReader` applies the permutation to the state before reading from it

        Self::Reader {
            state: self.state,
            cursor: Default::default(),
            keccak: self.keccak,
        }
    }
}

impl<const RATE: usize> AlgorithmName for CShake<RATE> {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let alg_name = match RATE {
            168 => "cSHAKE128",
            136 => "cSHAKE256",
            _ => unreachable!(),
        };
        f.write_str(alg_name)
    }
}

impl<const RATE: usize> fmt::Debug for CShake<RATE> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let debug_str = match RATE {
            168 => "CShake128 { ... }",
            136 => "CShake256 { ... }",
            _ => unreachable!(),
        };
        f.write_str(debug_str)
    }
}

impl<const RATE: usize> Drop for CShake<RATE> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use digest::zeroize::Zeroize;
            self.state.zeroize();
            self.cursor.zeroize();
            self.pad.zeroize();
        }
    }
}

#[cfg(feature = "zeroize")]
impl<const RATE: usize> digest::zeroize::ZeroizeOnDrop for CShake<RATE> {}

/// Generic cSHAKE XOF reader
#[derive(Clone)]
pub struct CShakeReader<const RATE: usize> {
    state: State1600,
    cursor: SpongeCursor<RATE>,
    keccak: Keccak,
}

impl<const RATE: usize> XofReader for CShakeReader<RATE> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) {
        self.keccak.with_f1600(|f1600| {
            self.cursor.squeeze_read_u64_le(&mut self.state, f1600, buf);
        });
    }
}

impl<const RATE: usize> fmt::Debug for CShakeReader<RATE> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let debug_str = match RATE {
            168 => "CShakeReader128 { ... }",
            136 => "CShakeReader256 { ... }",
            _ => unreachable!(),
        };
        f.write_str(debug_str)
    }
}

impl<const RATE: usize> Drop for CShakeReader<RATE> {
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
impl CollisionResistance for CShake128 {
    type CollisionResistance = U16;
}
impl CollisionResistance for CShake256 {
    type CollisionResistance = U32;
}

impl BlockSizeUser for CShake128 {
    type BlockSize = U168;
}

impl BlockSizeUser for CShake256 {
    type BlockSize = U136;
}
