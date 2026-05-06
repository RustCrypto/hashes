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

mod variants;
pub use variants::*;

use bash_f::{STATE_WORDS, bash_f};
use core::fmt;
use digest::{ExtendableOutput, TryCustomizedInit, Update, XofReader};
use sponge_cursor::SpongeCursor;

/// Data type codes from Table 3 of STB 34.101.77-2020
const DATA: u8 = 0b000010;
/// Data type codes from Table 3 of STB 34.101.77-2020
const OUT: u8 = 0b000100;

/// `bash-prg-hash` hasher generic over rate and capacity.
///
/// # Generic Parameters
///
/// Only the following combinations of rate and capacity with
/// the resulting security level are supported:
///
/// | Rate, bytes | Capacity | Security level, bits |
/// |:-----------:|:--------:|:--------------------:|
/// |     160     |     1    |          128         |
/// |     128     |     2    |          128         |
/// |     144     |     1    |          192         |
/// |      96     |     2    |          192         |
/// |     128     |     1    |          256         |
/// |      64     |     2    |          256         |
///
/// Trying to initialize hasher state with a different pair of parameters will
/// result in a compilation error.
///
/// Users are recommended to use type aliases (e.g. [`BashPrgHash1281`]) instead of using
/// this type directly.
// Note: Ideally, we would use `LEVEL` instead of `RATE` and define the `cursor` field as
// `SpongeCursor<{192-2*CAPACITY*LEVEL}>`, but it requires stabilized `generic_const_exprs`.
#[derive(Clone)]
pub struct BashPrgHash<const RATE: usize, const CAPACITY: usize> {
    state: [u64; STATE_WORDS],
    cursor: SpongeCursor<RATE>,
}

impl<const RATE: usize, const CAPACITY: usize> Default for BashPrgHash<RATE, CAPACITY> {
    #[inline]
    fn default() -> Self {
        Self::try_new_customized(&[]).expect("Always correct")
    }
}

impl<const RATE: usize, const CAPACITY: usize> TryCustomizedInit for BashPrgHash<RATE, CAPACITY> {
    type Error = InvalidHeaderError;

    #[inline]
    fn try_new_customized(header: &[u8]) -> Result<Self, Self::Error> {
        const {
            assert!(
                matches!(
                    (RATE, CAPACITY),
                    (160, 1) | (128, 2) | (144, 1) | (96, 2) | (128, 1) | (64, 2)
                ),
                "invalid combination of RATE and CAPACITY"
            )
        }

        const MAX_HEADER_LEN: usize = 60;

        let header_len = header.len();
        if header_len > MAX_HEADER_LEN || header_len % 4 != 0 {
            return Err(InvalidHeaderError);
        }

        // `start[ℓ, 𝑑](𝐴, 𝐾)` (Section 8.3.2)

        // Step 3: pos <- 8 + |A| + |K| (in bits), i.e. 1 + |A| + |K| (in bytes).
        let pos = 1 + header_len;

        // Step 4: S[...pos) <- <|A|/2 + |K|/32>_8 || A || K.
        // Step 5: S[pos...1472) <- 0^{1472-pos}

        let mut buf = [0u8; 8 * STATE_WORDS];
        buf[0] = u8::try_from(header_len / 4).expect("header_len fits into u8");
        buf[1..][..header_len].copy_from_slice(header);

        let mut state = [0u64; STATE_WORDS];
        let chunks = buf.chunks_exact(8);
        assert!(chunks.remainder().is_empty());
        for (dst, chunk) in state.iter_mut().zip(chunks) {
            let chunk = chunk.try_into().expect("chunk has correct size");
            *dst = u64::from_le_bytes(chunk);
        }

        // Step 6: S[1472...) <- <ℓ/4 + d>_64
        let level = (192 - RATE) / (2 * CAPACITY);
        state[23] = u64::try_from(level * 2 + CAPACITY).expect("the value always fits into u64");

        // `commit[ℓ, d](DATA)` (Section 8.4.2)

        let word_pos = pos / 8;
        let byte_pos = pos % 8;

        // Step 1: S[pos...pos+8) <- S[pos...pos+8) ⊕ (t || 01).
        const DATA_PAD: u8 = (DATA << 2) | 0x01;
        state[word_pos] ^= u64::from(DATA_PAD) << (8 * byte_pos);

        // Step 2: S[r] <- S[r] ⊕ 1, where r = 1536 - 2 d ℓ (bit index).
        const { assert!(RATE % 8 == 0) }
        state[RATE / 8] ^= 1u64 << 7;

        // Step 3: S <- bash-f(S).
        bash_f(&mut state);

        Ok(Self {
            state,
            // Step 4: pos <- 0.
            cursor: Default::default(),
        })
    }
}

impl<const RATE: usize, const CAPACITY: usize> BashPrgHash<RATE, CAPACITY> {}

impl<const RATE: usize, const CAPACITY: usize> Update for BashPrgHash<RATE, CAPACITY> {
    #[inline]
    fn update(&mut self, data: &[u8]) {
        // `absorb[ℓ, d](X)` (Section 8.6.2)
        self.cursor.absorb_u64_le(&mut self.state, bash_f, data);
    }
}

impl<const RATE: usize, const CAPACITY: usize> ExtendableOutput for BashPrgHash<RATE, CAPACITY> {
    type Reader = BashPrgHashReader<RATE, CAPACITY>;

    #[inline]
    fn finalize_xof(mut self) -> Self::Reader {
        let pos = self.cursor.pos();
        let word_pos = pos / 8;
        let byte_pos = pos % 8;

        // Step 1: S[pos...pos+8) <- S[pos...pos+8) ⊕ (t || 01).
        const OUT_PAD: u8 = (OUT << 2) | 0x01;
        self.state[word_pos] ^= u64::from(OUT_PAD) << (8 * byte_pos);

        // Step 2: S[r] <- S[r] ⊕ 1, where r = 1536 - 2 d ℓ (bit index).
        const { assert!(RATE % 8 == 0) }
        self.state[RATE / 8] ^= 1u64 << 7;

        BashPrgHashReader {
            state: self.state,
            cursor: Default::default(),
        }
    }
}

impl<const RATE: usize, const CAPACITY: usize> fmt::Debug for BashPrgHash<RATE, CAPACITY> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BashPrgHash { ... }")
    }
}

impl<const RATE: usize, const CAPACITY: usize> Drop for BashPrgHash<RATE, CAPACITY> {
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
impl<const RATE: usize, const CAPACITY: usize> digest::zeroize::ZeroizeOnDrop
    for BashPrgHash<RATE, CAPACITY>
{
}

/// Reader for bash-prg-hash XOF output.
#[derive(Clone)]
pub struct BashPrgHashReader<const RATE: usize, const CAPACITY: usize> {
    state: [u64; STATE_WORDS],
    cursor: SpongeCursor<RATE>,
}

impl<const RATE: usize, const CAPACITY: usize> XofReader for BashPrgHashReader<RATE, CAPACITY> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) {
        self.cursor
            .squeeze_read_u64_le(&mut self.state, bash_f, buf);
    }
}

impl<const RATE: usize, const CAPACITY: usize> Drop for BashPrgHashReader<RATE, CAPACITY> {
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
impl<const RATE: usize, const CAPACITY: usize> digest::zeroize::ZeroizeOnDrop
    for BashPrgHashReader<RATE, CAPACITY>
{
}

/// Invalid `bash-prg-hash` header error.
#[derive(Debug)]
pub struct InvalidHeaderError;

impl fmt::Display for InvalidHeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "Invalid `bash-prg-hash` header. \
            Header length must be a multiple of 4 bytes and not greater than 60 bytes.",
        )
    }
}

impl core::error::Error for InvalidHeaderError {}
