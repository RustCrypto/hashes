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

#[cfg(feature = "oid")]
mod oids;
mod variants;

use bash_f::{STATE_WORDS, bash_f};
use core::ops::Div;
use core::{fmt, marker::PhantomData};
use digest::typenum::Unsigned;
use digest::{
    ExtendableOutput, ExtendableOutputReset, Reset, Update, XofReader,
    typenum::{U1, U2, U128, U192, U256},
};
pub use variants::{Capacity, SecurityLevel};

/// Data type codes from Table 3 of STB 34.101.77-2020
const DATA: u8 = 0b000010;
/// Data type codes from Table 3 of STB 34.101.77-2020
const OUT: u8 = 0b000100;

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
    state: [u64; STATE_WORDS],
    /// current offset in bytes
    offset: usize,
    _pd: PhantomData<(L, D)>,
}

impl<L: SecurityLevel, D: Capacity> Default for BashPrgHash<L, D> {
    fn default() -> Self {
        Self::new_customized(&[])
    }
}

impl<L: SecurityLevel, D: Capacity> Update for BashPrgHash<L, D> {
    fn update(&mut self, data: &[u8]) {
        self.absorb(data);
    }
}

impl<L: SecurityLevel, D: Capacity> ExtendableOutput for BashPrgHash<L, D> {
    type Reader = BashPrgHashReader<L, D>;

    fn finalize_xof(mut self) -> Self::Reader {
        self.finalize();
        BashPrgHashReader {
            state: self.state,
            offset: self.offset,
            _pd: PhantomData,
        }
    }
}

impl<L: SecurityLevel, D: Capacity> ExtendableOutputReset for BashPrgHash<L, D> {
    fn finalize_xof_reset(&mut self) -> Self::Reader {
        let mut hasher_clone = self.clone();
        hasher_clone.finalize();
        self.reset();
        BashPrgHashReader {
            state: hasher_clone.state,
            offset: hasher_clone.offset,
            _pd: PhantomData,
        }
    }
}

impl<L: SecurityLevel, D: Capacity> Reset for BashPrgHash<L, D> {
    fn reset(&mut self) {
        *self = Self::default();
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
    state: [u64; STATE_WORDS],
    offset: usize,
    _pd: PhantomData<(L, D)>,
}

impl<L: SecurityLevel, D: Capacity> XofReader for BashPrgHashReader<L, D> {
    fn read(&mut self, buffer: &mut [u8]) {
        self.squeeze(buffer);
    }
}

#[cfg(feature = "zeroize")]
impl<L: SecurityLevel, D: Capacity> digest::zeroize::ZeroizeOnDrop for BashPrgHashReader<L, D> {}

impl<L: SecurityLevel, D: Capacity> BashPrgHash<L, D> {
    /// Calculate buffer size r = 1536 - 2dℓ (in bytes)
    const fn rate_bytes() -> usize {
        (1536 - 2 * D::USIZE * L::USIZE) / 8
    }

    fn new_customized(header: &[u8]) -> Self {
        const MAX_HEADER_LEN: usize = 60; // 480 bits = 60 bytes

        assert!(
            header.len() <= MAX_HEADER_LEN,
            "Header length must not exceed 480 bits (60 bytes)"
        );
        assert_eq!(
            header.len() % 4,
            0,
            "Header length must be multiple of 32 bits (4 bytes)"
        );

        let mut this = Self {
            state: [0u64; STATE_WORDS],
            offset: 0,
            _pd: PhantomData,
        };

        this.start(header);
        this.commit(DATA);
        this
    }

    /// Modify byte at position in state
    fn modify_byte(state: &mut [u64; STATE_WORDS], pos: usize, f: impl FnOnce(&mut u8)) {
        let word_idx = pos / 8;
        let byte_in_word = pos % 8;
        let mut bytes = state[word_idx].to_le_bytes();
        f(&mut bytes[byte_in_word]);
        state[word_idx] = u64::from_le_bytes(bytes);
    }

    /// Get byte at position in state
    fn get_byte(state: &[u64; STATE_WORDS], pos: usize) -> u8 {
        let word_idx = pos / 8;
        let byte_in_word = pos % 8;
        state[word_idx].to_le_bytes()[byte_in_word]
    }

    /// XOR input bytes into state at current offset
    fn xor_in(state: &mut [u64; STATE_WORDS], offset: &mut usize, input: &[u8]) {
        for (i, &byte) in input.iter().enumerate() {
            Self::modify_byte(state, *offset + i, |b| *b ^= byte);
        }
        *offset += input.len();
    }

    /// Extract bytes from state at current offset
    fn extract_bytes(state: &[u64; STATE_WORDS], offset: &mut usize, output: &mut [u8]) {
        for (i, out_byte) in output.iter_mut().enumerate() {
            *out_byte = Self::get_byte(state, *offset + i);
        }
        *offset += output.len();
    }

    /// `start[ℓ, 𝑑](𝐴, 𝐾)` (Section 8.3.2)
    fn start(&mut self, header: &[u8]) {
        let header_len = header.len();
        // Step 3: pos <- 8 + |A| + |K| (in bits), i.e. 1 + |A| + |K| (in bytes).
        self.offset = 1 + header_len;
        // Step 4: S[...pos) <- <|A|/2 + |K|/32>_8 || A || K.
        let first_byte = ((header_len * 8) / 2) as u8;
        Self::modify_byte(&mut self.state, 0, |b| *b = first_byte);
        for (i, &byte) in header.iter().enumerate() {
            Self::modify_byte(&mut self.state, 1 + i, |b| *b = byte);
        }
        // Step 6: S[1472...) <- <ℓ/4 + d>_64.
        self.state[23] = (L::USIZE / 4 + D::USIZE) as u64;
    }

    /// `commit[ℓ, d](t)` (Section 8.4.2)
    fn commit(&mut self, t: u8) {
        // Step 1: S[pos...pos+8) <- S[pos...pos+8) xor (t || 01).
        let tag = (t << 2) | 0x01;
        Self::modify_byte(&mut self.state, self.offset, |b| *b ^= tag);
        // Step 2: S[r] <- S[r] xor 1, where r = 1536 - 2 d ℓ (bit index).
        let r_bit_in_byte = (Self::rate_bytes() * 8) % 8;
        Self::modify_byte(&mut self.state, Self::rate_bytes(), |b| {
            *b ^= 1u8 << (7 - r_bit_in_byte)
        });
        // Step 3: S <- bash-f(S).
        bash_f(&mut self.state);
        // Step 4: pos <- 0.
        self.offset = 0;
    }

    /// `absorb[ℓ, d](X)` (Section 8.6.2)
    fn absorb(&mut self, data: &[u8]) {
        // Steps 2-3: process X in blocks of length up to r - pos.
        let mut input = data;
        while !input.is_empty() {
            let to_absorb = input.len().min(Self::rate_bytes() - self.offset);
            // S[pos...pos+|X_i|) <- S[pos...pos+|X_i|) xor X_i, pos <- pos + |X_i|.
            Self::xor_in(&mut self.state, &mut self.offset, &input[..to_absorb]);
            input = &input[to_absorb..];
            if self.offset == Self::rate_bytes() {
                // If pos = r, then S <- bash-f(S), pos <- 0.
                bash_f(&mut self.state);
                self.offset = 0;
            }
        }
    }

    /// `squeezePrep[ℓ, d]()` / output preparation: `commit(OUT)` (Section 8.7).
    fn finalize(&mut self) {
        self.commit(OUT);
    }
}

impl<L: SecurityLevel, D: Capacity> BashPrgHashReader<L, D> {
    /// `squeeze[ℓ, d](Y)` (Section 8.7.2)
    fn squeeze(&mut self, output: &mut [u8]) {
        let mut remaining = output;
        while !remaining.is_empty() {
            if self.offset == BashPrgHash::<L, D>::rate_bytes() {
                // If pos = r, then S <- bash-f(S), pos <- 0.
                bash_f(&mut self.state);
                self.offset = 0;
            }
            let to_squeeze = remaining
                .len()
                .min(BashPrgHash::<L, D>::rate_bytes() - self.offset);
            // Y_i <- S[pos...pos+|Y_i|), pos <- pos + |Y_i|.
            BashPrgHash::<L, D>::extract_bytes(
                &self.state,
                &mut self.offset,
                &mut remaining[..to_squeeze],
            );
            remaining = &mut remaining[to_squeeze..];
        }
    }
}

impl<L: SecurityLevel, D: Capacity> Drop for BashPrgHash<L, D> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use digest::zeroize::Zeroize;
            self.state.zeroize();
        }
    }
}

impl<L: SecurityLevel, D: Capacity> Drop for BashPrgHashReader<L, D> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use digest::zeroize::Zeroize;
            self.state.zeroize();
        }
    }
}

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
