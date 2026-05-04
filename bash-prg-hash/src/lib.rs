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

use crate::variants::Rate;
use bash_f::{STATE_WORDS, bash_f};
use core::fmt;
use digest::{
    ExtendableOutput, ExtendableOutputReset, Reset, TryCustomizedInit, Update, XofReader,
    typenum::{U1, U2, U16, U24, U32},
};
use sponge_cursor::SpongeCursor;
pub use variants::{Capacity, SecurityLevel};

/// Invalid header length error
#[derive(Debug)]
pub struct InvalidHeaderLength;

/// Data type codes from Table 3 of STB 34.101.77-2020
const DATA: u8 = 0b000010;
/// Data type codes from Table 3 of STB 34.101.77-2020
const OUT: u8 = 0b000100;

/// `bash-prg-hash` hasher generic over security level and capacity.
///
/// # Generic Parameters
///
/// - `L`: Security level ℓ ∈ {128, 192, 256}. Use `U16`, `U24`, or `U32` from `digest::typenum`.
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
pub struct BashPrgHash<L: SecurityLevel, D: Capacity>
where
    (L, D): Rate,
{
    state: [u64; STATE_WORDS],
    cursor: SpongeCursor<<(L, D) as Rate>::Rate>,
}

impl<L: SecurityLevel, D: Capacity> Default for BashPrgHash<L, D>
where
    (L, D): Rate,
{
    fn default() -> Self {
        Self::try_new_customized(&[][..]).expect("Always correct")
    }
}

impl<L: SecurityLevel, D: Capacity> TryCustomizedInit for BashPrgHash<L, D>
where
    (L, D): Rate,
{
    type Error = InvalidHeaderLength;

    fn try_new_customized(header: &[u8]) -> Result<Self, Self::Error> {
        const MAX_HEADER_LEN: usize = 60;

        if header.len() > MAX_HEADER_LEN || header.len() % 4 != 0 {
            return Err(InvalidHeaderLength);
        }

        let mut this = Self {
            state: [0u64; STATE_WORDS],
            cursor: SpongeCursor::default(),
        };

        this.start(header);
        this.commit(DATA);

        Ok(this)
    }
}

impl<L: SecurityLevel, D: Capacity> Update for BashPrgHash<L, D>
where
    (L, D): Rate,
{
    fn update(&mut self, data: &[u8]) {
        self.absorb(data);
    }
}

impl<L: SecurityLevel, D: Capacity> ExtendableOutput for BashPrgHash<L, D>
where
    (L, D): Rate,
{
    type Reader = BashPrgHashReader<L, D>;

    fn finalize_xof(mut self) -> Self::Reader {
        self.finalize();
        BashPrgHashReader {
            state: self.state,
            cursor: self.cursor.clone(),
        }
    }
}

impl<L: SecurityLevel, D: Capacity> ExtendableOutputReset for BashPrgHash<L, D>
where
    (L, D): Rate,
{
    fn finalize_xof_reset(&mut self) -> Self::Reader {
        let mut hasher_clone = self.clone();
        hasher_clone.finalize();
        self.reset();
        BashPrgHashReader {
            state: hasher_clone.state,
            cursor: hasher_clone.cursor.clone(),
        }
    }
}

impl<L: SecurityLevel, D: Capacity> Reset for BashPrgHash<L, D>
where
    (L, D): Rate,
{
    fn reset(&mut self) {
        *self = Self::default();
    }
}

impl<L: SecurityLevel, D: Capacity> fmt::Debug for BashPrgHash<L, D>
where
    (L, D): Rate,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BashPrgHash { ... }")
    }
}

impl<L: SecurityLevel, D: Capacity> digest::CollisionResistance for BashPrgHash<L, D>
where
    (L, D): Rate,
{
    type CollisionResistance = L;
}

#[cfg(feature = "zeroize")]
impl<L: SecurityLevel, D: Capacity> digest::zeroize::ZeroizeOnDrop for BashPrgHash<L, D> where
    (L, D): Rate
{
}

/// Reader for bash-prg-hash XOF output.
#[derive(Clone)]
pub struct BashPrgHashReader<L: SecurityLevel, D: Capacity>
where
    (L, D): Rate,
{
    state: [u64; STATE_WORDS],
    cursor: SpongeCursor<<(L, D) as Rate>::Rate>,
}

impl<L: SecurityLevel, D: Capacity> XofReader for BashPrgHashReader<L, D>
where
    (L, D): Rate,
{
    fn read(&mut self, buffer: &mut [u8]) {
        self.squeeze(buffer);
    }
}

#[cfg(feature = "zeroize")]
impl<L: SecurityLevel, D: Capacity> digest::zeroize::ZeroizeOnDrop for BashPrgHashReader<L, D> where
    (L, D): Rate
{
}

impl<L: SecurityLevel, D: Capacity> BashPrgHash<L, D>
where
    (L, D): Rate,
{
    /// Modify byte at position in state
    fn modify_byte(state: &mut [u64; STATE_WORDS], pos: usize, f: impl FnOnce(&mut u8)) {
        let word_idx = pos / 8;
        let byte_in_word = pos % 8;
        let mut bytes = state[word_idx].to_le_bytes();
        f(&mut bytes[byte_in_word]);
        state[word_idx] = u64::from_le_bytes(bytes);
    }

    /// `start[ℓ, 𝑑](𝐴, 𝐾)` (Section 8.3.2)
    fn start(&mut self, header: &[u8]) {
        let header_len = header.len();

        // Step 4: S[...pos) <- <|A|/2 + |K|/32>_8 || A || K.
        let first_byte = ((header_len * 8) / 2) as u8;
        Self::modify_byte(&mut self.state, 0, |b| *b = first_byte);
        for (i, &byte) in header.iter().enumerate() {
            Self::modify_byte(&mut self.state, 1 + i, |b| *b = byte);
        }

        // Step 3: pos <- 8 + |A| + |K| (in bits), i.e. 1 + |A| + |K| (in bytes).
        let pos = (1 + header_len) as u8;
        self.cursor = SpongeCursor::new(pos).expect("pos within bounds");

        // Step 6: S[1472...) <- <ℓ/4 + d>_64
        self.state[23] = (L::USIZE * 2 + D::USIZE) as u64;
    }

    /// `squeezePrep[ℓ, d]()` / output preparation: `commit(OUT)` (Section 8.7).
    fn finalize(&mut self) {
        self.commit(OUT);
    }
}

impl<L: SecurityLevel, D: Capacity> BashPrgHash<L, D>
where
    (L, D): Rate,
{
    const RATE: usize = 192 - 2 * D::USIZE * L::USIZE;

    fn get_byte(state: &[u64; STATE_WORDS], pos: usize) -> u8 {
        let word_idx = pos / 8;
        let byte_in_word = pos % 8;
        state[word_idx].to_le_bytes()[byte_in_word]
    }

    fn extract_bytes(state: &[u64; STATE_WORDS], offset: usize, output: &mut [u8]) {
        for (i, out_byte) in output.iter_mut().enumerate() {
            *out_byte = Self::get_byte(state, offset + i);
        }
    }

    /// `absorb[ℓ, d](X)` (Section 8.6.2)
    fn absorb(&mut self, data: &[u8]) {
        self.cursor
            .absorb_u64_le::<STATE_WORDS>(&mut self.state, bash_f, data);
    }

    /// `commit[ℓ, d](t)` (Section 8.4.2)
    fn commit(&mut self, t: u8) {
        let pos = self.cursor.pos();

        // Step 1: S[pos...pos+8) <- S[pos...pos+8) ⊕ (t || 01).
        let tag = (t << 2) | 0x01;
        Self::modify_byte(&mut self.state, pos, |b| *b ^= tag);

        // Step 2: S[r] <- S[r] ⊕ 1, where r = 1536 - 2 d ℓ (bit index).
        let r_bit_in_byte = (Self::RATE * 8) % 8;
        Self::modify_byte(&mut self.state, Self::RATE, |b| {
            *b ^= 1u8 << (7 - r_bit_in_byte)
        });

        // Step 3: S <- bash-f(S).
        bash_f(&mut self.state);
        // Step 4: pos <- 0.
        self.cursor = SpongeCursor::default();
    }
}

impl<L: SecurityLevel, D: Capacity> BashPrgHashReader<L, D>
where
    (L, D): Rate,
{
    /// `squeeze[ℓ, d](Y)` (Section 8.7.2)
    fn squeeze(&mut self, output: &mut [u8]) {
        let mut remaining = output;

        while !remaining.is_empty() {
            // Step 1: Split Y into the next chunk Yi with |Yi| <= r - pos.
            let pos = self.cursor.pos();
            let to_squeeze = remaining.len().min(BashPrgHash::<L, D>::RATE - pos);

            // Step 2: Yi <- S[pos..pos+|Yi|), pos <- pos + |Yi|.
            BashPrgHash::<L, D>::extract_bytes(&self.state, pos, &mut remaining[..to_squeeze]);
            remaining = &mut remaining[to_squeeze..];

            if pos + to_squeeze == BashPrgHash::<L, D>::RATE {
                // Step 3: If pos = r then S <- bash-f(S), pos <- 0.
                bash_f(&mut self.state);
                self.cursor = SpongeCursor::default();
            } else {
                let new_pos = u8::try_from(pos + to_squeeze).expect("position is within rate");
                self.cursor = SpongeCursor::new(new_pos).expect("position is within rate");
            }
        }
    }
}

impl<L: SecurityLevel, D: Capacity> Drop for BashPrgHash<L, D>
where
    (L, D): Rate,
{
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use digest::zeroize::Zeroize;
            self.state.zeroize();
        }
    }
}

impl<L: SecurityLevel, D: Capacity> Drop for BashPrgHashReader<L, D>
where
    (L, D): Rate,
{
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use digest::zeroize::Zeroize;
            self.state.zeroize();
        }
    }
}

/// bash-prg-hash with ℓ = 128 and d = 1
pub type BashPrgHash1281 = BashPrgHash<U16, U1>;
/// bash-prg-hash with ℓ = 128 and d = 2
pub type BashPrgHash1282 = BashPrgHash<U16, U2>;
/// bash-prg-hash with ℓ = 192 and d = 1
pub type BashPrgHash1921 = BashPrgHash<U24, U1>;
/// bash-prg-hash with ℓ = 192 and d = 2
pub type BashPrgHash1922 = BashPrgHash<U24, U2>;
/// bash-prg-hash with ℓ = 256 and d = 1
pub type BashPrgHash2561 = BashPrgHash<U32, U1>;
/// bash-prg-hash with ℓ = 256 and d = 2
pub type BashPrgHash2562 = BashPrgHash<U32, U2>;
