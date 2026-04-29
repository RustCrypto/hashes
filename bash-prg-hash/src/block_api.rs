use crate::variants::{Capacity, SecurityLevel};
use bash_f::{STATE_WORDS, bash_f};
use core::{fmt, marker::PhantomData};
use digest::{
    CustomizedInit, block_api::AlgorithmName, block_api::BlockSizeUser, typenum::Unsigned,
};

/// Data type codes from Table 3 of STB 34.101.77-2020
const DATA: u8 = 0b000010;
/// Data type codes from Table 3 of STB 34.101.77-2020
const OUT: u8 = 0b000100;

/// bash-prg-hash hasher state generic over security level and capacity.
///
/// Specified in Section 8.12 of STB 34.101.77-2020.
pub struct BashPrgHashState<L: SecurityLevel, D: Capacity> {
    state: [u64; STATE_WORDS],
    /// current offset in bytes
    offset: usize,
    _pd: PhantomData<(L, D)>,
}

macro_rules! impl_block_sizes {
    ($($level:ty, $cap:ty),* $(,)?) => {
        $(
            impl BlockSizeUser for BashPrgHashState<$level, $cap> {
                type BlockSize = digest::typenum::U<{
                    (1536 - 2 * <$cap as Unsigned>::USIZE * <$level as Unsigned>::USIZE) / 8
                }>;
            }
        )*
    };
}

impl_block_sizes! {
    digest::typenum::U128, digest::typenum::U1,
    digest::typenum::U192, digest::typenum::U1,
    digest::typenum::U256, digest::typenum::U1,
    digest::typenum::U128, digest::typenum::U2,
    digest::typenum::U192, digest::typenum::U2,
    digest::typenum::U256, digest::typenum::U2,
}

impl<L: SecurityLevel, D: Capacity> CustomizedInit for BashPrgHashState<L, D> {
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

        let mut state = Self {
            state: [0u64; STATE_WORDS],
            offset: 0,
            _pd: PhantomData,
        };

        // Immediately consume header during initialization
        state.start(header);
        state.commit(DATA);
        state
    }
}

impl<L: SecurityLevel, D: Capacity> BashPrgHashState<L, D> {
    /// Calculate buffer size r = 1536 - 2dℓ (in bytes)
    const fn rate_bytes() -> usize {
        (1536 - 2 * D::USIZE * L::USIZE) / 8
    }

    /// Helper: modify byte at position in state
    fn modify_byte<F: FnOnce(&mut u8)>(&mut self, pos: usize, f: F) {
        let word_idx = pos / 8;
        let byte_in_word = pos % 8;
        let mut bytes = self.state[word_idx].to_le_bytes();
        f(&mut bytes[byte_in_word]);
        self.state[word_idx] = u64::from_le_bytes(bytes);
    }

    /// Helper: get byte at position in state
    fn get_byte(&self, pos: usize) -> u8 {
        let word_idx = pos / 8;
        let byte_in_word = pos % 8;
        self.state[word_idx].to_le_bytes()[byte_in_word]
    }

    /// XOR input bytes into state at current offset
    fn xor_in(&mut self, input: &[u8]) {
        for (i, &byte) in input.iter().enumerate() {
            self.modify_byte(self.offset + i, |b| *b ^= byte);
        }
        self.offset += input.len();
    }

    /// Extract bytes from state at current offset
    fn extract_bytes(&mut self, output: &mut [u8]) {
        for (i, out_byte) in output.iter_mut().enumerate() {
            *out_byte = self.get_byte(self.offset + i);
        }
        self.offset += output.len();
    }

    /// Execute start command (Section 8.3)
    fn start(&mut self, header: &[u8]) {
        let header_len = header.len();

        // Step 3: pos ← 8 + |A| + |K| (in bits) = 1 + header_len (in bytes)
        self.offset = 1 + header_len;

        // Step 4: S[...pos) ← ⟨|A|/2 + |K|/32⟩_8 || A || K
        // First byte: |A|/2 where |A| is in bits
        let first_byte = ((header_len * 8) / 2) as u8;
        self.modify_byte(0, |b| *b = first_byte);

        // Copy header bytes
        for (i, &byte) in header.iter().enumerate() {
            self.modify_byte(1 + i, |b| *b = byte);
        }

        // Step 6: S[1472...) ← ⟨ℓ/4 + d⟩_64
        self.state[23] = (L::USIZE / 4 + D::USIZE) as u64;
    }

    /// Execute commit command (Section 8.4)
    fn commit(&mut self, t: u8) {
        // Step 1: S[pos...pos+8) ← S[pos...pos+8) ⊕ (t||01)
        let tag = (t << 2) | 0x01;
        self.modify_byte(self.offset, |b| *b ^= tag);

        // Step 2: S[r] ← S[r] ⊕ 1 (flip bit at position r in bits)
        let r_bit_in_byte = (Self::rate_bytes() * 8) % 8;
        // MSB-first within a byte: bit index i maps to (7 - i)
        self.modify_byte(Self::rate_bytes(), |b| *b ^= 1u8 << (7 - r_bit_in_byte));

        // Step 3: S ← bash-f(S)
        bash_f(&mut self.state);

        // Step 4: pos ← 0
        self.offset = 0;
    }

    /// Execute absorb command (Section 8.6)
    pub(crate) fn absorb(&mut self, data: &[u8]) {
        // Steps 2-3: Process blocks
        let mut input = data;

        while !input.is_empty() {
            let to_absorb = input.len().min(Self::rate_bytes() - self.offset);

            self.xor_in(&input[..to_absorb]);
            input = &input[to_absorb..];

            if self.offset == Self::rate_bytes() {
                bash_f(&mut self.state);
                self.offset = 0;
            }
        }
    }

    /// Prepare for reading output (squeeze)
    pub(crate) fn finalize(&mut self) {
        self.commit(OUT);
    }

    /// Execute squeeze command (Section 8.7)
    pub(crate) fn squeeze(&mut self, output: &mut [u8]) {
        let mut remaining = output;

        while !remaining.is_empty() {
            if self.offset == Self::rate_bytes() {
                bash_f(&mut self.state);
                self.offset = 0;
            }

            let to_squeeze = remaining.len().min(Self::rate_bytes() - self.offset);
            self.extract_bytes(&mut remaining[..to_squeeze]);
            remaining = &mut remaining[to_squeeze..];
        }
    }
}

impl<L: SecurityLevel, D: Capacity> Clone for BashPrgHashState<L, D> {
    fn clone(&self) -> Self {
        Self {
            state: self.state,
            offset: self.offset,
            _pd: PhantomData,
        }
    }
}

impl<L: SecurityLevel, D: Capacity> Default for BashPrgHashState<L, D> {
    fn default() -> Self {
        Self::new_customized(&[])
    }
}

impl<L: SecurityLevel, D: Capacity> AlgorithmName for BashPrgHashState<L, D> {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BashPrgHash{}-{}", L::USIZE, D::USIZE)
    }
}

impl<L: SecurityLevel, D: Capacity> fmt::Debug for BashPrgHashState<L, D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BashPrgHashState { ... }")
    }
}

impl<L: SecurityLevel, D: Capacity> Drop for BashPrgHashState<L, D> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use digest::zeroize::Zeroize;
            self.state.zeroize();
        }
    }
}

#[cfg(feature = "zeroize")]
impl<L: SecurityLevel, D: Capacity> digest::zeroize::ZeroizeOnDrop for BashPrgHashState<L, D> {}
