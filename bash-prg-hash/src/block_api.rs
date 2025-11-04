use bash_f::{STATE_WORDS, bash_f};
use core::{fmt, marker::PhantomData};
use digest::block_api::BlockSizeUser;
use digest::core_api::AlgorithmName;

use crate::variants::{Cap1, Cap2, Capacity, Level128, Level192, Level256, SecurityLevel};

/// A constant representing the maximum size of a header in bytes.
pub const MAX_HEADER_LEN: usize = 60;

/// Data type codes from Table 3 of STB 34.101.77-2020
const DATA: u8 = 0b000010;
/// Data type codes from Table 3 of STB 34.101.77-2020
const OUT: u8 = 0b000100;

/// Core bash-prg-hash hasher state generic over security level and capacity.
///
/// Specified in Section 8.12 of STB 34.101.77-2020.
pub struct BashPrgHashCore<L: SecurityLevel, D: Capacity> {
    state: [u64; STATE_WORDS],
    rate_bytes: usize,            // r/8 - buffer size in bytes
    offset: usize,                // current offset in bytes
    header: [u8; MAX_HEADER_LEN], // max header size (480 bits = 60 bytes)
    header_len: usize,            // header length in bytes
    data_committed: bool,         // whether commit(DATA) was called in
    _level: PhantomData<L>,
    _capacity: PhantomData<D>,
}

macro_rules! impl_block_sizes {
    ($($level:ty, $cap:ty),* $(,)?) => {
        $(
            impl BlockSizeUser for BashPrgHashCore<$level, $cap> {
                type BlockSize = digest::typenum::U<{
                    (1536 - 2 * <$cap as Capacity>::CAPACITY * <$level as SecurityLevel>::LEVEL) / 8
                }>;
            }
        )*
    };
}

impl_block_sizes! {
    Level128, Cap1,
    Level192, Cap1,
    Level256, Cap1,
    Level128, Cap2,
    Level192, Cap2,
    Level256, Cap2,
}

impl<L: SecurityLevel, D: Capacity> BashPrgHashCore<L, D> {
    /// Calculate buffer size r = 1536 - 2dℓ (in bytes)
    const fn calculate_rate_bytes() -> usize {
        (1536 - 2 * D::CAPACITY * L::LEVEL) / 8
    }

    /// Create a new hasher with an announcement (header).
    pub fn new(header: &[u8]) -> Self {
        assert!(
            header.len() <= MAX_HEADER_LEN,
            "Header length must not exceed 480 bits (60 bytes)"
        );
        assert_eq!(
            header.len() % 4,
            0,
            "Header length must be multiple of 32 bits (4 bytes)"
        );

        let mut header_buf = [0u8; 60];
        header_buf[..header.len()].copy_from_slice(header);

        Self {
            state: [0u64; STATE_WORDS],
            rate_bytes: Self::calculate_rate_bytes(),
            offset: 0,
            header: header_buf,
            header_len: header.len(),
            data_committed: false,
            _level: PhantomData,
            _capacity: PhantomData,
        }
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
    fn start(&mut self) {
        // Step 3: pos ← 8 + |A| + |K| (in bits) = 1 + header_len (in bytes)
        let header_len = self.header_len;
        self.offset = 1 + header_len;

        // Step 4: S[...pos) ← ⟨|A|/2 + |K|/32⟩_8 || A || K
        // First byte: |A|/2 where |A| is in bits
        let first_byte = ((header_len * 8) / 2) as u8;
        self.modify_byte(0, |b| *b = first_byte);

        // Copy header bytes
        for i in 0..header_len {
            let byte = self.header[i];
            self.modify_byte(1 + i, |b| *b = byte);
        }

        // Step 6: S[1472...) ← ⟨ℓ/4 + d⟩_64
        self.state[23] = (L::LEVEL / 4 + D::CAPACITY) as u64;
    }

    /// Execute commit command (Section 8.4)
    fn commit(&mut self, t: u8) {
        // Step 1: S[pos...pos+8) ← S[pos...pos+8) ⊕ (t||01)
        let tag = (t << 2) | 0x01;
        self.modify_byte(self.offset, |b| *b ^= tag);

        // Step 2: S[r] ← S[r] ⊕ 1 (flip bit at position r in bits)
        let r_bit_in_byte = (self.rate_bytes * 8) % 8;
        // MSB-first within a byte: bit index i maps to (7 - i)
        self.modify_byte(self.rate_bytes, |b| *b ^= 1u8 << (7 - r_bit_in_byte));

        // Step 3: S ← bash-f(S)
        bash_f(&mut self.state);

        // Step 4: pos ← 0
        self.offset = 0;
    }

    /// Execute absorb command (Section 8.6)
    pub(crate) fn absorb(&mut self, data: &[u8]) {
        // Check if initialized: state[23] == 0 means not initialized
        if self.state[23] == 0 {
            self.start();
        }

        // Step 1: commit(DATA) - only once per absorption session
        // We need data_committed because offset == 0 can happen multiple times:
        // - After finalize() (need commit(DATA))
        // - After commit(DATA) but before absorbing (already did commit)
        // - After full block during absorption (offset resets to 0)
        // - After empty data calls (offset stays 0)
        if !self.data_committed {
            self.commit(DATA);
            self.data_committed = true;
        }

        // Steps 2-3: Process blocks
        let mut input = data;

        while !input.is_empty() {
            let to_absorb = input.len().min(self.rate_bytes - self.offset);

            self.xor_in(&input[..to_absorb]);
            input = &input[to_absorb..];

            if self.offset == self.rate_bytes {
                bash_f(&mut self.state);
                self.offset = 0;
            }
        }
    }

    /// Prepare for reading output (squeeze)
    pub(crate) fn finalize(&mut self) {
        if self.state[23] == 0 {
            self.start();
        }

        self.commit(OUT);
        self.data_committed = false; // Reset for next absorption session
    }

    /// Execute squeeze command (Section 8.7)
    pub(crate) fn squeeze(&mut self, output: &mut [u8]) {
        let mut remaining = output;

        while !remaining.is_empty() {
            if self.offset == self.rate_bytes {
                bash_f(&mut self.state);
                self.offset = 0;
            }

            let to_squeeze = remaining.len().min(self.rate_bytes - self.offset);
            self.extract_bytes(&mut remaining[..to_squeeze]);
            remaining = &mut remaining[to_squeeze..];
        }
    }
}

impl<L: SecurityLevel, D: Capacity> Clone for BashPrgHashCore<L, D> {
    fn clone(&self) -> Self {
        Self {
            state: self.state,
            rate_bytes: self.rate_bytes,
            offset: self.offset,
            header: self.header,
            header_len: self.header_len,
            data_committed: self.data_committed,
            _level: PhantomData,
            _capacity: PhantomData,
        }
    }
}

impl<L: SecurityLevel, D: Capacity> Default for BashPrgHashCore<L, D> {
    fn default() -> Self {
        Self::new(&[])
    }
}

impl<L: SecurityLevel, D: Capacity> AlgorithmName for BashPrgHashCore<L, D> {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BashPrgHash{}-{}", L::LEVEL, D::CAPACITY)
    }
}

impl<L: SecurityLevel, D: Capacity> fmt::Debug for BashPrgHashCore<L, D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BashPrgHashCore { ... }")
    }
}

impl<L: SecurityLevel, D: Capacity> Drop for BashPrgHashCore<L, D> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use digest::zeroize::Zeroize;
            self.state.zeroize();
        }
    }
}

#[cfg(feature = "zeroize")]
impl<L: SecurityLevel, D: Capacity> digest::zeroize::ZeroizeOnDrop for BashPrgHashCore<L, D> {}
