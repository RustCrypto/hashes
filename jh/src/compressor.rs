use digest::array::{Array, typenum::U64};

#[cfg(feature = "zeroize")]
use digest::zeroize::Zeroize;

#[rustfmt::skip]
macro_rules! unroll7 {
    ($j:ident, $body:block) => {
        { const $j: usize = 0; $body }
        { const $j: usize = 1; $body }
        { const $j: usize = 2; $body }
        { const $j: usize = 3; $body }
        { const $j: usize = 4; $body }
        { const $j: usize = 5; $body }
        { const $j: usize = 6; $body }
    };
}

#[inline(always)]
fn read_word(bytes: &[u8], index: usize) -> u128 {
    let mut word = [0u8; 16];
    word.copy_from_slice(&bytes[16 * index..16 * (index + 1)]);
    u128::from_ne_bytes(word)
}

/// Computes one S-box selected by a round constant bit.
#[cfg(any(not(target_arch = "x86_64"), miri, test))]
#[inline(always)]
fn sbox(
    mut x0: u128,
    mut x1: u128,
    mut x2: u128,
    mut x3: u128,
    mut round_constant: u128,
) -> (u128, u128, u128, u128) {
    x3 = !x3;
    x0 ^= !x2 & round_constant;
    round_constant ^= x0 & x1;
    x0 ^= x3 & x2;
    x3 ^= !x1 & x2;
    x1 ^= x0 & x2;
    x2 ^= !x3 & x0;
    x0 ^= x1 | x3;
    x3 ^= x1 & x2;
    x2 ^= round_constant;
    x1 ^= round_constant & x0;
    (x0, x1, x2, x3)
}

#[cfg(any(not(target_arch = "x86_64"), miri, test))]
#[inline(always)]
fn linear(mut state: [u128; 8]) -> [u128; 8] {
    state[1] ^= state[2];
    state[3] ^= state[4];
    state[5] ^= state[6] ^ state[0];
    state[7] ^= state[0];
    state[0] ^= state[3];
    state[2] ^= state[5];
    state[4] ^= state[7] ^ state[1];
    state[6] ^= state[1];
    state
}

#[cfg(any(not(target_arch = "x86_64"), miri, test))]
#[inline(always)]
fn swap_bits(word: u128, shift: u32) -> u128 {
    let mask = match shift {
        1 => 0x55555555555555555555555555555555,
        2 => 0x33333333333333333333333333333333,
        4 => 0x0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f,
        8 => 0x00ff00ff00ff00ff00ff00ff00ff00ff,
        16 => 0x0000ffff0000ffff0000ffff0000ffff,
        32 => 0x00000000ffffffff00000000ffffffff,
        64 => 0x0000000000000000ffffffffffffffff,
        _ => unreachable!(),
    };
    ((word & mask) << shift) | ((word & !mask) >> shift)
}

#[cfg(any(not(target_arch = "x86_64"), miri, test))]
#[inline]
fn compress(state: &mut [u128; 8], data: &Array<u8, U64>) {
    let mut words = *state;
    for (i, word) in words[..4].iter_mut().enumerate() {
        *word ^= read_word(data, i);
    }

    for constants in crate::consts::E8_BITSLICE_ROUNDCONSTANT.chunks_exact(7) {
        unroll7!(J, {
            let even = sbox(
                words[0],
                words[2],
                words[4],
                words[6],
                read_word(&constants[J], 0),
            );
            let odd = sbox(
                words[1],
                words[3],
                words[5],
                words[7],
                read_word(&constants[J], 1),
            );
            words = [even.0, odd.0, even.1, odd.1, even.2, odd.2, even.3, odd.3];
            words = linear(words);
            words[1] = swap_bits(words[1], 1 << J);
            words[3] = swap_bits(words[3], 1 << J);
            words[5] = swap_bits(words[5], 1 << J);
            words[7] = swap_bits(words[7], 1 << J);
        });
    }

    for (i, word) in words[4..].iter_mut().enumerate() {
        *word ^= read_word(data, i);
    }
    *state = words;
}

#[cfg(all(target_arch = "x86_64", not(miri)))]
mod x86_64 {
    use super::*;
    use core::arch::x86_64::*;

    #[inline(always)]
    fn sbox(
        mut x0: __m128i,
        mut x1: __m128i,
        mut x2: __m128i,
        mut x3: __m128i,
        mut round_constant: __m128i,
    ) -> (__m128i, __m128i, __m128i, __m128i) {
        // SSE2 is part of the x86_64 architecture baseline.
        unsafe {
            x3 = _mm_xor_si128(x3, _mm_set1_epi32(-1));
            x0 = _mm_xor_si128(x0, _mm_andnot_si128(x2, round_constant));
            round_constant = _mm_xor_si128(round_constant, _mm_and_si128(x0, x1));
            x0 = _mm_xor_si128(x0, _mm_and_si128(x3, x2));
            x3 = _mm_xor_si128(x3, _mm_andnot_si128(x1, x2));
            x1 = _mm_xor_si128(x1, _mm_and_si128(x0, x2));
            x2 = _mm_xor_si128(x2, _mm_andnot_si128(x3, x0));
            x0 = _mm_xor_si128(x0, _mm_or_si128(x1, x3));
            x3 = _mm_xor_si128(x3, _mm_and_si128(x1, x2));
            x2 = _mm_xor_si128(x2, round_constant);
            x1 = _mm_xor_si128(x1, _mm_and_si128(round_constant, x0));
            (x0, x1, x2, x3)
        }
    }

    #[inline(always)]
    fn linear(mut state: [__m128i; 8]) -> [__m128i; 8] {
        unsafe {
            state[1] = _mm_xor_si128(state[1], state[2]);
            state[3] = _mm_xor_si128(state[3], state[4]);
            state[5] = _mm_xor_si128(state[5], _mm_xor_si128(state[6], state[0]));
            state[7] = _mm_xor_si128(state[7], state[0]);
            state[0] = _mm_xor_si128(state[0], state[3]);
            state[2] = _mm_xor_si128(state[2], state[5]);
            state[4] = _mm_xor_si128(state[4], _mm_xor_si128(state[7], state[1]));
            state[6] = _mm_xor_si128(state[6], state[1]);
            state
        }
    }

    macro_rules! swap_small {
        ($word:expr, $shift:literal, $mask:literal) => {{
            let mask = _mm_set1_epi8($mask as i8);
            _mm_or_si128(
                _mm_srli_epi16::<$shift>(_mm_and_si128($word, mask)),
                _mm_and_si128(_mm_slli_epi16::<$shift>($word), mask),
            )
        }};
    }

    #[inline(always)]
    fn swap_bits(word: __m128i, shift: u32) -> __m128i {
        unsafe {
            match shift {
                1 => swap_small!(word, 1, 0xaau8),
                2 => swap_small!(word, 2, 0xccu8),
                4 => swap_small!(word, 4, 0xf0u8),
                8 => _mm_or_si128(_mm_slli_epi16::<8>(word), _mm_srli_epi16::<8>(word)),
                16 => _mm_shufflehi_epi16::<0b1011_0001>(_mm_shufflelo_epi16::<0b1011_0001>(word)),
                32 => _mm_shuffle_epi32::<0b1011_0001>(word),
                64 => _mm_shuffle_epi32::<0b0100_1110>(word),
                _ => unreachable!(),
            }
        }
    }

    #[inline]
    pub(super) fn compress(state: &mut [u128; 8], data: &Array<u8, U64>) {
        unsafe {
            let state_ptr = state.as_mut_ptr().cast::<__m128i>();
            let data_ptr = data.as_ptr().cast::<__m128i>();
            let mut words = [
                _mm_loadu_si128(state_ptr),
                _mm_loadu_si128(state_ptr.add(1)),
                _mm_loadu_si128(state_ptr.add(2)),
                _mm_loadu_si128(state_ptr.add(3)),
                _mm_loadu_si128(state_ptr.add(4)),
                _mm_loadu_si128(state_ptr.add(5)),
                _mm_loadu_si128(state_ptr.add(6)),
                _mm_loadu_si128(state_ptr.add(7)),
            ];
            words[0] = _mm_xor_si128(words[0], _mm_loadu_si128(data_ptr));
            words[1] = _mm_xor_si128(words[1], _mm_loadu_si128(data_ptr.add(1)));
            words[2] = _mm_xor_si128(words[2], _mm_loadu_si128(data_ptr.add(2)));
            words[3] = _mm_xor_si128(words[3], _mm_loadu_si128(data_ptr.add(3)));

            for constants in crate::consts::E8_BITSLICE_ROUNDCONSTANT.chunks_exact(7) {
                unroll7!(J, {
                    let constant_ptr = constants[J].as_ptr().cast::<__m128i>();
                    let even = sbox(
                        words[0],
                        words[2],
                        words[4],
                        words[6],
                        _mm_loadu_si128(constant_ptr),
                    );
                    let odd = sbox(
                        words[1],
                        words[3],
                        words[5],
                        words[7],
                        _mm_loadu_si128(constant_ptr.add(1)),
                    );
                    words = [even.0, odd.0, even.1, odd.1, even.2, odd.2, even.3, odd.3];
                    words = linear(words);
                    words[1] = swap_bits(words[1], 1 << J);
                    words[3] = swap_bits(words[3], 1 << J);
                    words[5] = swap_bits(words[5], 1 << J);
                    words[7] = swap_bits(words[7], 1 << J);
                });
            }

            words[4] = _mm_xor_si128(words[4], _mm_loadu_si128(data_ptr));
            words[5] = _mm_xor_si128(words[5], _mm_loadu_si128(data_ptr.add(1)));
            words[6] = _mm_xor_si128(words[6], _mm_loadu_si128(data_ptr.add(2)));
            words[7] = _mm_xor_si128(words[7], _mm_loadu_si128(data_ptr.add(3)));
            for (i, word) in words.iter().enumerate() {
                _mm_storeu_si128(state_ptr.add(i), *word);
            }
        }
    }
}

#[derive(Clone)]
pub(crate) struct Compressor {
    state: [u128; 8],
}

impl Compressor {
    #[inline]
    pub(crate) fn new(bytes: [u8; 128]) -> Self {
        Self {
            state: core::array::from_fn(|i| read_word(&bytes, i)),
        }
    }

    #[inline]
    pub(crate) fn update(&mut self, data: &Array<u8, U64>) {
        #[cfg(all(target_arch = "x86_64", not(miri)))]
        x86_64::compress(&mut self.state, data);
        #[cfg(any(not(target_arch = "x86_64"), miri))]
        compress(&mut self.state, data);
    }

    #[inline]
    fn write_words(words: &[u128], bytes: &mut [u8]) {
        assert_eq!(bytes.len(), 16 * words.len());
        for (word, chunk) in words.iter().zip(bytes.chunks_exact_mut(16)) {
            chunk.copy_from_slice(&word.to_ne_bytes());
        }
    }

    #[inline]
    pub(crate) fn write_digest(&self, out: &mut [u8]) {
        Self::write_words(&self.state[4..], out);
    }

    #[inline]
    pub(crate) fn write_state(&self, out: &mut [u8]) {
        Self::write_words(&self.state, out);
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for Compressor {
    fn zeroize(&mut self) {
        self.state.zeroize();
    }
}

#[cfg(all(test, target_arch = "x86_64", not(miri)))]
mod tests {
    use super::*;

    #[test]
    fn portable_matches_x86_64() {
        let mut seed = 0x243f6a8885a308d3u64;

        for _ in 0..16 {
            let mut next = || {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                seed
            };
            let state = core::array::from_fn(|_| {
                let lo = next() as u128;
                let hi = next() as u128;
                lo | (hi << 64)
            });
            let data = Array::from_fn(|_| next() as u8);

            let mut portable = state;
            compress(&mut portable, &data);
            let mut accelerated = state;
            x86_64::compress(&mut accelerated, &data);

            assert_eq!(portable, accelerated);
        }
    }
}
