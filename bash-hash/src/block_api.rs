use core::fmt;
use digest::{
    HashMarker, Output,
    array::Array,
    block_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, Eager, FixedOutputCore,
        OutputSizeUser, Reset, UpdateCore,
    },
    crypto_common::hazmat::{DeserializeStateError, SerializableState, SerializedState},
    typenum::U192,
};

use crate::variants::{Bash256, Bash384, Bash512, Variant};
use bash_f::{STATE_WORDS, bash_f};
use digest::typenum::Unsigned;

/// Core Bash hasher state with generic security level.
///
/// Implements bash-hash[ℓ] algorithm according to section 7 of STB 34.101.77-2020.
/// Parameters:
/// - BlockSize: block size r = (1536 - 4ℓ) / 8 bytes
/// - OutputSize: output size 2ℓ / 8 bytes
#[derive(Clone)]
pub struct BashHashCore<V: Variant> {
    state: [u64; STATE_WORDS],
    _variant: core::marker::PhantomData<V>,
}

impl<V> BashHashCore<V>
where
    V: Variant,
{
    /// Calculate security level ℓ
    ///
    /// According to section 5.3: ℓ = OutputSize * 8 / 2 = OutputSize * 4
    #[inline]
    const fn get_level() -> usize {
        // 3. ℓ ← OutSize * 8 / 2
        V::OutputSize::USIZE * 4
    }

    /// Calculate buffer size r in bytes
    #[inline]
    const fn get_r_bytes() -> usize {
        V::BlockSize::USIZE
    }

    /// Compress one data block
    fn compress_block(&mut self, block: &Block<Self>) {
        let r_bytes = Self::get_r_bytes();
        debug_assert_eq!(r_bytes % 8, 0);

        // 4.1: S[...1536 - 4ℓ) ← Xi
        for (dst, chunk) in self.state.iter_mut().zip(block[..r_bytes].chunks_exact(8)) {
            // `chunk` is guaranteed to be 8 bytes long due to `r_bytes` being a multiple of 8
            *dst = u64::from_le_bytes(chunk.try_into().unwrap());
        }

        // 4.2: S ← bash-f(S)
        bash_f(&mut self.state);
    }
}

impl<V> HashMarker for BashHashCore<V> where V: Variant {}

impl<V> BlockSizeUser for BashHashCore<V>
where
    V: Variant,
{
    type BlockSize = V::BlockSize;
}

impl<V> BufferKindUser for BashHashCore<V>
where
    V: Variant,
{
    type BufferKind = Eager;
}

impl<V> OutputSizeUser for BashHashCore<V>
where
    V: Variant,
{
    type OutputSize = V::OutputSize;
}

impl<V> UpdateCore for BashHashCore<V>
where
    V: Variant,
{
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        for block in blocks {
            self.compress_block(block);
        }
    }
}

impl<V> FixedOutputCore for BashHashCore<V>
where
    V: Variant,
{
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let pos = buffer.get_pos();

        // 1. Split(X || 01, r) - split message with appended 01
        // 2: Xn ← Xn || 0^(1536-4ℓ-|Xn|) - pad last block with zeros
        let mut padding_block = Array::<u8, V::BlockSize>::default();
        let block = buffer.pad_with_zeros();
        padding_block.copy_from_slice(&block);
        padding_block[pos] = 0x40;

        // 4. for i = 1, 2, ..., n, do:
        self.compress_block(&padding_block);

        //5. Y ← S[...2ℓ)
        self.state
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .take(V::OutputSize::USIZE)
            .zip(out.iter_mut())
            .for_each(|(src, dst)| *dst = src);
    }
}

impl<V> Default for BashHashCore<V>
where
    V: Variant,
{
    #[inline]
    fn default() -> Self {
        let mut state = [0u64; STATE_WORDS];

        // 3. S ← 0^1472 || ⟨ℓ/4⟩_64
        let level = Self::get_level();
        state[23] = (level / 4) as u64;

        Self {
            state,
            _variant: core::marker::PhantomData,
        }
    }
}

impl<V> Reset for BashHashCore<V>
where
    V: Variant,
{
    #[inline]
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl<V> AlgorithmName for BashHashCore<V>
where
    V: Variant,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let level = Self::get_level();
        write!(f, "Bash{}", level * 2)
    }
}

impl<V> fmt::Debug for BashHashCore<V>
where
    V: Variant,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BashHashCore { ... }")
    }
}

impl<V> Drop for BashHashCore<V>
where
    V: Variant,
{
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use digest::zeroize::Zeroize;
            self.state.zeroize();
        }
    }
}

#[cfg(feature = "zeroize")]
impl<V> digest::zeroize::ZeroizeOnDrop for BashHashCore<V> where V: Variant {}

impl<V> SerializableState for BashHashCore<V>
where
    V: Variant,
{
    type SerializedStateSize = U192;

    fn serialize(&self) -> SerializedState<Self> {
        let mut dst = SerializedState::<Self>::default();

        for (word, chunk) in self.state.iter().zip(dst.chunks_exact_mut(8)) {
            // `word` is guaranteed to be 8 bytes long due to `STATE_WORDS` being a multiple of 8
            // and `chunk` being a slice of 8 bytes
            chunk.copy_from_slice(&word.to_le_bytes());
        }

        dst
    }

    fn deserialize(
        serialized_state: &SerializedState<Self>,
    ) -> Result<Self, DeserializeStateError> {
        let mut state = [0u64; STATE_WORDS];

        for (dst, chunk) in state.iter_mut().zip(serialized_state.chunks_exact(8)) {
            // `chunk` is guaranteed to be 8 bytes long due to `STATE_WORDS` being a multiple of 8
            // and `dst` being a slice of 8 bytes
            *dst = u64::from_le_bytes(chunk.try_into().map_err(|_| DeserializeStateError)?);
        }

        Ok(Self {
            state,
            _variant: core::marker::PhantomData,
        })
    }
}

// Standard Bash hash variants according to section 5.3 and 7.1
// Bash256: ℓ = 128, output = 2ℓ = 256 bits, block = (1536 - 4×128)/8 = 128 bytes
// Bash384: ℓ = 192, output = 2ℓ = 384 bits, block = (1536 - 4×192)/8 = 96 bytes
// Bash512: ℓ = 256, output = 2ℓ = 512 bits, block = (1536 - 4×256)/8 = 64 bytes
pub(crate) type Bash256Core = BashHashCore<Bash256>;
pub(crate) type Bash384Core = BashHashCore<Bash384>;
pub(crate) type Bash512Core = BashHashCore<Bash512>;
