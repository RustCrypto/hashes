use core::{fmt, marker::PhantomData};
use digest::{
    HashMarker, Output,
    block_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, Eager, FixedOutputCore,
        OutputSizeUser, Reset, UpdateCore,
    },
    crypto_common::hazmat::{DeserializeStateError, SerializableState, SerializedState},
    typenum::U192,
};

use crate::OutputSize;
use bash_f::{STATE_WORDS, bash_f};

/// Core `bash-hash` hasher generic over output size.
///
/// Specified in Section 7 of STB 34.101.77-2020.
pub struct BashHashCore<OS: OutputSize> {
    state: [u64; STATE_WORDS],
    _pd: PhantomData<OS>,
}

impl<OS: OutputSize> Clone for BashHashCore<OS> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            state: self.state,
            _pd: PhantomData,
        }
    }
}

impl<OS: OutputSize> BashHashCore<OS> {
    /// Compress one data block
    fn compress_block(&mut self, block: &Block<Self>) {
        // 4.1: S[...1536 - 4ℓ) ← Xi
        // TODO: use `as_chunks` after MSRV is bumped to 1.88+
        for (dst, chunk) in self.state.iter_mut().zip(block.chunks_exact(8)) {
            // `chunk` is guaranteed to be 8 bytes long due to `r_bytes` being a multiple of 8
            *dst = u64::from_le_bytes(chunk.try_into().unwrap());
        }

        // 4.2: S ← bash-f(S)
        bash_f(&mut self.state);
    }
}

impl<OS: OutputSize> HashMarker for BashHashCore<OS> {}

impl<OS: OutputSize> BlockSizeUser for BashHashCore<OS> {
    type BlockSize = OS::BlockSize;
}

impl<OS: OutputSize> BufferKindUser for BashHashCore<OS> {
    type BufferKind = Eager;
}

impl<OS: OutputSize> OutputSizeUser for BashHashCore<OS> {
    type OutputSize = OS;
}

impl<OS: OutputSize> UpdateCore for BashHashCore<OS> {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        for block in blocks {
            self.compress_block(block);
        }
    }
}

impl<OS: OutputSize> FixedOutputCore for BashHashCore<OS> {
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        // 1. Split(X || 01, r) - split message with appended 01
        // 2: Xn ← Xn || 0^(1536-4ℓ-|Xn|) - pad last block with zeros
        let pos = buffer.get_pos();
        let mut block = buffer.pad_with_zeros();
        block[pos] = 0x40;

        // 4. for i = 1, 2, ..., n, do:
        self.compress_block(&block);

        // 5. Y ← S[...2ℓ)
        // TODO: use `as_chunks` after MSRV is bumped to 1.88+
        for (src, dst) in self.state.iter().zip(out.chunks_exact_mut(8)) {
            dst.copy_from_slice(&src.to_le_bytes());
        }
    }
}

impl<OS: OutputSize> Default for BashHashCore<OS> {
    #[inline]
    fn default() -> Self {
        let mut state = [0u64; STATE_WORDS];

        // 3. ℓ ← OutSize * 8 / 2
        let level = OS::USIZE * 4;
        // 3. S ← 0^1472 || ⟨ℓ/4⟩_64
        state[23] = (level / 4) as u64;

        Self {
            state,
            _pd: PhantomData,
        }
    }
}

impl<OS: OutputSize> Reset for BashHashCore<OS> {
    #[inline]
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl<OS: OutputSize> AlgorithmName for BashHashCore<OS> {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BashHash{}", OS::USIZE)
    }
}

impl<OS: OutputSize> fmt::Debug for BashHashCore<OS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BashHashCore { ... }")
    }
}

impl<OS: OutputSize> Drop for BashHashCore<OS> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use digest::zeroize::Zeroize;
            self.state.zeroize();
        }
    }
}

#[cfg(feature = "zeroize")]
impl<OS: OutputSize> digest::zeroize::ZeroizeOnDrop for BashHashCore<OS> {}

impl<OS: OutputSize> SerializableState for BashHashCore<OS> {
    type SerializedStateSize = U192;

    fn serialize(&self) -> SerializedState<Self> {
        let mut res = SerializedState::<Self>::default();
        // TODO: use `as_chunks` after MSRV is bumped to 1.88+
        for (src, dst) in self.state.iter().zip(res.chunks_exact_mut(8)) {
            dst.copy_from_slice(&src.to_le_bytes());
        }
        res
    }

    fn deserialize(
        serialized_state: &SerializedState<Self>,
    ) -> Result<Self, DeserializeStateError> {
        let mut state = [0u64; STATE_WORDS];
        // TODO: use `as_chunks` after MSRV is bumped to 1.88+
        for (src, dst) in serialized_state.chunks_exact(8).zip(state.iter_mut()) {
            *dst = u64::from_le_bytes(src.try_into().unwrap());
        }
        Ok(Self {
            state,
            _pd: PhantomData,
        })
    }
}
