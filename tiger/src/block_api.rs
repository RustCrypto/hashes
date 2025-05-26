use crate::compress::compress;
use core::fmt;
use digest::{
    HashMarker, Output,
    block_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, Eager, FixedOutputCore,
        OutputSizeUser, Reset, UpdateCore,
    },
    crypto_common::hazmat::{DeserializeStateError, SerializableState, SerializedState},
    typenum::{U24, U32, U64, Unsigned},
};

type State = [u64; STATE_LEN];
const STATE_LEN: usize = 3;
const S0: State = [
    0x0123_4567_89AB_CDEF,
    0xFEDC_BA98_7654_3210,
    0xF096_A5B4_C3B2_E187,
];

/// Core Tiger hasher state.
#[derive(Clone)]
pub struct TigerCore<const V2: bool = true> {
    block_len: u64,
    state: State,
}

impl<const V2: bool> HashMarker for TigerCore<V2> {}

impl<const V2: bool> BlockSizeUser for TigerCore<V2> {
    type BlockSize = U64;
}

impl<const V2: bool> BufferKindUser for TigerCore<V2> {
    type BufferKind = Eager;
}

impl<const V2: bool> OutputSizeUser for TigerCore<V2> {
    type OutputSize = U24;
}

impl<const V2: bool> UpdateCore for TigerCore<V2> {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.block_len += blocks.len() as u64;
        for block in blocks {
            compress(&mut self.state, block.as_ref());
        }
    }
}

impl<const V2: bool> FixedOutputCore for TigerCore<V2> {
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let bs = Self::BlockSize::U64;
        let pos = buffer.get_pos() as u64;
        let bit_len = 8 * (pos + bs * self.block_len);

        if V2 {
            buffer.len64_padding_le(bit_len, |b| compress(&mut self.state, b.as_ref()));
        } else {
            buffer.digest_pad(1, &bit_len.to_le_bytes(), |b| {
                compress(&mut self.state, b.as_ref())
            });
        }

        for (chunk, v) in out.chunks_exact_mut(8).zip(self.state.iter()) {
            chunk.copy_from_slice(&v.to_le_bytes());
        }
    }
}

impl<const V2: bool> Default for TigerCore<V2> {
    #[inline]
    fn default() -> Self {
        Self {
            block_len: 0,
            state: S0,
        }
    }
}

impl<const V2: bool> Reset for TigerCore<V2> {
    #[inline]
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl<const V2: bool> SerializableState for TigerCore<V2> {
    type SerializedStateSize = U32;

    fn serialize(&self) -> SerializedState<Self> {
        let mut serialized_state = SerializedState::<Self>::default();

        for (val, chunk) in self.state.iter().zip(serialized_state.chunks_exact_mut(8)) {
            chunk.copy_from_slice(&val.to_le_bytes());
        }

        serialized_state[24..].copy_from_slice(&self.block_len.to_le_bytes());
        serialized_state
    }

    fn deserialize(
        serialized_state: &SerializedState<Self>,
    ) -> Result<Self, DeserializeStateError> {
        let (serialized_state, serialized_block_len) = serialized_state.split::<U24>();

        let mut state = [0; STATE_LEN];
        for (val, chunk) in state.iter_mut().zip(serialized_state.chunks_exact(8)) {
            *val = u64::from_le_bytes(chunk.try_into().unwrap());
        }

        let block_len = u64::from_le_bytes(*serialized_block_len.as_ref());

        Ok(Self { state, block_len })
    }
}

impl<const V2: bool> AlgorithmName for TigerCore<V2> {
    #[inline]
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if V2 {
            f.write_str("Tiger2")
        } else {
            f.write_str("Tiger")
        }
    }
}

impl<const V2: bool> fmt::Debug for TigerCore<V2> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if V2 {
            f.write_str("Tiger2Core { ... }")
        } else {
            f.write_str("TigerCore { ... }")
        }
    }
}

impl<const V2: bool> Drop for TigerCore<V2> {
    #[inline]
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use digest::zeroize::Zeroize;
            self.state.zeroize();
            self.block_len.zeroize();
        }
    }
}

#[cfg(feature = "zeroize")]
impl<const V2: bool> digest::zeroize::ZeroizeOnDrop for TigerCore<V2> {}
