use core::fmt;
use digest::{
    HashMarker, Output,
    array::Array,
    block_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, Eager, FixedOutputCore,
        OutputSizeUser, Reset, UpdateCore,
    },
    common::hazmat::{DeserializeStateError, SerializableState, SerializedState},
    consts::{U64, U72},
};

use crate::compress::compress;

const STATE_LEN: usize = 8;

/// Core Whirlpool hasher state.
#[derive(Clone)]
pub struct WhirlpoolCore {
    state: [u64; STATE_LEN],
    blocks_len: u64,
}

impl HashMarker for WhirlpoolCore {}

impl BlockSizeUser for WhirlpoolCore {
    type BlockSize = U64;
}

impl BufferKindUser for WhirlpoolCore {
    type BufferKind = Eager;
}

impl OutputSizeUser for WhirlpoolCore {
    type OutputSize = U64;
}

impl UpdateCore for WhirlpoolCore {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        // Technically, Whirlpool uses 256-bit counter for tracking
        // message length in bits, but it would take more than 100k years
        // of continuous computation to overflow 64-bit block counter,
        // so we use it instead.
        self.blocks_len += blocks.len() as u64;
        let blocks = Array::cast_slice_to_core(blocks);
        compress(&mut self.state, blocks);
    }
}

impl FixedOutputCore for WhirlpoolCore {
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let pos = buffer.get_pos();

        let block_size = Self::block_size() as u128;
        let byte_len = block_size * (self.blocks_len as u128) + (pos as u128);
        let bit_len = 8 * byte_len;

        let mut buf = [0u8; 32];
        buf[16..].copy_from_slice(&bit_len.to_be_bytes());

        let mut state = self.state;
        buffer.digest_pad(0x80, &buf, |block| {
            compress(&mut state, &[block.0]);
        });

        for (chunk, v) in out.chunks_exact_mut(8).zip(state.iter()) {
            chunk.copy_from_slice(&v.to_le_bytes());
        }
    }
}

// derivable impl does not inline
#[allow(clippy::derivable_impls)]
impl Default for WhirlpoolCore {
    #[inline]
    fn default() -> Self {
        Self {
            state: [0u64; 8],
            blocks_len: 0,
        }
    }
}

impl Reset for WhirlpoolCore {
    #[inline]
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl AlgorithmName for WhirlpoolCore {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Whirlpool")
    }
}

impl fmt::Debug for WhirlpoolCore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WhirlpoolCore { ... }")
    }
}

impl SerializableState for WhirlpoolCore {
    type SerializedStateSize = U72;

    fn serialize(&self) -> SerializedState<Self> {
        let mut res = Array::<_, U72>::default();

        let (state_dst, blocks_len_dst) = res.split_at_mut(64);

        for (val, chunk) in self.state.iter().zip(state_dst.chunks_exact_mut(8)) {
            chunk.copy_from_slice(&val.to_le_bytes());
        }
        blocks_len_dst.copy_from_slice(&self.blocks_len.to_le_bytes());

        res
    }

    fn deserialize(
        serialized_state: &SerializedState<Self>,
    ) -> Result<Self, DeserializeStateError> {
        let (state_src, blocks_len_src) = serialized_state.split_at(64);

        let mut state = [0; STATE_LEN];
        for (val, chunk) in state.iter_mut().zip(state_src.chunks_exact(8)) {
            *val = u64::from_le_bytes(chunk.try_into().unwrap());
        }

        let blocks_len = u64::from_le_bytes(blocks_len_src.try_into().unwrap());

        Ok(Self { state, blocks_len })
    }
}

impl Drop for WhirlpoolCore {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use digest::zeroize::Zeroize;
            self.state.zeroize();
            self.blocks_len.zeroize();
        }
    }
}

#[cfg(feature = "zeroize")]
impl digest::zeroize::ZeroizeOnDrop for WhirlpoolCore {}
