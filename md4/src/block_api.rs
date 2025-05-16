use core::fmt;
use digest::{
    HashMarker, Output,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, Eager, FixedOutputCore,
        OutputSizeUser, Reset, UpdateCore,
    },
    crypto_common::hazmat::{DeserializeStateError, SerializableState, SerializedState},
    typenum::{U16, U24, U64, Unsigned},
};

use crate::compress::compress;

const S0: [u32; 4] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476];

/// MD4 core hasher state
#[derive(Clone)]
pub struct Md4Core {
    block_len: u64,
    state: [u32; STATE_LEN],
}

const STATE_LEN: usize = 4;

impl HashMarker for Md4Core {}

impl BlockSizeUser for Md4Core {
    type BlockSize = U64;
}

impl BufferKindUser for Md4Core {
    type BufferKind = Eager;
}

impl OutputSizeUser for Md4Core {
    type OutputSize = U16;
}

impl UpdateCore for Md4Core {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.block_len = self.block_len.wrapping_add(blocks.len() as u64);
        for block in blocks {
            compress(&mut self.state, block.as_ref());
        }
    }
}

impl FixedOutputCore for Md4Core {
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let bits_len = self
            .block_len
            .wrapping_mul(Self::BlockSize::U64)
            .wrapping_add(buffer.get_pos() as u64)
            .wrapping_mul(8);

        let mut state = self.state;
        buffer.len64_padding_le(bits_len, |block| compress(&mut state, block.as_ref()));

        for (chunk, v) in out.chunks_exact_mut(4).zip(state.iter()) {
            chunk.copy_from_slice(&v.to_le_bytes());
        }
    }
}

impl Default for Md4Core {
    #[inline]
    fn default() -> Self {
        Self {
            state: S0,
            block_len: 0,
        }
    }
}

impl Reset for Md4Core {
    #[inline]
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl AlgorithmName for Md4Core {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Md4")
    }
}

impl fmt::Debug for Md4Core {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Md4Core { ... }")
    }
}

impl Drop for Md4Core {
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
impl digest::zeroize::ZeroizeOnDrop for Md4Core {}

impl SerializableState for Md4Core {
    type SerializedStateSize = U24;

    fn serialize(&self) -> SerializedState<Self> {
        let mut serialized_state = SerializedState::<Self>::default();

        for (val, chunk) in self.state.iter().zip(serialized_state.chunks_exact_mut(4)) {
            chunk.copy_from_slice(&val.to_le_bytes());
        }

        serialized_state[16..].copy_from_slice(&self.block_len.to_le_bytes());
        serialized_state
    }

    fn deserialize(
        serialized_state: &SerializedState<Self>,
    ) -> Result<Self, DeserializeStateError> {
        let (serialized_state, serialized_block_len) = serialized_state.split::<U16>();

        let mut state = [0; STATE_LEN];
        for (val, chunk) in state.iter_mut().zip(serialized_state.chunks_exact(4)) {
            *val = u32::from_le_bytes(chunk.try_into().unwrap());
        }

        let block_len = u64::from_le_bytes(*serialized_block_len.as_ref());

        Ok(Self { block_len, state })
    }
}
