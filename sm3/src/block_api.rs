use core::fmt;
use digest::{
    HashMarker, Output,
    array::Array,
    block_buffer::Eager,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, FixedOutputCore,
        OutputSizeUser, Reset, UpdateCore,
    },
    crypto_common::hazmat::{DeserializeStateError, SerializableState, SerializedState},
    typenum::{U32, U40, U64, Unsigned},
};

use crate::{
    compress::compress,
    consts::{H_LEN, H0},
};

/// Core SM3 hasher state.
#[derive(Clone)]
pub struct Sm3Core {
    block_len: u64,
    h: [u32; H_LEN],
}

impl HashMarker for Sm3Core {}

impl BlockSizeUser for Sm3Core {
    type BlockSize = U64;
}

impl BufferKindUser for Sm3Core {
    type BufferKind = Eager;
}

impl OutputSizeUser for Sm3Core {
    type OutputSize = U32;
}

impl UpdateCore for Sm3Core {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.block_len += blocks.len() as u64;
        compress(&mut self.h, Array::cast_slice_to_core(blocks));
    }
}

impl FixedOutputCore for Sm3Core {
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let bs = Self::BlockSize::U64;
        let bit_len = 8 * (buffer.get_pos() as u64 + bs * self.block_len);

        let mut h = self.h;
        buffer.len64_padding_be(bit_len, |b| compress(&mut h, &[b.0]));
        for (chunk, v) in out.chunks_exact_mut(4).zip(h.iter()) {
            chunk.copy_from_slice(&v.to_be_bytes());
        }
    }
}

impl Default for Sm3Core {
    #[inline]
    fn default() -> Self {
        Self {
            h: H0,
            block_len: 0,
        }
    }
}

impl Reset for Sm3Core {
    #[inline]
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl AlgorithmName for Sm3Core {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sm3")
    }
}

impl fmt::Debug for Sm3Core {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sm3Core { ... }")
    }
}

impl Drop for Sm3Core {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use digest::zeroize::Zeroize;
            self.h.zeroize();
            self.block_len.zeroize();
        }
    }
}

#[cfg(feature = "zeroize")]
impl digest::zeroize::ZeroizeOnDrop for Sm3Core {}

impl SerializableState for Sm3Core {
    type SerializedStateSize = U40;

    fn serialize(&self) -> SerializedState<Self> {
        let mut serialized_h = SerializedState::<Self>::default();

        for (val, chunk) in self.h.iter().zip(serialized_h.chunks_exact_mut(4)) {
            chunk.copy_from_slice(&val.to_le_bytes());
        }

        serialized_h[32..].copy_from_slice(&self.block_len.to_le_bytes());
        serialized_h
    }

    fn deserialize(
        serialized_state: &SerializedState<Self>,
    ) -> Result<Self, DeserializeStateError> {
        let (serialized_h, serialized_block_len) = serialized_state.split::<U32>();

        let mut h = [0; H_LEN];
        for (val, chunk) in h.iter_mut().zip(serialized_h.chunks_exact(4)) {
            *val = u32::from_le_bytes(chunk.try_into().unwrap());
        }

        let block_len = u64::from_le_bytes(*serialized_block_len.as_ref());

        Ok(Self { block_len, h })
    }
}
