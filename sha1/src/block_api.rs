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
    typenum::{U20, U28, U64, Unsigned},
};

#[cfg(feature = "zeroize")]
use digest::zeroize::{Zeroize, ZeroizeOnDrop};

pub use crate::compress;

const STATE_LEN: usize = 5;
const H0: [u32; STATE_LEN] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

/// Core SHA-1 hasher state.
#[derive(Clone)]
pub struct Sha1Core {
    h: [u32; STATE_LEN],
    block_len: u64,
}

impl HashMarker for Sha1Core {}

impl BlockSizeUser for Sha1Core {
    type BlockSize = U64;
}

impl BufferKindUser for Sha1Core {
    type BufferKind = Eager;
}

impl OutputSizeUser for Sha1Core {
    type OutputSize = U20;
}

impl UpdateCore for Sha1Core {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.block_len += blocks.len() as u64;
        let blocks = Array::cast_slice_to_core(blocks);
        compress(&mut self.h, blocks);
    }
}

impl FixedOutputCore for Sha1Core {
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

impl Default for Sha1Core {
    #[inline]
    fn default() -> Self {
        Self {
            h: H0,
            block_len: 0,
        }
    }
}

impl Reset for Sha1Core {
    #[inline]
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl AlgorithmName for Sha1Core {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sha1")
    }
}

impl fmt::Debug for Sha1Core {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sha1Core { ... }")
    }
}

impl Drop for Sha1Core {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            self.h.zeroize();
            self.block_len.zeroize();
        }
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for Sha1Core {}

impl SerializableState for Sha1Core {
    type SerializedStateSize = U28;

    fn serialize(&self) -> SerializedState<Self> {
        let mut serialized_h = SerializedState::<Self>::default();

        for (val, chunk) in self.h.iter().zip(serialized_h.chunks_exact_mut(4)) {
            chunk.copy_from_slice(&val.to_le_bytes());
        }

        serialized_h[20..].copy_from_slice(&self.block_len.to_le_bytes());
        serialized_h
    }

    fn deserialize(
        serialized_state: &SerializedState<Self>,
    ) -> Result<Self, DeserializeStateError> {
        let (serialized_h, serialized_block_len) = serialized_state.split::<U20>();

        let mut h = [0; STATE_LEN];
        for (val, chunk) in h.iter_mut().zip(serialized_h.chunks_exact(4)) {
            *val = u32::from_le_bytes(chunk.try_into().unwrap());
        }

        let block_len = u64::from_le_bytes(*serialized_block_len.as_ref());

        Ok(Self { h, block_len })
    }
}
