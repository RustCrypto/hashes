use core::fmt;
use digest::{
    HashMarker, Output,
    array::Array,
    block_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, Eager, FixedOutputCore,
        OutputSizeUser, Reset, UpdateCore,
    },
    crypto_common::hazmat::{DeserializeStateError, SerializableState, SerializedState},
    typenum::{U20, U28, U64, Unsigned},
};

#[cfg(feature = "zeroize")]
use digest::zeroize::{Zeroize, ZeroizeOnDrop};

pub use crate::compress::compress;

/// Initial state values imported from `consts` to avoid duplication.
use crate::consts::STATE_INIT;
use crate::consts::STATE_LEN;

/// Core HAS-160 hasher state.
#[derive(Clone)]
pub struct Has160Core {
    h: [u32; STATE_LEN],
    /// Number of 512-bit message blocks processed (not including the buffer)
    block_len: u64,
}

impl HashMarker for Has160Core {}

impl BlockSizeUser for Has160Core {
    type BlockSize = U64; // 512-bit blocks
}

impl BufferKindUser for Has160Core {
    type BufferKind = Eager;
}

impl OutputSizeUser for Has160Core {
    type OutputSize = U20; // 160-bit output
}

impl UpdateCore for Has160Core {
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        // Count full blocks processed
        self.block_len = self.block_len.wrapping_add(blocks.len() as u64);

        // Cast slice of generic blocks to array-of-64-byte blocks
        let blocks = Array::cast_slice_to_core(blocks);
        compress(&mut self.h, blocks);
    }
}

impl FixedOutputCore for Has160Core {
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        // Total bit length (processed blocks * 64 + buffer length) * 8 bits.
        // HAS-160 uses little-endian length encoding unlike SHA-1.
        let bs = Self::BlockSize::U64;
        let bit_len = 8 * (buffer.get_pos() as u64 + bs * self.block_len);

        // Copy current state
        let mut h = self.h;

        // Apply Merkle–Damgård padding with 64-bit little-endian length
        buffer.len64_padding_le(bit_len, |b| compress(&mut h, &[b.0]));

        // Write final 160-bit digest as little-endian words (HAS-160 specification)
        for (chunk, v) in out.chunks_exact_mut(4).zip(h.iter()) {
            chunk.copy_from_slice(&v.to_le_bytes());
        }
    }
}

impl Default for Has160Core {
    fn default() -> Self {
        Self {
            h: STATE_INIT,
            block_len: 0,
        }
    }
}

impl Reset for Has160Core {
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl AlgorithmName for Has160Core {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Has160")
    }
}

impl fmt::Debug for Has160Core {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Has160Core { ... }")
    }
}

impl Drop for Has160Core {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            self.h.zeroize();
            self.block_len.zeroize();
        }
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for Has160Core {}

impl SerializableState for Has160Core {
    // Serialized state size: 28 bytes
    type SerializedStateSize = U28;

    fn serialize(&self) -> SerializedState<Self> {
        let mut ser = SerializedState::<Self>::default();

        // Serialize state words little-endian for consistency with other implementations
        for (val, chunk) in self.h.iter().zip(ser.chunks_exact_mut(4)) {
            chunk.copy_from_slice(&val.to_le_bytes());
        }

        ser[20..].copy_from_slice(&self.block_len.to_le_bytes());
        ser
    }

    fn deserialize(serialized: &SerializedState<Self>) -> Result<Self, DeserializeStateError> {
        let (ser_state, ser_block_len) = serialized.split::<U20>();

        let mut h = [0u32; STATE_LEN];
        for (val, chunk) in h.iter_mut().zip(ser_state.chunks_exact(4)) {
            *val = u32::from_le_bytes(chunk.try_into().unwrap());
        }

        let block_len = u64::from_le_bytes(*ser_block_len.as_ref());

        Ok(Self { h, block_len })
    }
}
