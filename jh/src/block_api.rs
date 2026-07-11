use crate::compressor::Compressor;
use core::fmt;
use digest::{
    HashMarker, InvalidOutputSize, Output,
    block_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, Eager, OutputSizeUser,
        TruncSide, UpdateCore, VariableOutputCore,
    },
    common::hazmat::{DeserializeStateError, SerializableState, SerializedState},
    typenum::{U64, U128, U136, Unsigned},
};

use crate::consts;

/// Core JH hasher state
#[derive(Clone)]
pub struct JhCore {
    state: Compressor,
    block_len: u64,
}

impl HashMarker for JhCore {}

impl BlockSizeUser for JhCore {
    type BlockSize = U64;
}

impl BufferKindUser for JhCore {
    type BufferKind = Eager;
}

impl OutputSizeUser for JhCore {
    type OutputSize = U64;
}

impl UpdateCore for JhCore {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.block_len = self.block_len.wrapping_add(blocks.len() as u64);
        for b in blocks {
            self.state.update(b);
        }
    }
}

impl VariableOutputCore for JhCore {
    const TRUNC_SIDE: TruncSide = TruncSide::Right;

    #[inline]
    fn new(output_size: usize) -> Result<Self, InvalidOutputSize> {
        let h0 = match output_size {
            28 => consts::JH224_H0,
            32 => consts::JH256_H0,
            48 => consts::JH384_H0,
            64 => consts::JH512_H0,
            _ => return Err(InvalidOutputSize),
        };
        Ok(Self {
            state: Compressor::new(h0),
            block_len: 0,
        })
    }

    #[inline]
    fn finalize_variable_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let bit_len = self
            .block_len
            .wrapping_mul(Self::BlockSize::U64)
            .wrapping_add(buffer.get_pos() as u64)
            .wrapping_mul(8);
        if buffer.get_pos() == 0 {
            buffer.len64_padding_be(bit_len, |b| self.state.update(b));
        } else {
            buffer.digest_pad(0x80, &[], |b| self.state.update(b));
            buffer.digest_pad(0, &bit_len.to_be_bytes(), |b| self.state.update(b));
        }
        self.state.write_digest(out);
    }
}

impl AlgorithmName for JhCore {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Jh")
    }
}

impl fmt::Debug for JhCore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JhCore { ... }")
    }
}

impl SerializableState for JhCore {
    type SerializedStateSize = U136;

    #[inline]
    fn serialize(&self) -> SerializedState<Self> {
        let mut serialized_state = SerializedState::<Self>::default();
        let (state_dst, block_len_dst) = serialized_state.split_at_mut(128);

        self.state.write_state(state_dst);
        block_len_dst.copy_from_slice(&self.block_len.to_le_bytes());

        serialized_state
    }

    #[inline]
    fn deserialize(
        serialized_state: &SerializedState<Self>,
    ) -> Result<Self, DeserializeStateError> {
        let (serialized_state, serialized_block_len) = serialized_state.split::<U128>();

        Ok(Self {
            state: Compressor::new(serialized_state.0),
            block_len: u64::from_le_bytes(serialized_block_len.0),
        })
    }
}

impl Drop for JhCore {
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
impl digest::zeroize::ZeroizeOnDrop for JhCore {}
