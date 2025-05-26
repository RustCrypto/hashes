use crate::{
    long, short,
    utils::{read_u64_le, write_u64_le, xor_words},
};
use core::fmt;
use digest::{
    HashMarker, InvalidOutputSize, Output,
    block_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, Eager, OutputSizeUser,
        TruncSide, UpdateCore, VariableOutputCore,
    },
    crypto_common::hazmat::{DeserializeStateError, SerializableState, SerializedState},
    typenum::{U32, U64, U72, U128, U136, Unsigned},
};

#[cfg(feature = "zeroize")]
use digest::zeroize::{Zeroize, ZeroizeOnDrop};

/// Lowest-level core hasher state of the short Kupyna variant.
#[derive(Clone)]
pub struct KupynaShortVarCore {
    state: [u64; short::COLS],
    blocks_len: u64,
}

impl HashMarker for KupynaShortVarCore {}

impl BlockSizeUser for KupynaShortVarCore {
    type BlockSize = U64;
}

impl BufferKindUser for KupynaShortVarCore {
    type BufferKind = Eager;
}

impl UpdateCore for KupynaShortVarCore {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.blocks_len += blocks.len() as u64;
        for block in blocks {
            short::compress(&mut self.state, block.as_ref());
        }
    }
}

impl OutputSizeUser for KupynaShortVarCore {
    type OutputSize = U32;
}

impl VariableOutputCore for KupynaShortVarCore {
    const TRUNC_SIDE: TruncSide = TruncSide::Right;

    #[inline]
    fn new(output_size: usize) -> Result<Self, InvalidOutputSize> {
        if output_size > Self::OutputSize::USIZE {
            return Err(InvalidOutputSize);
        }
        let mut state = [0; short::COLS];
        state[0] = 0x40;
        state[0] <<= 56;
        let blocks_len = 0;
        Ok(Self { state, blocks_len })
    }

    #[inline]
    fn finalize_variable_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let block_size = Self::BlockSize::USIZE as u128;
        let msg_len_bytes = (self.blocks_len as u128) * block_size + (buffer.get_pos() as u128);
        let msg_len_bits = 8 * msg_len_bytes;

        buffer.digest_pad(0x80, &msg_len_bits.to_le_bytes()[0..12], |block| {
            short::compress(&mut self.state, block.as_ref());
        });

        // Process final state with t_xor_l
        let t_xor_ult_processed_block = short::t_xor_l(self.state);

        let result_state = xor_words(self.state, t_xor_ult_processed_block);

        // println!("final_result(pre truncate):=");
        // for v in result_state.iter() {
        //     println!("{:02X?}", v);
        // }

        let n = short::COLS / 2;
        for (chunk, v) in out.chunks_exact_mut(8).zip(result_state[n..].iter()) {
            chunk.copy_from_slice(&v.to_be_bytes());
        }
    }
}

impl AlgorithmName for KupynaShortVarCore {
    #[inline]
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KupynaShort")
    }
}

impl fmt::Debug for KupynaShortVarCore {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KupynaShortVarCore { ... }")
    }
}

impl Drop for KupynaShortVarCore {
    #[inline]
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            self.state.zeroize();
            self.blocks_len.zeroize();
        }
    }
}

impl SerializableState for KupynaShortVarCore {
    type SerializedStateSize = U72;

    #[inline]
    fn serialize(&self) -> SerializedState<Self> {
        let mut serialized_state = SerializedState::<Self>::default();
        let (state_dst, len_dst) = serialized_state.split_at_mut(64);
        write_u64_le(&self.state, state_dst);
        len_dst.copy_from_slice(&self.blocks_len.to_le_bytes());
        serialized_state
    }

    #[inline]
    fn deserialize(
        serialized_state: &SerializedState<Self>,
    ) -> Result<Self, DeserializeStateError> {
        let (serialized_state, serialized_block_len) = serialized_state.split::<U64>();
        Ok(Self {
            state: read_u64_le(&serialized_state.0),
            blocks_len: u64::from_le_bytes(serialized_block_len.0),
        })
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for KupynaShortVarCore {}

/// Lowest-level core hasher state of the long Kupyna variant.
#[derive(Clone)]
pub struct KupynaLongVarCore {
    state: [u64; long::COLS],
    blocks_len: u64,
}

impl HashMarker for KupynaLongVarCore {}

impl BlockSizeUser for KupynaLongVarCore {
    type BlockSize = U128;
}

impl BufferKindUser for KupynaLongVarCore {
    type BufferKind = Eager;
}

impl UpdateCore for KupynaLongVarCore {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.blocks_len += blocks.len() as u64;
        for block in blocks {
            long::compress(&mut self.state, block.as_ref());
        }
    }
}

impl OutputSizeUser for KupynaLongVarCore {
    type OutputSize = U64;
}

impl VariableOutputCore for KupynaLongVarCore {
    const TRUNC_SIDE: TruncSide = TruncSide::Right;

    #[inline]
    fn new(output_size: usize) -> Result<Self, InvalidOutputSize> {
        let min_size = Self::OutputSize::USIZE / 2;
        let max_size = Self::OutputSize::USIZE;
        if output_size < min_size || output_size > max_size {
            return Err(InvalidOutputSize);
        }
        let mut state = [0; long::COLS];
        state[0] = 0x80;
        state[0] <<= 56;
        let blocks_len = 0;
        Ok(Self { state, blocks_len })
    }

    #[inline]
    fn finalize_variable_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let block_size = Self::BlockSize::USIZE as u128;
        let msg_len_bytes = (self.blocks_len as u128) * block_size + (buffer.get_pos() as u128);
        let msg_len_bits = 8 * msg_len_bytes;

        buffer.digest_pad(0x80, &msg_len_bits.to_le_bytes()[0..12], |block| {
            long::compress(&mut self.state, block.as_ref());
        });

        // Process final state with t_xor_l
        let t_xor_ult_processed_block = long::t_xor_l(self.state);

        let result_state = xor_words(self.state, t_xor_ult_processed_block);

        let n = long::COLS / 2;
        for (chunk, v) in out.chunks_exact_mut(8).zip(result_state[n..].iter()) {
            chunk.copy_from_slice(&v.to_be_bytes());
        }
    }
}

impl AlgorithmName for KupynaLongVarCore {
    #[inline]
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KupynaLong")
    }
}

impl fmt::Debug for KupynaLongVarCore {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KupynaLongVarCore { ... }")
    }
}

impl Drop for KupynaLongVarCore {
    #[inline]
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            self.state.zeroize();
            self.blocks_len.zeroize();
        }
    }
}

impl SerializableState for KupynaLongVarCore {
    type SerializedStateSize = U136;

    #[inline]
    fn serialize(&self) -> SerializedState<Self> {
        let mut serialized_state = SerializedState::<Self>::default();
        let (state_dst, len_dst) = serialized_state.split_at_mut(128);
        write_u64_le(&self.state, state_dst);
        len_dst.copy_from_slice(&self.blocks_len.to_le_bytes());
        serialized_state
    }

    #[inline]
    fn deserialize(
        serialized_state: &SerializedState<Self>,
    ) -> Result<Self, DeserializeStateError> {
        let (serialized_state, serialized_block_len) = serialized_state.split::<U128>();
        Ok(Self {
            state: read_u64_le(&serialized_state.0),
            blocks_len: u64::from_le_bytes(serialized_block_len.0),
        })
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for KupynaLongVarCore {}
