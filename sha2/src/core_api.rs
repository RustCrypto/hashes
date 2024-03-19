use crate::{consts, sha256::compress256, sha512::compress512};
use core::{convert::TryInto, fmt, slice::from_ref};
use digest::{
    array::Array,
    block_buffer::Eager,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, OutputSizeUser, TruncSide,
        UpdateCore, VariableOutputCore,
    },
    crypto_common::hazmat::{DeserializeStateError, SerializableState, SerializedState},
    typenum::{Unsigned, U128, U32, U40, U64, U80},
    HashMarker, InvalidOutputSize, Output,
};

#[cfg(feature = "zeroize")]
use digest::zeroize::{Zeroize, ZeroizeOnDrop};

/// Core block-level SHA-256 hasher with variable output size.
///
/// Supports initialization only for 28 and 32 byte output sizes,
/// i.e. 224 and 256 bits respectively.
#[derive(Clone)]
pub struct Sha256VarCore {
    state: consts::State256,
    block_len: u64,
}

impl HashMarker for Sha256VarCore {}

impl BlockSizeUser for Sha256VarCore {
    type BlockSize = U64;
}

impl BufferKindUser for Sha256VarCore {
    type BufferKind = Eager;
}

impl UpdateCore for Sha256VarCore {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.block_len += blocks.len() as u64;
        let blocks = Array::cast_slice_to_core(blocks);
        compress256(&mut self.state, blocks);
    }
}

impl OutputSizeUser for Sha256VarCore {
    type OutputSize = U32;
}

impl VariableOutputCore for Sha256VarCore {
    const TRUNC_SIDE: TruncSide = TruncSide::Left;

    #[inline]
    fn new(output_size: usize) -> Result<Self, InvalidOutputSize> {
        let state = match output_size {
            28 => consts::H256_224,
            32 => consts::H256_256,
            _ => return Err(InvalidOutputSize),
        };
        let block_len = 0;
        Ok(Self { state, block_len })
    }

    #[inline]
    fn finalize_variable_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let bs = Self::BlockSize::U64;
        let bit_len = 8 * (buffer.get_pos() as u64 + bs * self.block_len);
        buffer.len64_padding_be(bit_len, |b| compress256(&mut self.state, from_ref(&b.0)));

        for (chunk, v) in out.chunks_exact_mut(4).zip(self.state.iter()) {
            chunk.copy_from_slice(&v.to_be_bytes());
        }
    }
}

impl AlgorithmName for Sha256VarCore {
    #[inline]
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sha256")
    }
}

impl fmt::Debug for Sha256VarCore {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sha256VarCore { ... }")
    }
}

impl Drop for Sha256VarCore {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            self.state.zeroize();
            self.block_len.zeroize();
        }
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for Sha256VarCore {}

impl SerializableState for Sha256VarCore {
    type SerializedStateSize = U40;

    fn serialize(&self) -> SerializedState<Self> {
        let mut serialized_state = SerializedState::<Self>::default();

        for (val, chunk) in self.state.iter().zip(serialized_state.chunks_exact_mut(4)) {
            chunk.copy_from_slice(&val.to_le_bytes());
        }

        serialized_state[32..].copy_from_slice(&self.block_len.to_le_bytes());
        serialized_state
    }

    fn deserialize(
        serialized_state: &SerializedState<Self>,
    ) -> Result<Self, DeserializeStateError> {
        let (serialized_state, serialized_block_len) = serialized_state.split::<U32>();

        let mut state = consts::State256::default();
        for (val, chunk) in state.iter_mut().zip(serialized_state.chunks_exact(4)) {
            *val = u32::from_le_bytes(chunk.try_into().unwrap());
        }

        let block_len = u64::from_le_bytes(*serialized_block_len.as_ref());

        Ok(Self { state, block_len })
    }
}

/// Core block-level SHA-512 hasher with variable output size.
///
/// Supports initialization only for 28, 32, 48, and 64 byte output sizes,
/// i.e. 224, 256, 384, and 512 bits respectively.
#[derive(Clone)]
pub struct Sha512VarCore {
    state: consts::State512,
    block_len: u128,
}

impl HashMarker for Sha512VarCore {}

impl BlockSizeUser for Sha512VarCore {
    type BlockSize = U128;
}

impl BufferKindUser for Sha512VarCore {
    type BufferKind = Eager;
}

impl UpdateCore for Sha512VarCore {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.block_len += blocks.len() as u128;
        let blocks = Array::cast_slice_to_core(blocks);
        compress512(&mut self.state, blocks);
    }
}

impl OutputSizeUser for Sha512VarCore {
    type OutputSize = U64;
}

impl VariableOutputCore for Sha512VarCore {
    const TRUNC_SIDE: TruncSide = TruncSide::Left;

    #[inline]
    fn new(output_size: usize) -> Result<Self, InvalidOutputSize> {
        let state = match output_size {
            28 => consts::H512_224,
            32 => consts::H512_256,
            48 => consts::H512_384,
            64 => consts::H512_512,
            _ => return Err(InvalidOutputSize),
        };
        let block_len = 0;
        Ok(Self { state, block_len })
    }

    #[inline]
    fn finalize_variable_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let bs = Self::BlockSize::U64 as u128;
        let bit_len = 8 * (buffer.get_pos() as u128 + bs * self.block_len);
        buffer.len128_padding_be(bit_len, |b| compress512(&mut self.state, from_ref(&b.0)));

        for (chunk, v) in out.chunks_exact_mut(8).zip(self.state.iter()) {
            chunk.copy_from_slice(&v.to_be_bytes());
        }
    }
}

impl AlgorithmName for Sha512VarCore {
    #[inline]
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sha512")
    }
}

impl fmt::Debug for Sha512VarCore {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sha512VarCore { ... }")
    }
}

impl Drop for Sha512VarCore {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            self.state.zeroize();
            self.block_len.zeroize();
        }
    }
}
#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for Sha512VarCore {}

impl SerializableState for Sha512VarCore {
    type SerializedStateSize = U80;

    fn serialize(&self) -> SerializedState<Self> {
        let mut serialized_state = SerializedState::<Self>::default();

        for (val, chunk) in self.state.iter().zip(serialized_state.chunks_exact_mut(8)) {
            chunk.copy_from_slice(&val.to_le_bytes());
        }

        serialized_state[64..].copy_from_slice(&self.block_len.to_le_bytes());

        serialized_state
    }

    fn deserialize(
        serialized_state: &SerializedState<Self>,
    ) -> Result<Self, DeserializeStateError> {
        let (serialized_state, serialized_block_len) = serialized_state.split::<U64>();

        let mut state = consts::State512::default();
        for (val, chunk) in state.iter_mut().zip(serialized_state.chunks_exact(8)) {
            *val = u64::from_le_bytes(chunk.try_into().unwrap());
        }

        let block_len = u128::from_le_bytes(*serialized_block_len.as_ref());

        Ok(Self { state, block_len })
    }
}
