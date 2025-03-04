// #![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub use digest::{self, Digest};

use core::{convert::TryInto, fmt};
#[cfg(feature = "zeroize")]
use digest::zeroize::{Zeroize, ZeroizeOnDrop};
use digest::{
    HashMarker, InvalidOutputSize, Output,
    block_buffer::Eager,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper,
        CtVariableCoreWrapper, OutputSizeUser, RtVariableCoreWrapper, TruncSide, UpdateCore,
        VariableOutputCore,
    },
    crypto_common::hazmat::{DeserializeStateError, SerializableState, SerializedState},
    typenum::{U6, U28, U32, U48, U64, U72, U128, U136, Unsigned},
};

mod compress1024;
mod compress512;
mod tables;

/// Lowest-level core hasher state of the short Kupyna variant.
#[derive(Clone)]
pub struct KupynaShortVarCore {
    state: [u64; compress512::COLS],
    blocks_len: u64,
}

/// Short Kupyna variant which allows to choose output size at runtime.
pub type KupynaShortVar = RtVariableCoreWrapper<KupynaShortVarCore>;
/// Core hasher state of the short Kupyna variant generic over output size.
pub type KupynaShortCore<OutSize> = CtVariableCoreWrapper<KupynaShortVarCore, OutSize>;
/// Hasher state of the short Kupyna variant generic over output size.
pub type KupynaShort<OutSize> = CoreWrapper<KupynaShortCore<OutSize>>;

/// Kupyna-48 hasher state
pub type Kupyna48 = CoreWrapper<KupynaShortCore<U6>>;
/// Kupyna-224 hasher state.
pub type Kupyna224 = CoreWrapper<KupynaShortCore<U28>>;
/// Kupyna-256 hasher state.
pub type Kupyna256 = CoreWrapper<KupynaShortCore<U32>>;

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
            compress512::compress(&mut self.state, block.as_ref());
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
        let mut state = [0; compress512::COLS];
        state[0] = 0x40;
        state[0] <<= 56;
        let blocks_len = 0;
        Ok(Self { state, blocks_len })
    }

    fn finalize_variable_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let total_message_len_bits =
            (((self.blocks_len * 64) + (buffer.size() - buffer.remaining()) as u64) * 8) as u128;

        buffer.digest_pad(
            0x80,
            &total_message_len_bits.to_le_bytes()[0..12],
            |block| compress512::compress(&mut self.state, block.as_ref()),
        );

        let mut state_u8 = [0u8; 64];
        for (i, &value) in self.state.iter().enumerate() {
            let bytes = value.to_be_bytes();
            state_u8[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
        }

        // Call t_xor_l with u8 array
        let t_xor_ult_processed_block = compress512::t_xor_l(state_u8);

        let result_u8 = compress512::xor_bytes(state_u8, t_xor_ult_processed_block);

        // Convert result back to u64s
        let mut res = [0u64; 8];
        for i in 0..8 {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&result_u8[i * 8..(i + 1) * 8]);
            res[i] = u64::from_be_bytes(bytes);
        }
        let n = compress512::COLS / 2;
        for (chunk, v) in out.chunks_exact_mut(8).zip(res[n..].iter()) {
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KupynaShortVarCore { ... }")
    }
}

impl Drop for KupynaShortVarCore {
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

    fn serialize(&self) -> SerializedState<Self> {
        let mut serialized_state = SerializedState::<Self>::default();

        for (val, chunk) in self.state.iter().zip(serialized_state.chunks_exact_mut(8)) {
            chunk.copy_from_slice(&val.to_le_bytes());
        }

        serialized_state[64..].copy_from_slice(&self.blocks_len.to_le_bytes());
        serialized_state
    }

    fn deserialize(
        serialized_state: &SerializedState<Self>,
    ) -> Result<Self, DeserializeStateError> {
        let (serialized_state, serialized_block_len) = serialized_state.split::<U64>();

        let mut state = [0; compress512::COLS];
        for (val, chunk) in state.iter_mut().zip(serialized_state.chunks_exact(8)) {
            *val = u64::from_le_bytes(chunk.try_into().unwrap());
        }

        let blocks_len = u64::from_le_bytes(*serialized_block_len.as_ref());

        Ok(Self { state, blocks_len })
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for KupynaShortVarCore {}

/// Lowest-level core hasher state of the long Kupyna variant.
#[derive(Clone)]
pub struct KupynaLongVarCore {
    state: [u64; compress1024::COLS],
    blocks_len: u64,
}

/// Long Kupyna variant which allows to choose output size at runtime.
pub type KupynaLongVar = RtVariableCoreWrapper<KupynaLongVarCore>;
/// Core hasher state of the long Kupyna variant generic over output size.
pub type KupynaLongCore<OutSize> = CtVariableCoreWrapper<KupynaLongVarCore, OutSize>;
/// Hasher state of the long Kupyna variant generic over output size.
pub type KupynaLong<OutSize> = CoreWrapper<KupynaLongCore<OutSize>>;

/// Kupyna-384 hasher state.
pub type Kupyna384 = CoreWrapper<KupynaLongCore<U48>>;
/// Kupyna-512 hasher state.
pub type Kupyna512 = CoreWrapper<KupynaLongCore<U64>>;

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
            compress1024::compress(&mut self.state, block.as_ref());
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
        if output_size > Self::OutputSize::USIZE {
            return Err(InvalidOutputSize);
        }
        let mut state = [0; compress1024::COLS];
        state[0] = 0x80;
        state[0] <<= 56;
        let blocks_len = 0;
        Ok(Self { state, blocks_len })
    }

    #[inline]
    fn finalize_variable_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let total_message_len_bits =
            (((self.blocks_len * 128) + (buffer.size() - buffer.remaining()) as u64) * 8) as u128;

        buffer.digest_pad(
            0x80,
            &total_message_len_bits.to_le_bytes()[0..12],
            |block| compress1024::compress(&mut self.state, block.as_ref()),
        );

        let mut state_u8 = [0u8; 128];
        for (i, &value) in self.state.iter().enumerate() {
            let bytes = value.to_be_bytes();
            state_u8[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
        }

        // Call t_xor_l with u8 array
        let t_xor_ult_processed_block = compress1024::t_xor_l(state_u8);

        let result_u8 = compress1024::xor_bytes(state_u8, t_xor_ult_processed_block);

        // Convert result back to u64s
        let mut res = [0u64; 16];
        for i in 0..16 {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&result_u8[i * 8..(i + 1) * 8]);
            res[i] = u64::from_be_bytes(bytes);
        }
        let n = compress1024::COLS / 2;
        for (chunk, v) in out.chunks_exact_mut(8).zip(res[n..].iter()) {
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KupynaLongVarCore { ... }")
    }
}

impl Drop for KupynaLongVarCore {
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

    fn serialize(&self) -> SerializedState<Self> {
        let mut serialized_state = SerializedState::<Self>::default();

        for (val, chunk) in self.state.iter().zip(serialized_state.chunks_exact_mut(8)) {
            chunk.copy_from_slice(&val.to_le_bytes());
        }

        serialized_state[128..].copy_from_slice(&self.blocks_len.to_le_bytes());
        serialized_state
    }

    fn deserialize(
        serialized_state: &SerializedState<Self>,
    ) -> Result<Self, DeserializeStateError> {
        let (serialized_state, serialized_block_len) = serialized_state.split::<U128>();

        let mut state = [0; compress1024::COLS];
        for (val, chunk) in state.iter_mut().zip(serialized_state.chunks_exact(8)) {
            *val = u64::from_le_bytes(chunk.try_into().unwrap());
        }

        let blocks_len = u64::from_le_bytes(*serialized_block_len.as_ref());

        Ok(Self { state, blocks_len })
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for KupynaLongVarCore {}
