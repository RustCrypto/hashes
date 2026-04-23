use ascon::State;
use digest::{
    CustomizedInit, HashMarker, OutputSizeUser,
    block_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, Eager, ExtendableOutputCore,
        UpdateCore,
    },
    common::hazmat::{DeserializeStateError, SerializableState, SerializedState},
    consts::{U8, U32, U40},
};

use super::{AsconXofReaderCore, init_state};

/// Maximum allowed length of customization strings in bits.
const MAX_CUSTOM_LEN: usize = 2048;

const IV: u64 = 0x0000_0800_00CC_0004;
const INIT_STATE: State = init_state(IV);

/// Ascon-CXOF128 block-level hasher
#[derive(Clone, Debug)]
pub struct AsconCxof128Core {
    state: State,
}

impl Default for AsconCxof128Core {
    #[inline]
    fn default() -> Self {
        Self::new_customized(&[])
    }
}

impl CustomizedInit for AsconCxof128Core {
    #[inline]
    fn new_customized(customization: &[u8]) -> Self {
        let bit_len = 8 * customization.len();
        assert!(bit_len < MAX_CUSTOM_LEN);
        let mut state = INIT_STATE;

        state[0] ^= u64::try_from(bit_len).expect("bit_len is smaller than MAX_CUSTOM_LEN");

        ascon::permute12(&mut state);

        let mut blocks = customization.chunks_exact(size_of::<u64>());
        for block in &mut blocks {
            let block = block.try_into().expect("block has correct length");
            state[0] ^= u64::from_le_bytes(block);
            ascon::permute12(&mut state);
        }

        let last_block = blocks.remainder();
        let len = last_block.len();

        let mut buf = [0u8; 8];
        buf[..len].copy_from_slice(last_block);

        let pad = 1u64 << (8 * len);
        state[0] ^= u64::from_le_bytes(buf) ^ pad;

        ascon::permute12(&mut state);

        Self { state }
    }
}

impl HashMarker for AsconCxof128Core {}

impl BlockSizeUser for AsconCxof128Core {
    type BlockSize = U8;
}

impl BufferKindUser for AsconCxof128Core {
    type BufferKind = Eager;
}

impl OutputSizeUser for AsconCxof128Core {
    type OutputSize = U32;
}

impl UpdateCore for AsconCxof128Core {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        for block in blocks {
            self.state[0] ^= u64::from_le_bytes(block.0);
            ascon::permute12(&mut self.state);
        }
    }
}

impl ExtendableOutputCore for AsconCxof128Core {
    type ReaderCore = AsconXofReaderCore;

    fn finalize_xof_core(&mut self, buffer: &mut Buffer<Self>) -> Self::ReaderCore {
        let len = buffer.get_pos();
        let last_block = buffer.pad_with_zeros();
        let pad = 1u64 << (8 * len);
        self.state[0] ^= u64::from_le_bytes(last_block.0) ^ pad;

        AsconXofReaderCore { state: self.state }
    }
}

impl AlgorithmName for AsconCxof128Core {
    #[inline]
    fn write_alg_name(f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Ascon-CXOF128")
    }
}

impl SerializableState for AsconCxof128Core {
    type SerializedStateSize = U40;

    #[inline]
    fn serialize(&self) -> SerializedState<Self> {
        let mut res = SerializedState::<Self>::default();
        let mut chunks = res.chunks_exact_mut(size_of::<u64>());
        for (src, dst) in self.state.iter().zip(&mut chunks) {
            dst.copy_from_slice(&src.to_le_bytes());
        }
        assert!(chunks.into_remainder().is_empty());
        res
    }

    #[inline]
    fn deserialize(
        serialized_state: &SerializedState<Self>,
    ) -> Result<Self, DeserializeStateError> {
        let state = core::array::from_fn(|i| {
            let n = size_of::<u64>();
            let chunk = &serialized_state[n * i..][..n];
            u64::from_le_bytes(chunk.try_into().expect("chunk has correct length"))
        });
        Ok(Self { state })
    }
}

impl Drop for AsconCxof128Core {
    #[inline]
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use digest::zeroize::Zeroize;
            self.state.zeroize()
        }
    }
}

#[cfg(feature = "zeroize")]
impl digest::zeroize::ZeroizeOnDrop for AsconCxof128Core {}
