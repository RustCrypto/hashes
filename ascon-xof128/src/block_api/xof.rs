use ascon::State;
use digest::{
    HashMarker, OutputSizeUser, Reset,
    block_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, Eager, ExtendableOutputCore,
        UpdateCore,
    },
    common::hazmat::{DeserializeStateError, SerializableState, SerializedState},
    consts::{U8, U32, U40},
};

use super::{AsconXofReaderCore, init_state};

const IV: u64 = 0x0000_0800_00CC_0003;
const INIT_STATE: State = init_state(IV);

/// Ascon-XOF128 block-level hasher
#[derive(Clone, Debug)]
pub struct AsconXof128Core {
    state: State,
}

impl Default for AsconXof128Core {
    #[inline]
    fn default() -> Self {
        Self { state: INIT_STATE }
    }
}

impl HashMarker for AsconXof128Core {}

impl BlockSizeUser for AsconXof128Core {
    type BlockSize = U8;
}

impl BufferKindUser for AsconXof128Core {
    type BufferKind = Eager;
}

impl OutputSizeUser for AsconXof128Core {
    type OutputSize = U32;
}

impl UpdateCore for AsconXof128Core {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        for block in blocks {
            self.state[0] ^= u64::from_le_bytes(block.0);
            ascon::permute12(&mut self.state);
        }
    }
}

impl ExtendableOutputCore for AsconXof128Core {
    type ReaderCore = AsconXofReaderCore;

    fn finalize_xof_core(&mut self, buffer: &mut Buffer<Self>) -> Self::ReaderCore {
        let len = buffer.get_pos();
        let last_block = buffer.pad_with_zeros();
        let pad = 1u64 << (8 * len);
        self.state[0] ^= u64::from_le_bytes(last_block.0) ^ pad;

        AsconXofReaderCore { state: self.state }
    }
}

impl Reset for AsconXof128Core {
    #[inline]
    fn reset(&mut self) {
        self.state = INIT_STATE;
    }
}

impl AlgorithmName for AsconXof128Core {
    #[inline]
    fn write_alg_name(f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Ascon-XOF128")
    }
}

impl SerializableState for AsconXof128Core {
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

impl Drop for AsconXof128Core {
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
impl digest::zeroize::ZeroizeOnDrop for AsconXof128Core {}
