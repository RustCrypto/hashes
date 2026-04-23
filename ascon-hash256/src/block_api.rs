use ascon::State;
use digest::{
    HashMarker, Output, OutputSizeUser, Reset,
    block_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, Eager, FixedOutputCore,
        UpdateCore,
    },
    common::hazmat::{DeserializeStateError, SerializableState, SerializedState},
    consts::{U8, U32, U40},
};

const IV: u64 = 0x0000_0801_00CC_0002;

/// Initial state of Ascon-Hash256
const INIT_STATE: State = {
    let mut state = [IV, 0, 0, 0, 0];
    ascon::permute12(&mut state);
    state
};

/// Ascon-Hash256 block-level hasher
#[derive(Clone, Debug)]
pub struct AsconHash256Core {
    state: State,
}

impl Default for AsconHash256Core {
    #[inline]
    fn default() -> Self {
        Self { state: INIT_STATE }
    }
}

impl HashMarker for AsconHash256Core {}

impl BlockSizeUser for AsconHash256Core {
    type BlockSize = U8;
}

impl BufferKindUser for AsconHash256Core {
    type BufferKind = Eager;
}

impl OutputSizeUser for AsconHash256Core {
    type OutputSize = U32;
}

impl UpdateCore for AsconHash256Core {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        for block in blocks {
            self.state[0] ^= u64::from_le_bytes(block.0);
            ascon::permute12(&mut self.state);
        }
    }
}

impl FixedOutputCore for AsconHash256Core {
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let len = buffer.get_pos();
        let last_block = buffer.pad_with_zeros();
        let pad = 1u64 << (8 * len);
        self.state[0] ^= u64::from_le_bytes(last_block.0) ^ pad;

        ascon::permute12(&mut self.state);

        let mut chunks = out.chunks_exact_mut(size_of::<u64>());
        for chunk in &mut chunks {
            chunk.copy_from_slice(&self.state[0].to_le_bytes());
            ascon::permute12(&mut self.state);
        }
        assert!(chunks.into_remainder().is_empty());
    }
}

impl Reset for AsconHash256Core {
    #[inline]
    fn reset(&mut self) {
        self.state = INIT_STATE;
    }
}

impl AlgorithmName for AsconHash256Core {
    #[inline]
    fn write_alg_name(f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Ascon-Hash256")
    }
}

impl SerializableState for AsconHash256Core {
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

impl Drop for AsconHash256Core {
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
impl digest::zeroize::ZeroizeOnDrop for AsconHash256Core {}
