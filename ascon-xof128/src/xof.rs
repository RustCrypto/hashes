use ascon::State;
use core::fmt;
use digest::{
    CollisionResistance, ExtendableOutput, ExtendableOutputReset, HashMarker, OutputSizeUser,
    Reset, Update,
    block_api::AlgorithmName,
    block_buffer::EagerBuffer,
    common::hazmat::{DeserializeStateError, SerializableState, SerializedState},
    consts::{U8, U16, U32, U48},
};

use crate::{AsconXof128Reader, consts::XOF_INIT_STATE};

/// Ascon-XOF128 hasher.
#[derive(Clone)]
pub struct AsconXof128 {
    state: State,
    buffer: EagerBuffer<U8>,
}

impl Default for AsconXof128 {
    #[inline]
    fn default() -> Self {
        Self {
            state: XOF_INIT_STATE,
            buffer: Default::default(),
        }
    }
}

impl HashMarker for AsconXof128 {}

impl OutputSizeUser for AsconXof128 {
    type OutputSize = U32;
}

// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-232.ipd.pdf#table.caption.25
impl CollisionResistance for AsconXof128 {
    type CollisionResistance = U16;
}

impl Update for AsconXof128 {
    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.buffer.digest_blocks(data, |blocks| {
            for block in blocks {
                self.state[0] ^= u64::from_le_bytes(block.0);
                ascon::permute12(&mut self.state);
            }
        });
    }
}

impl AsconXof128 {
    fn finalize_xof_dirty(&mut self) -> AsconXof128Reader {
        let Self { state, buffer } = self;
        let len = buffer.get_pos();
        let last_block = buffer.pad_with_zeros();
        let pad = 1u64 << (8 * len);
        state[0] ^= u64::from_le_bytes(last_block.0) ^ pad;

        AsconXof128Reader::new(state)
    }
}

impl ExtendableOutput for AsconXof128 {
    type Reader = AsconXof128Reader;

    fn finalize_xof(mut self) -> Self::Reader {
        self.finalize_xof_dirty()
    }
}

impl ExtendableOutputReset for AsconXof128 {
    fn finalize_xof_reset(&mut self) -> Self::Reader {
        let res = self.finalize_xof_dirty();
        self.reset();
        res
    }
}

impl Reset for AsconXof128 {
    #[inline]
    fn reset(&mut self) {
        self.state = XOF_INIT_STATE;
        self.buffer.reset();
    }
}

impl AlgorithmName for AsconXof128 {
    #[inline]
    fn write_alg_name(f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Ascon-XOF128")
    }
}

impl fmt::Debug for AsconXof128 {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AsconXof128 { ... }")
    }
}

impl SerializableState for AsconXof128 {
    type SerializedStateSize = U48;

    #[inline]
    fn serialize(&self) -> SerializedState<Self> {
        let mut res = SerializedState::<Self>::default();
        let (state_dst, buffer_dst) = res.split_at_mut(size_of::<State>());
        let mut chunks = state_dst.chunks_exact_mut(size_of::<u64>());
        for (src, dst) in self.state.iter().zip(&mut chunks) {
            dst.copy_from_slice(&src.to_le_bytes());
        }
        assert!(chunks.into_remainder().is_empty());
        buffer_dst.copy_from_slice(&self.buffer.serialize());
        res
    }

    #[inline]
    fn deserialize(
        serialized_state: &SerializedState<Self>,
    ) -> Result<Self, DeserializeStateError> {
        let (state_src, buffer_src) = serialized_state.split_at(size_of::<State>());
        let state = core::array::from_fn(|i| {
            let n = size_of::<u64>();
            let chunk = &state_src[n * i..][..n];
            u64::from_le_bytes(chunk.try_into().expect("chunk has correct length"))
        });
        let buffer_src = buffer_src
            .try_into()
            .expect("buffer_src has correct length");
        EagerBuffer::deserialize(buffer_src)
            .map_err(|_| DeserializeStateError)
            .map(|buffer| Self { state, buffer })
    }
}

impl Drop for AsconXof128 {
    #[inline]
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use digest::zeroize::{Zeroize, ZeroizeOnDrop};
            fn assert_zeroize_on_drop<T: ZeroizeOnDrop>(_: &mut T) {}
            self.state.zeroize();
            assert_zeroize_on_drop(&mut self.buffer);
        }
    }
}

#[cfg(feature = "zeroize")]
impl digest::zeroize::ZeroizeOnDrop for AsconXof128 {}
