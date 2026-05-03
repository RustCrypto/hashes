use ascon::State;
use core::fmt;
use digest::{
    CollisionResistance, ExtendableOutput, ExtendableOutputReset, HashMarker, OutputSizeUser,
    Reset, Update,
    common::AlgorithmName,
    common::hazmat::{DeserializeStateError, SerializableState, SerializedState},
    consts::{U8, U16, U32, U41},
};
use sponge_cursor::SpongeCursor;

use crate::{AsconXof128Reader, consts::XOF_INIT_STATE};

/// Ascon-XOF128 hasher.
#[derive(Clone)]
pub struct AsconXof128 {
    state: State,
    cursor: SpongeCursor<U8>,
}

impl Default for AsconXof128 {
    #[inline]
    fn default() -> Self {
        Self {
            state: XOF_INIT_STATE,
            cursor: Default::default(),
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
        self.cursor
            .absorb_u64_le(&mut self.state, ascon::permute12, data);
    }
}

impl AsconXof128 {
    fn pad(&mut self) {
        let pos = self.cursor.pos();
        self.state[0] ^= 1u64 << (8 * pos);
    }
}

impl ExtendableOutput for AsconXof128 {
    type Reader = AsconXof128Reader;

    fn finalize_xof(mut self) -> Self::Reader {
        self.pad();
        AsconXof128Reader::new(&self.state)
    }
}

impl ExtendableOutputReset for AsconXof128 {
    fn finalize_xof_reset(&mut self) -> Self::Reader {
        self.pad();
        let res = AsconXof128Reader::new(&self.state);
        self.reset();
        res
    }
}

impl Reset for AsconXof128 {
    #[inline]
    fn reset(&mut self) {
        self.state = XOF_INIT_STATE;
        self.cursor = Default::default();
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
    type SerializedStateSize = U41;

    #[inline]
    fn serialize(&self) -> SerializedState<Self> {
        let mut res = SerializedState::<Self>::default();
        let (state_dst, cursor_dst) = res.split_at_mut(size_of::<State>());
        let mut chunks = state_dst.chunks_exact_mut(size_of::<u64>());
        for (src, dst) in self.state.iter().zip(&mut chunks) {
            dst.copy_from_slice(&src.to_le_bytes());
        }
        assert!(chunks.into_remainder().is_empty());
        assert_eq!(cursor_dst.len(), 1);
        cursor_dst[0] = self.cursor.raw_pos();
        res
    }

    #[inline]
    fn deserialize(
        serialized_state: &SerializedState<Self>,
    ) -> Result<Self, DeserializeStateError> {
        let (state_src, cursor_src) = serialized_state.split_at(size_of::<State>());
        let state = core::array::from_fn(|i| {
            let n = size_of::<u64>();
            let chunk = &state_src[n * i..][..n];
            u64::from_le_bytes(chunk.try_into().expect("chunk has correct length"))
        });
        assert_eq!(cursor_src.len(), 1);
        SpongeCursor::new(cursor_src[0])
            .ok_or(DeserializeStateError)
            .map(|cursor| Self { state, cursor })
    }
}

impl Drop for AsconXof128 {
    #[inline]
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use digest::zeroize::Zeroize;
            self.state.zeroize();
            self.cursor.zeroize();
        }
    }
}

#[cfg(feature = "zeroize")]
impl digest::zeroize::ZeroizeOnDrop for AsconXof128 {}
