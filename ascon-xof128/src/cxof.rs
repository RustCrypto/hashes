use ascon::State;
use digest::{
    CollisionResistance, CustomizedInit, ExtendableOutput, HashMarker, OutputSizeUser, Update,
    block_api::AlgorithmName,
    block_buffer::EagerBuffer,
    common::hazmat::{DeserializeStateError, SerializableState, SerializedState},
    consts::{U8, U16, U32, U48},
};

use crate::{AsconXof128Reader, consts::CXOF_INIT_STATE};

/// Ascon-CXOF128 hasher.
///
/// Note that NIST SP 800-232 specifies the following:
///
/// >The length of the customization string **shall** be at most 2048 bits (i.e., 256 bytes).
///
/// We do not check this condition as part of [`CustomizedInit::new_customized`] and
/// consider it the user's responsibility to use appropriately sized customization strings.
#[derive(Clone, Debug)]
pub struct AsconCxof128 {
    state: State,
    buffer: EagerBuffer<U8>,
}

impl CustomizedInit for AsconCxof128 {
    #[inline]
    fn new_customized(customization: &[u8]) -> Self {
        let bit_len = 8 * customization.len();
        let mut state = CXOF_INIT_STATE;

        state[0] ^= u64::try_from(bit_len).expect("`usize` always fits into `u64` in practice");

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

        let buffer = Default::default();
        Self { state, buffer }
    }
}

impl HashMarker for AsconCxof128 {}

impl OutputSizeUser for AsconCxof128 {
    type OutputSize = U32;
}

// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-232.ipd.pdf#table.caption.25
impl CollisionResistance for AsconCxof128 {
    type CollisionResistance = U16;
}

impl Update for AsconCxof128 {
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

impl ExtendableOutput for AsconCxof128 {
    type Reader = AsconXof128Reader;

    fn finalize_xof(mut self) -> Self::Reader {
        let Self { state, buffer } = &mut self;
        let len = buffer.get_pos();
        let last_block = buffer.pad_with_zeros();
        let pad = 1u64 << (8 * len);
        state[0] ^= u64::from_le_bytes(last_block.0) ^ pad;

        AsconXof128Reader::new(state)
    }
}

impl AlgorithmName for AsconCxof128 {
    #[inline]
    fn write_alg_name(f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Ascon-CXOF128")
    }
}

impl SerializableState for AsconCxof128 {
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

impl Drop for AsconCxof128 {
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
impl digest::zeroize::ZeroizeOnDrop for AsconCxof128 {}
