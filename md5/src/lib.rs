#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![warn(missing_docs, rust_2018_idioms)]

pub use digest::{self, Digest};

mod compress;
pub(crate) mod consts;

use core::{convert::TryInto, fmt, slice::from_ref};
use digest::{
    array::Array,
    block_buffer::Eager,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore,
        OutputSizeUser, Reset, UpdateCore,
    },
    crypto_common::hazmat::{DeserializeStateError, SerializableState, SerializedState},
    typenum::{Unsigned, U16, U24, U64},
    HashMarker, Output,
};

#[cfg(feature = "oid")]
use digest::const_oid::{AssociatedOid, ObjectIdentifier};
#[cfg(feature = "zeroize")]
use digest::zeroize::{Zeroize, ZeroizeOnDrop};

/// Core MD5 hasher state.
#[derive(Clone)]
pub struct Md5Core {
    block_len: u64,
    state: [u32; STATE_LEN],
}

/// MD5 hasher state.
pub type Md5 = CoreWrapper<Md5Core>;

const STATE_LEN: usize = 4;

impl HashMarker for Md5Core {}

impl BlockSizeUser for Md5Core {
    type BlockSize = U64;
}

impl BufferKindUser for Md5Core {
    type BufferKind = Eager;
}

impl OutputSizeUser for Md5Core {
    type OutputSize = U16;
}

impl UpdateCore for Md5Core {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.block_len = self.block_len.wrapping_add(blocks.len() as u64);
        let blocks = Array::cast_slice_to_core(blocks);
        compress::compress(&mut self.state, blocks)
    }
}

impl FixedOutputCore for Md5Core {
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let bit_len = self
            .block_len
            .wrapping_mul(Self::BlockSize::U64)
            .wrapping_add(buffer.get_pos() as u64)
            .wrapping_mul(8);
        let mut s = self.state;
        buffer.len64_padding_le(bit_len, |b| compress::compress(&mut s, from_ref(&b.0)));
        for (chunk, v) in out.chunks_exact_mut(4).zip(s.iter()) {
            chunk.copy_from_slice(&v.to_le_bytes());
        }
    }
}

impl Default for Md5Core {
    #[inline]
    fn default() -> Self {
        Self {
            block_len: 0,
            state: consts::STATE_INIT,
        }
    }
}

impl Reset for Md5Core {
    #[inline]
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl AlgorithmName for Md5Core {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Md5")
    }
}

impl fmt::Debug for Md5Core {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Md5Core { ... }")
    }
}

#[cfg(feature = "oid")]
#[cfg_attr(docsrs, doc(cfg(feature = "oid")))]
impl AssociatedOid for Md5Core {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.2.5");
}

impl Drop for Md5Core {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            self.state.zeroize();
            self.block_len.zeroize();
        }
    }
}

impl SerializableState for Md5Core {
    type SerializedStateSize = U24;

    fn serialize(&self) -> SerializedState<Self> {
        let mut serialized_state = SerializedState::<Self>::default();

        for (val, chunk) in self.state.iter().zip(serialized_state.chunks_exact_mut(4)) {
            chunk.copy_from_slice(&val.to_le_bytes());
        }

        serialized_state[16..].copy_from_slice(&self.block_len.to_le_bytes());
        serialized_state
    }

    fn deserialize(
        serialized_state: &SerializedState<Self>,
    ) -> Result<Self, DeserializeStateError> {
        let (serialized_state, serialized_block_len) = serialized_state.split::<U16>();

        let mut state = [0; STATE_LEN];
        for (val, chunk) in state.iter_mut().zip(serialized_state.chunks_exact(4)) {
            *val = u32::from_le_bytes(chunk.try_into().unwrap());
        }

        let block_len = u64::from_le_bytes(*serialized_block_len.as_ref());

        Ok(Self { state, block_len })
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for Md5Core {}
