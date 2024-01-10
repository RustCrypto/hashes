#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![warn(missing_docs, rust_2018_idioms)]

pub use digest::{self, Digest};

mod compress;
pub(crate) mod consts;

use core::{fmt, slice::from_ref};
#[cfg(feature = "oid")]
use digest::const_oid::{AssociatedOid, ObjectIdentifier};
use digest::{
    block_buffer::Eager,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore,
        OutputSizeUser, Reset, UpdateCore,
    },
    typenum::{Unsigned, U16, U64},
    HashMarker, Output,
};

/// Core MD5 hasher state.
#[derive(Clone)]
pub struct Md5Core {
    block_len: u64,
    state: [u32; 4],
}

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
        compress::compress(&mut self.state, convert(blocks))
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
        buffer.len64_padding_le(bit_len, |b| {
            compress::compress(&mut s, convert(from_ref(b)))
        });
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

/// MD5 hasher state.
pub type Md5 = CoreWrapper<Md5Core>;

const BLOCK_SIZE: usize = <Md5Core as BlockSizeUser>::BlockSize::USIZE;

#[inline(always)]
fn convert(blocks: &[Block<Md5Core>]) -> &[[u8; BLOCK_SIZE]] {
    // SAFETY: Array<u8, U64> and [u8; 64] have
    // exactly the same memory layout
    let p = blocks.as_ptr() as *const [u8; BLOCK_SIZE];
    unsafe { core::slice::from_raw_parts(p, blocks.len()) }
}
