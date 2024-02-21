#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![warn(missing_docs, rust_2018_idioms)]

pub use digest::{self, Digest};

use core::fmt;
use digest::{
    array::Array,
    block_buffer::Eager,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore,
        OutputSizeUser, Reset, UpdateCore,
    },
    typenum::{Unsigned, U20, U64},
    HashMarker, Output,
};

#[cfg(feature = "oid")]
use digest::const_oid::{AssociatedOid, ObjectIdentifier};
#[cfg(feature = "zeroize")]
use digest::zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "collision")]
mod ubc_check;

mod compress;

pub use compress::compress;

const STATE_LEN: usize = 5;
const BLOCK_SIZE: usize = <Sha1Core as BlockSizeUser>::BlockSize::USIZE;

/// Core SHA-1 hasher state.
#[derive(Clone)]
pub struct Sha1Core {
    h: [u32; STATE_LEN],
    block_len: u64,
    #[cfg(feature = "collision")]
    detection: DetectionState,
}

/// The internal state used to do collision detection.
#[cfg(feature = "collision")]
#[derive(Clone)]
pub struct DetectionState {
    /// Should we detect collisions at all?
    detect_collision: bool,
    /// Should a fix be automatically be applied, or the original hash be returned?
    safe_hash: bool,
    /// Should unavoidable bitconditions be used to speed up the check?
    ubc_check: bool,
    /// Has a collision been detected?
    found_collision: bool,
    /// Has a reduced round collision been detected?
    reduced_round_collision: bool,
    ihv1: [u32; 5],
    ihv2: [u32; 5],
    m1: [u32; 80],
    m2: [u32; 80],
    /// Stores past states, for faster recompression.
    state_58: [u32; 5],
    state_65: [u32; 5],
}

#[cfg(feature = "collision")]
impl Default for DetectionState {
    fn default() -> Self {
        Self {
            detect_collision: true,
            safe_hash: false,
            ubc_check: true,
            reduced_round_collision: false,
            found_collision: false,
            ihv1: Default::default(),
            ihv2: Default::default(),
            m1: [0; 80],
            m2: [0; 80],
            state_58: Default::default(),
            state_65: Default::default(),
        }
    }
}

/// SHA-1 hasher state.
pub type Sha1 = CoreWrapper<Sha1Core>;

impl HashMarker for Sha1Core {}

impl BlockSizeUser for Sha1Core {
    type BlockSize = U64;
}

impl BufferKindUser for Sha1Core {
    type BufferKind = Eager;
}

impl OutputSizeUser for Sha1Core {
    type OutputSize = U20;
}

impl UpdateCore for Sha1Core {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.block_len += blocks.len() as u64;
        let blocks = Array::cast_slice_to_core(blocks);
        compress(
            &mut self.h,
            #[cfg(feature = "collision")]
            &mut self.detection,
            blocks,
        );
    }
}

impl FixedOutputCore for Sha1Core {
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let bs = Self::BlockSize::U64;
        let mut h = self.h;

        #[cfg(feature = "collision")]
        {
            let last_block = buffer.get_data();
            crate::compress::finalize(&mut h, bs * self.block_len, last_block, &mut self.detection);
        }
        #[cfg(not(feature = "collision"))]
        {
            use core::slice::from_ref;
            let bit_len = 8 * (buffer.get_pos() as u64 + bs * self.block_len);
            buffer.len64_padding_be(bit_len, |b| compress(&mut h, from_ref(&b.0)));
        }

        for (chunk, v) in out.chunks_exact_mut(4).zip(h.iter()) {
            chunk.copy_from_slice(&v.to_be_bytes());
        }
    }
}

impl Default for Sha1Core {
    #[inline]
    fn default() -> Self {
        Self {
            h: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            block_len: 0,
            #[cfg(feature = "collision")]
            detection: Default::default(),
        }
    }
}

impl Reset for Sha1Core {
    #[inline]
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl AlgorithmName for Sha1Core {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sha1")
    }
}

impl fmt::Debug for Sha1Core {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sha1Core { ... }")
    }
}

#[cfg(feature = "oid")]
#[cfg_attr(docsrs, doc(cfg(feature = "oid")))]
impl AssociatedOid for Sha1Core {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
}

impl Drop for Sha1Core {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            self.h.zeroize();
            self.block_len.zeroize();
        }
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for Sha1Core {}
