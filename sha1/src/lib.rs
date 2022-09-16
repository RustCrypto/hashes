//! Pure Rust implementation of the [SHA-1][1] cryptographic hash algorithm
//! with optional hardware-specific optimizations.
//!
//! # 🚨 Warning: Cryptographically Broken! 🚨
//!
//! The SHA-1 hash function should be considered cryptographically broken and
//! unsuitable for further use in any security critical capacity, as it is
//! [practically vulnerable to chosen-prefix collisions][2].
//!
//! We provide this crate for legacy interoperability purposes only.
//!
//! # Usage
//!
//! ```rust
//! use hex_literal::hex;
//! use sha1::{Sha1, Digest};
//!
//! // create a Sha1 object
//! let mut hasher = Sha1::new();
//!
//! // process input message
//! hasher.update(b"hello world");
//!
//! // acquire hash digest in the form of GenericArray,
//! // which in this case is equivalent to [u8; 20]
//! let result = hasher.finalize();
//! assert_eq!(result[..], hex!("2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"));
//! ```
//!
//! Also see [RustCrypto/hashes][3] readme.
//!
//! # Note for users of `sha1 v0.6`
//!
//! This crate has been transferred to the RustCrypto organization and uses
//! implementation previously published as the `sha-1` crate. The previous
//! zero dependencies version is now published as the [`sha1_smoll`] crate.
//!
//! [1]: https://en.wikipedia.org/wiki/SHA-1
//! [2]: https://sha-mbles.github.io/
//! [3]: https://github.com/RustCrypto/hashes
//! [`sha1_smoll`]: https://github.com/mitsuhiko/sha1-smol/

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![warn(missing_docs, rust_2018_idioms)]

pub use digest::{self, Digest};

use core::{convert::TryInto, fmt, slice::from_ref};
#[cfg(feature = "oid")]
use digest::const_oid::{AssociatedOid, ObjectIdentifier};
use digest::{
    block_buffer::Eager,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore,
        OutputSizeUser, Reset, UpdateCore,
    },
    crypto_common::{DeserializeStateError, SerializableState, SerializedState},
    generic_array::{
        sequence::{Concat, Split},
        GenericArray,
    },
    typenum::{Unsigned, U20, U28, U64},
    HashMarker, Output,
};

mod compress;

#[cfg(feature = "compress")]
pub use compress::compress;
#[cfg(not(feature = "compress"))]
use compress::compress;

const STATE_LEN: usize = 5;

/// Core SHA-1 hasher state.
#[derive(Clone)]
pub struct Sha1Core {
    h: [u32; STATE_LEN],
    block_len: u64,
}

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
        compress(&mut self.h, blocks);
    }
}

impl FixedOutputCore for Sha1Core {
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let bs = Self::BlockSize::U64;
        let bit_len = 8 * (buffer.get_pos() as u64 + bs * self.block_len);

        let mut h = self.h;
        buffer.len64_padding_be(bit_len, |b| compress(&mut h, from_ref(b)));
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

impl SerializableState for Sha1Core {
    type SerializedStateSize = U28;

    fn serialize(&self) -> SerializedState<Self> {
        let mut serialized_h = GenericArray::<_, U20>::default();

        for (val, chunk) in self.h.iter().zip(serialized_h.chunks_exact_mut(4)) {
            chunk.copy_from_slice(&val.to_le_bytes());
        }

        serialized_h.concat(self.block_len.to_le_bytes().into())
    }

    fn deserialize(
        serialized_state: &SerializedState<Self>,
    ) -> Result<Self, DeserializeStateError> {
        let (serialized_h, serialized_block_len) = Split::<_, U20>::split(serialized_state);

        let mut h = [0; STATE_LEN];
        for (val, chunk) in h.iter_mut().zip(serialized_h.chunks_exact(4)) {
            *val = u32::from_le_bytes(chunk.try_into().unwrap());
        }

        let block_len = u64::from_le_bytes((*serialized_block_len).into());

        Ok(Self { h, block_len })
    }
}

/// SHA-1 hasher state.
pub type Sha1 = CoreWrapper<Sha1Core>;
