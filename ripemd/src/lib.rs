#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub use digest::{self, Digest};

use core::fmt;
use digest::{
    block_buffer::Eager,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore,
        OutputSizeUser, Reset, UpdateCore,
    },
    typenum::{Unsigned, U16, U20, U32, U40, U64},
    HashMarker, Output,
};

#[cfg(feature = "oid")]
use digest::const_oid::{AssociatedOid, ObjectIdentifier};
#[cfg(feature = "zeroize")]
use digest::zeroize::{Zeroize, ZeroizeOnDrop};

mod c128;
mod c160;
mod c256;
mod c320;

macro_rules! impl_ripemd {
    (
        $name:ident, $wrapped_name:ident, $mod:ident,
        $alg_width:expr, $doc_name:expr, $output_size:ty $(,)?
    ) => {
        #[doc = "Core block-level"]
        #[doc = $doc_name]
        #[doc = " hasher state."]
        #[derive(Clone)]
        pub struct $name {
            h: [u32; $mod::DIGEST_BUF_LEN],
            block_len: u64,
        }

        #[doc = $doc_name]
        #[doc = " hasher."]
        pub type $wrapped_name = CoreWrapper<$name>;

        impl HashMarker for $name {}

        impl BlockSizeUser for $name {
            type BlockSize = U64;
        }

        impl BufferKindUser for $name {
            type BufferKind = Eager;
        }

        impl OutputSizeUser for $name {
            type OutputSize = $output_size;
        }

        impl UpdateCore for $name {
            #[inline]
            fn update_blocks(&mut self, blocks: &[Block<Self>]) {
                // Assumes that `block_len` does not overflow
                self.block_len += blocks.len() as u64;
                for block in blocks {
                    $mod::compress(&mut self.h, block.as_ref());
                }
            }
        }

        impl FixedOutputCore for $name {
            #[inline]
            fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
                let bs = Self::BlockSize::U64;
                let bit_len = 8 * (buffer.get_pos() as u64 + bs * self.block_len);
                let mut h = self.h;
                buffer.len64_padding_le(bit_len, |block| $mod::compress(&mut h, block.as_ref()));

                for (chunk, v) in out.chunks_exact_mut(4).zip(h.iter()) {
                    chunk.copy_from_slice(&v.to_le_bytes());
                }
            }
        }

        impl Default for $name {
            #[inline]
            fn default() -> Self {
                Self {
                    h: $mod::H0,
                    block_len: 0,
                }
            }
        }

        impl Reset for $name {
            #[inline]
            fn reset(&mut self) {
                *self = Default::default();
            }
        }

        impl AlgorithmName for $name {
            #[inline]
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!("Ripemd", $alg_width))
            }
        }

        impl fmt::Debug for $name {
            #[inline]
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!("Ripemd", $alg_width, "Core { ... }"))
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                #[cfg(feature = "zeroize")]
                {
                    self.h.zeroize();
                    self.block_len.zeroize();
                }
            }
        }

        #[cfg(feature = "zeroize")]
        impl ZeroizeOnDrop for $name {}
    };
}

impl_ripemd!(Ripemd128Core, Ripemd128, c128, "128", "RIPEMD-128", U16);
impl_ripemd!(Ripemd160Core, Ripemd160, c160, "160", "RIPEMD-160", U20);
impl_ripemd!(Ripemd256Core, Ripemd256, c256, "256", "RIPEMD-256", U32);
impl_ripemd!(Ripemd320Core, Ripemd320, c320, "320", "RIPEMD-320", U40);

#[cfg(feature = "oid")]
#[cfg_attr(docsrs, doc(cfg(feature = "oid")))]
impl AssociatedOid for Ripemd128Core {
    /// The OID used for the RIPEMD-160. There are two OIDs defined. The Teletrust one (which is
    /// used by almost anybody, including BouncyCastle, OpenSSL, GnuTLS, etc. and the ISO one
    /// (1.0.10118.3.0.50), which seems to be used by nobody.
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.36.3.2.2");
}

#[cfg(feature = "oid")]
#[cfg_attr(docsrs, doc(cfg(feature = "oid")))]
impl AssociatedOid for Ripemd160Core {
    /// The OID used for the RIPEMD-160. There are two OIDs defined. The Teletrust one (which is
    /// used by almost anybody, including BouncyCastle, OpenSSL, GnuTLS, etc. and the ISO one
    /// (1.0.10118.3.0.49), which seems to be used by Go and nobody else.
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.36.3.2.1");
}

#[cfg(feature = "oid")]
#[cfg_attr(docsrs, doc(cfg(feature = "oid")))]
impl AssociatedOid for Ripemd256Core {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.36.3.2.3");
}
