#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, unreachable_pub)]

pub use digest;

/// Block-level types
pub mod block_api;

use core::fmt;
use digest::{
    CollisionResistance, ExtendableOutput, HashMarker, Reset, Update, XofReader,
    block_api::{AlgorithmName, BlockSizeUser, ExtendableOutputCore, UpdateCore, XofReaderCore},
    block_buffer::{BlockBuffer, Eager, ReadBuffer},
    consts::{U16, U32, U128, U136, U168},
};

macro_rules! impl_k12 {
    (
        $name:ident, $reader_name:ident, $core_name:ident, $reader_core_name:ident, $rate:ty,
        $alg_name:literal,
    ) => {
        #[doc = $alg_name]
        #[doc = "hasher."]
        #[derive(Default, Clone)]
        pub struct $name<'cs> {
            core: block_api::$core_name<'cs>,
            buffer: BlockBuffer<U128, Eager>,
        }

        impl<'cs> $name<'cs> {
            #[doc = "Creates a new"]
            #[doc = $alg_name]
            #[doc = "instance with the given customization."]
            pub fn new(customization: &'cs [u8]) -> Self {
                Self {
                    core: block_api::$core_name::new(customization),
                    buffer: Default::default(),
                }
            }
        }

        impl fmt::Debug for $name<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
                f.write_str(concat!(stringify!($name), " { .. }"))
            }
        }

        impl AlgorithmName for $name<'_> {
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str($alg_name)
            }
        }

        impl HashMarker for $name<'_> {}

        impl BlockSizeUser for $name<'_> {
            type BlockSize = U128;
        }

        impl Update for $name<'_> {
            fn update(&mut self, data: &[u8]) {
                let Self { core, buffer } = self;
                buffer.digest_blocks(data, |blocks| core.update_blocks(blocks));
            }
        }

        impl Reset for $name<'_> {
            fn reset(&mut self) {
                self.core.reset();
                self.buffer.reset();
            }
        }

        impl ExtendableOutput for $name<'_> {
            type Reader = $reader_name;

            #[inline]
            fn finalize_xof(mut self) -> Self::Reader {
                Self::Reader {
                    core: self.core.finalize_xof_core(&mut self.buffer),
                    buffer: Default::default(),
                }
            }
        }

        #[cfg(feature = "zeroize")]
        impl digest::zeroize::ZeroizeOnDrop for $name<'_> {}

        #[doc = $alg_name]
        #[doc = "XOF reader."]
        pub struct $reader_name {
            core: block_api::$reader_core_name,
            buffer: ReadBuffer<$rate>,
        }

        impl fmt::Debug for $reader_name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
                f.write_str(concat!(stringify!($reader_name), " { .. }"))
            }
        }

        impl XofReader for $reader_name {
            #[inline]
            fn read(&mut self, buffer: &mut [u8]) {
                let Self { core, buffer: buf } = self;
                buf.read(buffer, |block| *block = core.read_block());
            }
        }

        #[cfg(feature = "zeroize")]
        impl digest::zeroize::ZeroizeOnDrop for $reader_name {}
    };
}

impl_k12!(
    Kt128,
    Kt128Reader,
    Kt128Core,
    Kt128ReaderCore,
    U168,
    "KT128",
);
impl_k12!(
    Kt256,
    Kt256Reader,
    Kt256Core,
    Kt256ReaderCore,
    U136,
    "KT256",
);

impl CollisionResistance for Kt128<'_> {
    // https://www.rfc-editor.org/rfc/rfc9861.html#section-7-7
    type CollisionResistance = U16;
}

impl CollisionResistance for Kt256<'_> {
    // https://www.rfc-editor.org/rfc/rfc9861.html#section-7-8
    type CollisionResistance = U32;
}

/// KT128 hasher.
#[deprecated(since = "0.4.0-pre", note = "use `Kt128` instead")]
pub type KangarooTwelve<'cs> = Kt128<'cs>;

/// KT128 XOF reader.
#[deprecated(since = "0.4.0-pre", note = "use `Kt128Reader` instead")]
pub type KangarooTwelveReader = Kt128Reader;
