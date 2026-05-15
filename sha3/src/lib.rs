#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]
#![warn(unreachable_pub)]

pub use digest::{self, Digest};

use core::fmt;
use digest::{
    FixedOutput, FixedOutputReset, HashMarker, Output, OutputSizeUser, Reset, Update,
    common::{
        AlgorithmName, BlockSizeUser,
        hazmat::{DeserializeStateError, SerializableState, SerializedState},
    },
    consts::{U28, U32, U48, U64, U72, U104, U136, U144, U200, U201},
    typenum::Unsigned,
};
use keccak::{Keccak, State1600};

#[cfg(feature = "oid")]
mod oids;
mod utils;

macro_rules! impl_sha3_variants {
    ($(
        $(#[$attr:meta])*
        $name:ident($rate_ty:ty, $out_len:ty, $pad:expr);
    )*) => {$(
        $(#[$attr])*
        #[derive(Clone, Default)]
        pub struct $name {
            state: State1600,
            cursor: sponge_cursor::SpongeCursor<{ <$rate_ty>::USIZE }>,
            keccak: Keccak,
        }

        impl Reset for $name {
            #[inline]
            fn reset(&mut self) {
                self.state = Default::default();
                self.cursor = Default::default();
            }
        }

        impl HashMarker for $name {}

        impl Update for $name {
            #[inline]
            fn update(&mut self, data: &[u8]) {
                self.keccak.with_f1600(|f1600| {
                    self.cursor.absorb_u64_le(&mut self.state, f1600, data);
                });
            }
        }

        impl BlockSizeUser for $name {
            type BlockSize = $rate_ty;
        }

        impl OutputSizeUser for $name {
            type OutputSize = $out_len;
        }

        impl FixedOutput for $name {
            fn finalize_into(mut self, dst: &mut Output<Self>) {
                utils::pad::<$pad, { <$rate_ty>::USIZE }>(&mut self.state, &self.cursor);
                self.keccak.with_f1600(|f1600| {
                    f1600(&mut self.state);
                    utils::read_state(&mut self.state, dst);
                });
            }
        }

        impl FixedOutputReset for $name {
            fn finalize_into_reset(&mut self, dst: &mut Output<Self>) {
                utils::pad::<$pad, { <$rate_ty>::USIZE }>(&mut self.state, &self.cursor);
                self.keccak.with_f1600(|f1600| {
                    f1600(&mut self.state);
                    utils::read_state(&mut self.state, dst);
                });
                Reset::reset(self);
            }
        }

        impl AlgorithmName for $name {
            #[inline]
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(stringify!($name))
            }
        }

        impl SerializableState for $name {
            type SerializedStateSize = U201;

            fn serialize(&self) -> SerializedState<Self> {
                utils::serialize(&self.state, &self.cursor).into()
            }

            fn deserialize(
                serialized_state: &SerializedState<Self>,
            ) -> Result<Self, DeserializeStateError> {
                utils::deserialize(serialized_state.into())
                    .ok_or(DeserializeStateError)
                    .map(|(state, cursor)| Self {
                        state,
                        cursor,
                        keccak: Keccak::new(),
                    })
            }
        }

        impl fmt::Debug for $name {
            #[inline]
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), " { ... }"))
            }
        }

        impl Drop for $name {
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
        impl digest::zeroize::ZeroizeOnDrop for $name {}
    )*};
}

const KECCAK_PAD: u8 = 0x01;
const SHA3_PAD: u8 = 0x06;

impl_sha3_variants!(
    /// SHA-3-224 hasher.
    Sha3_224(U144, U28, SHA3_PAD);
    /// SHA-3-256 hasher.
    Sha3_256(U136, U32, SHA3_PAD);
    /// SHA-3-384 hasher.
    Sha3_384(U104, U48, SHA3_PAD);
    /// SHA-3-256 hasher.
    Sha3_512(U72, U64, SHA3_PAD);

    /// Keccak-224 hasher.
    Keccak224(U144, U28, KECCAK_PAD);
    /// Keccak-256 hasher.
    Keccak256(U136, U32, KECCAK_PAD);
    /// Keccak-384 hasher.
    Keccak384(U104, U48, KECCAK_PAD);
    /// Keccak-512 hasher.
    Keccak512(U72, U64, KECCAK_PAD);

    /// CryptoNight variant of SHA-3.
    Keccak256Full(U136, U200, KECCAK_PAD);
);
