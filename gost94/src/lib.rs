#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![warn(missing_docs)]
#![forbid(unsafe_code)]

pub use digest::{self, Digest};

use core::fmt;
use digest::{
    FixedOutput, FixedOutputReset, HashMarker, Output, OutputSizeUser, Reset, Update,
    consts::U129,
    core_api::{AlgorithmName, BlockSizeUser, CoreWrapper},
    crypto_common::hazmat::{DeserializeStateError, SerializableState, SerializedState},
};

#[cfg(feature = "oid")]
use digest::const_oid::{AssociatedOid, ObjectIdentifier};

mod gost94_core;
/// GOST94 parameters.
pub mod params;

pub use gost94_core::Gost94Core;
use params::Gost94Params;

/// GOST94 hash function with CryptoPro parameters.
pub struct Gost94<P: Gost94Params>(CoreWrapper<Gost94Core<P>>);

/// GOST94 hash function with CryptoPro parameters.
pub type Gost94CryptoPro = Gost94<params::CryptoProParam>;
/// GOST94 hash function with S-box defined in GOST R 34.12-2015.
pub type Gost94s2015 = Gost94<params::S2015Param>;
/// GOST94 hash function with test parameters.
pub type Gost94Test = Gost94<params::TestParam>;
/// GOST94 hash function with UAPKI GOST 34.311-95 parameters
pub type Gost94UA = Gost94<params::GOST28147UAParam>;

impl<P: Gost94Params> fmt::Debug for Gost94<P> {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Gost94<{}> {{ ... }}", P::NAME)
    }
}

impl<P: Gost94Params> AlgorithmName for Gost94<P> {
    #[inline]
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Gost94<{}> {{ ... }}", P::NAME)
    }
}

impl<P: Gost94Params> Clone for Gost94<P> {
    #[inline]
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<P: Gost94Params> Default for Gost94<P> {
    #[inline]
    fn default() -> Self {
        Self(Default::default())
    }
}

impl<P: Gost94Params> Reset for Gost94<P> {
    #[inline]
    fn reset(&mut self) {
        Reset::reset(&mut self.0);
    }
}

impl<P: Gost94Params> Update for Gost94<P> {
    #[inline]
    fn update(&mut self, data: &[u8]) {
        Update::update(&mut self.0, data);
    }
}

impl<P: Gost94Params> FixedOutput for Gost94<P> {
    #[inline]
    fn finalize_into(self, out: &mut Output<Self>) {
        FixedOutput::finalize_into(self.0, out);
    }
}

impl<P: Gost94Params> FixedOutputReset for Gost94<P> {
    #[inline]
    fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
        FixedOutputReset::finalize_into_reset(&mut self.0, out);
    }
}

impl<P: Gost94Params> HashMarker for Gost94<P> {}

impl<P: Gost94Params> BlockSizeUser for Gost94<P> {
    type BlockSize = <Gost94Core<P> as BlockSizeUser>::BlockSize;
}

impl<P: Gost94Params> OutputSizeUser for Gost94<P> {
    type OutputSize = <Gost94Core<P> as OutputSizeUser>::OutputSize;
}

impl<P: Gost94Params> SerializableState for Gost94<P> {
    type SerializedStateSize = U129;

    #[inline]
    fn serialize(&self) -> SerializedState<Self> {
        self.0.serialize()
    }

    #[inline]
    fn deserialize(
        serialized_state: &SerializedState<Self>,
    ) -> Result<Self, DeserializeStateError> {
        SerializableState::deserialize(serialized_state).map(Self)
    }
}

#[cfg(feature = "oid")]
impl AssociatedOid for Gost94CryptoPro {
    // From RFC 4490
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.643.2.2.9");
}

#[cfg(feature = "oid")]
impl AssociatedOid for Gost94UA {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.804.2.1.1.1.1.2.1");
}
