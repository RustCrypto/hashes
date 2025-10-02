#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, unreachable_pub)]
#![forbid(unsafe_code)]

pub use digest::{self, Digest};

/// Block-level types
pub mod block_api;
/// GOST94 parameters.
pub mod params;

use params::Gost94Params;

digest::buffer_fixed!(
    /// GOST94 hash function generic over parameters.
    pub struct Gost94<P: Gost94Params>(block_api::Gost94Core<P>);
    impl: FixedHashTraits;
);

/// GOST94 hash function with CryptoPro parameters.
pub type Gost94CryptoPro = Gost94<params::CryptoProParam>;
/// GOST94 hash function with S-box defined in GOST R 34.12-2015.
pub type Gost94s2015 = Gost94<params::S2015Param>;
/// GOST94 hash function with test parameters.
pub type Gost94Test = Gost94<params::TestParam>;
/// GOST94 hash function with UAPKI GOST 34.311-95 parameters
pub type Gost94UA = Gost94<params::GOST28147UAParam>;

#[cfg(feature = "oid")]
mod oids {
    use digest::const_oid::{AssociatedOid, ObjectIdentifier};

    impl AssociatedOid for super::Gost94CryptoPro {
        // From RFC 4490
        const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.643.2.2.9");
    }

    impl AssociatedOid for super::Gost94UA {
        const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.804.2.1.1.1.1.2.1");
    }
}
