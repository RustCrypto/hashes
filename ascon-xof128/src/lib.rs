#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, unreachable_pub)]
#![forbid(unsafe_code)]

pub use digest::{self, ExtendableOutput, Update, XofReader};

/// Block-level types
pub mod block_api;

use digest::{CollisionResistance, consts::U16};

digest::buffer_xof!(
    /// Ascon-XOF128 hasher.
    pub struct AsconXof128(block_api::AsconXof128Core);
    impl: XofHasherTraits;
    /// Ascon-XOF128 reader.
    pub struct AsconXof128Reader(block_api::AsconXofReaderCore);
    impl: XofReaderTraits;
);

digest::buffer_xof!(
    /// Ascon-CXOF128 hasher.
    pub struct AsconCxof128(block_api::AsconCxof128Core);
    impl: Debug AlgorithmName Clone Default BlockSizeUser CoreProxy
        HashMarker Update SerializableState CustomizedInit;
    /// Ascon-CXOF128 reader.
    pub struct AsconCxof128Reader(block_api::AsconXofReaderCore);
    impl: XofReaderTraits;
);

// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-232.ipd.pdf#table.caption.25
impl CollisionResistance for AsconXof128 {
    type CollisionResistance = U16;
}
impl CollisionResistance for AsconCxof128 {
    type CollisionResistance = U16;
}
