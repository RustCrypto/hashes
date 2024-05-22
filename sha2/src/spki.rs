//! Implements [`AlgorithmIdentifier`] according to [RFC5754 section 2]
//!
//! [RFC5754 section 2]: https://www.rfc-editor.org/rfc/rfc5754#section-2

use digest::{
    const_oid::AssociatedOid,
    spki::{der::asn1::AnyRef, AlgorithmIdentifierRef, AssociatedAlgorithmIdentifier},
};

use super::{OidSha224, OidSha256, OidSha384, OidSha512};

macro_rules! impl_aai {
    ($name:ident) => {
        impl AssociatedAlgorithmIdentifier for $name {
            type Params = AnyRef<'static>;

            const ALGORITHM_IDENTIFIER: AlgorithmIdentifierRef<'static> = AlgorithmIdentifierRef {
                oid: Self::OID,
                parameters: None,
            };
        }
    };
}

impl_aai!(OidSha224);
impl_aai!(OidSha256);
impl_aai!(OidSha384);
impl_aai!(OidSha512);
