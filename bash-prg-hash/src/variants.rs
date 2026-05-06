use crate::BashPrgHash;
use digest::{
    CollisionResistance,
    consts::{U16, U24, U32},
};

/// `bash-prg-hash` with ℓ = 128 and d = 1
pub type BashPrgHash1281 = BashPrgHash<160, 1>;
/// `bash-prg-hash` with ℓ = 128 and d = 2
pub type BashPrgHash1282 = BashPrgHash<128, 2>;
/// `bash-prg-hash` with ℓ = 192 and d = 1
pub type BashPrgHash1921 = BashPrgHash<144, 1>;
/// `bash-prg-hash` with ℓ = 192 and d = 2
pub type BashPrgHash1922 = BashPrgHash<96, 2>;
/// `bash-prg-hash` with ℓ = 256 and d = 1
pub type BashPrgHash2561 = BashPrgHash<128, 1>;
/// `bash-prg-hash`` with ℓ = 256 and d = 2
pub type BashPrgHash2562 = BashPrgHash<64, 2>;

impl CollisionResistance for BashPrgHash1281 {
    type CollisionResistance = U16;
}
impl CollisionResistance for BashPrgHash1282 {
    type CollisionResistance = U16;
}
impl CollisionResistance for BashPrgHash1921 {
    type CollisionResistance = U24;
}
impl CollisionResistance for BashPrgHash1922 {
    type CollisionResistance = U24;
}
impl CollisionResistance for BashPrgHash2561 {
    type CollisionResistance = U32;
}
impl CollisionResistance for BashPrgHash2562 {
    type CollisionResistance = U32;
}

#[cfg(feature = "oid")]
mod oids {
    use digest::const_oid::{AssociatedOid, ObjectIdentifier};

    impl AssociatedOid for super::BashPrgHash1281 {
        const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.112.0.2.0.34.101.77.21");
    }

    impl AssociatedOid for super::BashPrgHash1282 {
        const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.112.0.2.0.34.101.77.22");
    }

    impl AssociatedOid for super::BashPrgHash1921 {
        const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.112.0.2.0.34.101.77.23");
    }

    impl AssociatedOid for super::BashPrgHash1922 {
        const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.112.0.2.0.34.101.77.24");
    }

    impl AssociatedOid for super::BashPrgHash2561 {
        const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.112.0.2.0.34.101.77.25");
    }

    impl AssociatedOid for super::BashPrgHash2562 {
        const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.112.0.2.0.34.101.77.26");
    }
}
