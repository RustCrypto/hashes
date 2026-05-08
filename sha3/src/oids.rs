use digest::const_oid::{AssociatedOid, ObjectIdentifier};

impl AssociatedOid for super::Sha3_224 {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.7");
}

impl AssociatedOid for super::Sha3_256 {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.8");
}

impl AssociatedOid for super::Sha3_384 {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.9");
}

impl AssociatedOid for super::Sha3_512 {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.10");
}
