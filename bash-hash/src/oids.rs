use digest::const_oid::{AssociatedOid, ObjectIdentifier};

impl AssociatedOid for super::BashHash256 {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.112.0.2.0.34.101.77.11");
}

impl AssociatedOid for super::BashHash384 {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.112.0.2.0.34.101.77.12");
}

impl AssociatedOid for super::BashHash512 {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.112.0.2.0.34.101.77.13");
}
