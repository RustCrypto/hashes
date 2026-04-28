use digest::const_oid::{AssociatedOid, ObjectIdentifier};

use crate::{
    BashPrgHash1281, BashPrgHash1282, BashPrgHash1921, BashPrgHash1922, BashPrgHash2561,
    BashPrgHash2562,
};

impl AssociatedOid for BashPrgHash1281 {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.112.0.2.0.34.101.77.21");
}

impl AssociatedOid for BashPrgHash1282 {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.112.0.2.0.34.101.77.22");
}

impl AssociatedOid for BashPrgHash1921 {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.112.0.2.0.34.101.77.23");
}

impl AssociatedOid for BashPrgHash1922 {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.112.0.2.0.34.101.77.24");
}

impl AssociatedOid for BashPrgHash2561 {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.112.0.2.0.34.101.77.25");
}

impl AssociatedOid for BashPrgHash2562 {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.112.0.2.0.34.101.77.26");
}
