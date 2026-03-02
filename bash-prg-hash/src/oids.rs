use digest::const_oid::{AssociatedOid, ObjectIdentifier};

use crate::{
    block_api::BashPrgHashCore,
    variants::{Cap1, Cap2, Level128, Level192, Level256},
};

impl AssociatedOid for BashPrgHashCore<Level128, Cap1> {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.112.0.2.0.34.101.77.21");
}

impl AssociatedOid for BashPrgHashCore<Level128, Cap2> {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.112.0.2.0.34.101.77.22");
}

impl AssociatedOid for BashPrgHashCore<Level192, Cap1> {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.112.0.2.0.34.101.77.23");
}

impl AssociatedOid for BashPrgHashCore<Level192, Cap2> {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.112.0.2.0.34.101.77.24");
}

impl AssociatedOid for BashPrgHashCore<Level256, Cap1> {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.112.0.2.0.34.101.77.25");
}

impl AssociatedOid for BashPrgHashCore<Level256, Cap2> {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.112.0.2.0.34.101.77.26");
}
