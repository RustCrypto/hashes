use digest::dev::{feed_rand_16mib, fixed_reset_test};
use hex_literal::hex;
use sm3::{Digest, Sm3};

digest::new_test!(sm3_kat, Sm3, fixed_reset_test);
digest::hash_serialization_test!(sm3_serialization, Sm3);

#[test]
fn sm3_rand() {
    let mut h = Sm3::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize(),
        hex!("ad154967b08d636a148dd4c688a6df7add1ed1946af18eb358a9b320de2aca86"),
    );
}

#[cfg(feature = "oid")]
#[test]
fn sm3_oid() {
    use sm3::digest::const_oid::{AssociatedOid, ObjectIdentifier};
    assert_eq!(
        Sm3::OID,
        ObjectIdentifier::new_unwrap("1.2.156.10197.1.401")
    );
}
