use digest::dev::{feed_rand_16mib, fixed_reset_test};
use digest::{hash_serialization_test, new_test};
use hex_literal::hex;
use sm3::{Digest, Sm3};

new_test!(sm3_main, "sm3", Sm3, fixed_reset_test);

#[rustfmt::skip]
hash_serialization_test!(
    sm3_serialization,
    Sm3,
    hex!("
        ca87204f0aac075dbfa7088e245ff9f9
        6e941eb2b5b63e57fdedfa1d2e1f5a27
        01000000000000000113000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        000000000000000000
    ")
);

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
