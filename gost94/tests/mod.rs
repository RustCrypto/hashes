#[cfg(feature = "oid")]
use digest::const_oid::{AssociatedOid, ObjectIdentifier};
use digest::dev::{feed_rand_16mib, fixed_reset_test};
use digest::new_test;
use gost94::{Digest, Gost94CryptoPro, Gost94Test, Gost94UA};
use hex_literal::hex;

new_test!(gost94_test_main, "test", Gost94Test, fixed_reset_test);
new_test!(
    gost94_cryptopro_main,
    "cryptopro",
    Gost94CryptoPro,
    fixed_reset_test
);

#[test]
fn gost94_test_rand() {
    let mut h = Gost94Test::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize()[..],
        hex!("fdd1b9f220898c117f82d664716795e12f5e9f458ee8cd71d014329438db5089")[..]
    );
}

#[test]
fn gost94_cryptopro_rand() {
    let mut h = Gost94CryptoPro::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize()[..],
        hex!("1d539ea8a318df8c13d304fcfd9beeec188bb48683d9d7f4c4a3750cff6ef22a")[..]
    );
}

/// Test vectors from:
/// https://github.com/gost-engine/engine/blob/master/test/01-digest.t
#[test]
fn gost_engine_tests() {
    let mut h = Gost94CryptoPro::new();
    for _ in 0..128 {
        h.update(b"12345670");
    }
    assert_eq!(
        h.finalize_reset().as_slice(),
        hex!("f7fc6d16a6a5c12ac4f7d320e0fd0d8354908699125e09727a4ef929122b1cae"),
    );

    for _ in 0..128 {
        h.update(b"\x00\x01\x02\x15\x84\x67\x45\x31");
    }
    assert_eq!(
        h.finalize_reset().as_slice(),
        hex!("69f529aa82d9344ab0fa550cdf4a70ecfd92a38b5520b1906329763e09105196"),
    );

    let mut buf = Vec::new();
    for _ in 0..128 {
        buf.extend_from_slice(b"12345670");
    }
    h.update(&buf[0..539]);
    assert_eq!(
        h.finalize_reset().as_slice(),
        hex!("bd5f1e4b539c7b00f0866afdbc8ed452503a18436061747a343f43efe888aac9"),
    );

    for _ in 0..4096 {
        for _ in 0..7 {
            h.update(b"121345678");
        }
        h.update(b"1234567\n");
    }
    h.update("12345\n");
    assert_eq!(
        h.finalize().as_slice(),
        hex!("e5d3ac4ea3f67896c51ff919cedb9405ad771e39f0f2eab103624f9a758e506f"),
    );
}

#[test]
fn arithmetic_overflow_regression() {
    let mut h = Gost94Test::default();
    h.update(&include_bytes!("data/arithmetic_overflow.bin")[..]);
    h.finalize().as_slice();
}

#[test]
fn gost_ua_engine_tests() {
    let mut h = Gost94UA::new();
    h.update(b"test");
    assert_eq!(
        h.finalize_reset().as_slice(),
        hex!("7c536414f8b5b9cc649fdf3cccb2685c1a12622956308e34f31c50ed7b3af56c"),
    );
}

#[cfg(feature = "oid")]
#[test]
fn gost_oid_tests() {
    assert_eq!(
        Gost94CryptoPro::OID,
        ObjectIdentifier::new_unwrap("1.2.643.2.2.9")
    );
    assert_eq!(
        Gost94UA::OID,
        ObjectIdentifier::new_unwrap("1.2.804.2.1.1.1.1.2.1")
    );
}
