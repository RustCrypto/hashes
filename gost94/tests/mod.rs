#[cfg(feature = "oid")]
use digest::const_oid::{AssociatedOid, ObjectIdentifier};
use digest::dev::{feed_rand_16mib, fixed_reset_test};
use digest::{hash_serialization_test, new_test};
use gost94::{Digest, Gost94CryptoPro, Gost94Test, Gost94UA, Gost94s2015};
use hex_literal::hex;

new_test!(gost94_test_main, "test", Gost94Test, fixed_reset_test);
new_test!(
    gost94_cryptopro_main,
    "cryptopro",
    Gost94CryptoPro,
    fixed_reset_test
);

#[rustfmt::skip]
hash_serialization_test!(
    gost94_crypto_pro_serialization,
    Gost94CryptoPro,
    hex!("
        51aeb30f746350e15ef31472e3914b1b
        4b9198e0272881ff2401cea8490e5ab2
        00010000000000000000000000000000
        00000000000000000000000000000000
        13131313131313131313131313131313
        13131313131313131313131313131313
        01130000000000000000000000000000
        00000000000000000000000000000000
        00
    ")
);
#[rustfmt::skip]
hash_serialization_test!(
    gost94_test_serialization,
    Gost94Test,
    hex!("
        81bba4e852b20165ac12b2151cd38b47
        821cfd45ad739fb03018021a77750754
        00010000000000000000000000000000
        00000000000000000000000000000000
        13131313131313131313131313131313
        13131313131313131313131313131313
        01130000000000000000000000000000
        00000000000000000000000000000000
        00
    ")
);
#[rustfmt::skip]
hash_serialization_test!(
    gost94_ua_serialization,
    Gost94UA,
    hex!("
        7755aa3d77c2026677adf176fd722741
        742a184862f353ec99b1f7928ff0eaa4
        00010000000000000000000000000000
        00000000000000000000000000000000
        13131313131313131313131313131313
        13131313131313131313131313131313
        01130000000000000000000000000000
        00000000000000000000000000000000
        00
    ")
);
#[rustfmt::skip]
hash_serialization_test!(
    gost94_s_2015_serialization,
    Gost94s2015,
    hex!("
        d29b34011a22a27037ea42d36a512910
        913482fdc2349ab02ca1087a50745d5b
        00010000000000000000000000000000
        00000000000000000000000000000000
        13131313131313131313131313131313
        13131313131313131313131313131313
        01130000000000000000000000000000
        00000000000000000000000000000000
        00
    ")
);

#[test]
fn gost94_test_rand() {
    let mut h = Gost94Test::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize(),
        hex!("fdd1b9f220898c117f82d664716795e12f5e9f458ee8cd71d014329438db5089")
    );
}

#[test]
fn gost94_cryptopro_rand() {
    let mut h = Gost94CryptoPro::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize(),
        hex!("1d539ea8a318df8c13d304fcfd9beeec188bb48683d9d7f4c4a3750cff6ef22a")
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
        h.finalize_reset(),
        hex!("f7fc6d16a6a5c12ac4f7d320e0fd0d8354908699125e09727a4ef929122b1cae"),
    );

    for _ in 0..128 {
        h.update(b"\x00\x01\x02\x15\x84\x67\x45\x31");
    }
    assert_eq!(
        h.finalize_reset(),
        hex!("69f529aa82d9344ab0fa550cdf4a70ecfd92a38b5520b1906329763e09105196"),
    );

    let mut buf = Vec::new();
    for _ in 0..128 {
        buf.extend_from_slice(b"12345670");
    }
    h.update(&buf[0..539]);
    assert_eq!(
        h.finalize_reset(),
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
        h.finalize(),
        hex!("e5d3ac4ea3f67896c51ff919cedb9405ad771e39f0f2eab103624f9a758e506f"),
    );
}

#[test]
fn arithmetic_overflow_regression() {
    let mut h = Gost94Test::default();
    h.update(&include_bytes!("data/arithmetic_overflow.bin")[..]);
    h.finalize();
}

#[test]
fn gost_ua_engine_tests() {
    let mut h = Gost94UA::new();
    h.update(b"test");
    assert_eq!(
        h.finalize_reset(),
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
