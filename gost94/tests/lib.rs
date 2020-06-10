use digest::dev::{digest_test, one_million_a};
use digest::new_test;

new_test!(gost94_test_main, "test", gost94::Gost94Test, digest_test);
new_test!(
    gost94_cryptopro_main,
    "cryptopro",
    gost94::Gost94CryptoPro,
    digest_test
);

#[test]
fn gost94_test_1million_a() {
    let output = include_bytes!("data/test_one_million_a.bin");
    one_million_a::<gost94::Gost94Test>(output);
}

#[test]
fn gost94_cryptopro_1million_a() {
    let output = include_bytes!("data/cryptopro_one_million_a.bin");
    one_million_a::<gost94::Gost94CryptoPro>(output);
}

/// Test vectors from:
/// https://github.com/gost-engine/engine/blob/master/test/01-digest.t
#[test]
fn gost_engine_tests() {
    use digest::Digest;
    use hex_literal::hex;

    let mut h = gost94::Gost94CryptoPro::new();
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
