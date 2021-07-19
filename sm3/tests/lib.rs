use digest::dev::{digest_test, one_million_a};
use digest::new_test;

new_test!(sm3_main, "sm3", sm3::Sm3, digest_test);

#[test]
fn sm3_1million_a() {
    let output = include_bytes!("data/sm3_one_million_a.bin");
    one_million_a::<sm3::Sm3>(output);
}

/// Test vectors from libgcrypt
#[test]
#[rustfmt::skip]
fn sm3_tests() {
    use digest::Digest;
    use hex_literal::hex;

    let hash = &mut sm3::Sm3::new();

    hash.update(b"abc");
    assert_eq!(hash.finalize_reset().as_slice(),
        hex!("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"));

    hash.update(b"abcdefghijklmnopqrstuvwxyz");
    assert_eq!(hash.finalize_reset().as_slice(),
        hex!("b80fe97a4da24afc277564f66a359ef440462ad28dcc6d63adb24d5c20a61595"));
}
