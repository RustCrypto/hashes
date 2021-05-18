use digest::dev::one_million_a;
use hex_literal::hex;
use ripemd256::{Digest, Ripemd256};

fn hash_test(msg: &str, expected: [u8; 32]) {
    let mut hasher = Ripemd256::new();
    hasher.update(msg.as_bytes());
    let result = hasher.finalize();
    assert_eq!(result[..], expected);
}

#[test]
fn ripemd256_messages() {
    hash_test(
        "",
        hex!("02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d"),
    );
    hash_test(
        "a",
        hex!("f9333e45d857f5d90a91bab70a1eba0cfb1be4b0783c9acfcd883a9134692925"),
    );
    hash_test(
        "abc",
        hex!("afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65"),
    );
    hash_test(
        "message digest",
        hex!("87e971759a1ce47a514d5c914c392c9018c7c46bc14465554afcdf54a5070c0e"),
    );
    hash_test(
        "abcdefghijklmnopqrstuvwxyz",
        hex!("649d3034751ea216776bf9a18acc81bc7896118a5197968782dd1fd97d8d5133"),
    );
    hash_test(
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        hex!("3843045583aac6c8c8d9128573e7a9809afb2a0f34ccc36ea9e72f16f6368e3f"),
    );
    hash_test(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        hex!("5740a408ac16b720b84424ae931cbb1fe363d1d0bf4017f1a89f7ea6de77a0b8"),
    );
    hash_test(
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        hex!("06fdcc7a409548aaf91368c06a6275b553e3f099bf0ea4edfd6778df89a890dd"),
    );
}

#[test]
fn ripemd256_1million_a() {
    one_million_a::<ripemd256::Ripemd256>(&hex!(
        "ac953744e10e31514c150d4d8d7b677342e33399788296e43ae4850ce4f97978"
    ));
}
