use skein::digest::{dev::fixed_test, hash_serialization_test, new_test};

new_test!(skein256_256_kat, skein::Skein256_256, fixed_test);
new_test!(skein256_512_kat, skein::Skein256_512, fixed_test);
new_test!(skein512_256_kat, skein::Skein512_256, fixed_test);
new_test!(skein512_512_kat, skein::Skein512_512, fixed_test);
new_test!(skein1024_256_kat, skein::Skein1024_256, fixed_test);
new_test!(skein1024_512_kat, skein::Skein1024_512, fixed_test);
new_test!(skein1024_1024_kat, skein::Skein1024_1024, fixed_test);

hash_serialization_test!(skein256_serialization, skein::Skein256_256);
hash_serialization_test!(skein512_serialization, skein::Skein512_512);
hash_serialization_test!(skein1024_serialization, skein::Skein1024_1024);

/// Regression tests for https://github.com/RustCrypto/hashes/issues/681
#[test]
fn skein_uncommon_sizes() {
    use digest::{Digest, consts::U7};
    use hex_literal::hex;

    let s = "hello world";
    let h = skein::Skein256::<U7>::digest(s);
    assert_eq!(h[..], hex!("31bffb70f5dafe")[..]);
    let h = skein::Skein512::<U7>::digest(s);
    assert_eq!(h[..], hex!("ee6004efedd69c")[..]);
    let h = skein::Skein1024::<U7>::digest(s);
    assert_eq!(h[..], hex!("a2808b638681c6")[..]);
}
