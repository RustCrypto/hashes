use skein::digest::{dev::fixed_test, new_test};

new_test!(
    skein256_256,
    "skein256_256",
    skein::Skein256_256,
    fixed_test,
);
new_test!(
    skein256_512,
    "skein256_512",
    skein::Skein256_512,
    fixed_test,
);
new_test!(
    skein512_256,
    "skein512_256",
    skein::Skein512_256,
    fixed_test,
);
new_test!(
    skein512_512,
    "skein512_512",
    skein::Skein512_512,
    fixed_test,
);
new_test!(
    skein1024_256,
    "skein1024_256",
    skein::Skein1024_256,
    fixed_test,
);
new_test!(
    skein1024_512,
    "skein1024_512",
    skein::Skein1024_512,
    fixed_test,
);
new_test!(
    skein1024_1024,
    "skein1024_1024",
    skein::Skein1024_1024,
    fixed_test,
);

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
