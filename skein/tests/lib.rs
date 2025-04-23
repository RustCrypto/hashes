use hex_literal::hex;
use skein::{
    consts::{U128, U32, U64, U7},
    digest::{dev::fixed_test, new_test},
    Digest, Skein1024, Skein256, Skein512,
};

new_test!(skein256_32, "skein256_32", Skein256<U32>, fixed_test);
new_test!(skein256_64, "skein256_64", Skein256<U64>, fixed_test);
new_test!(skein512_32, "skein512_32", Skein512<U32>, fixed_test);
new_test!(skein512_64, "skein512_64", Skein512<U64>, fixed_test);
new_test!(skein1024_32, "skein1024_32", Skein1024<U32>, fixed_test);
new_test!(skein1024_64, "skein1024_64", Skein1024<U64>, fixed_test);
new_test!(skein1024_128, "skein1024_128", Skein1024<U128>, fixed_test);

/// Regression tests for https://github.com/RustCrypto/hashes/issues/681
#[test]
fn skein_uncommon_sizes() {
    let s = "hello world";
    let h = Skein256::<U7>::digest(s);
    assert_eq!(h[..], hex!("31bffb70f5dafe")[..]);
    let h = Skein512::<U7>::digest(s);
    assert_eq!(h[..], hex!("ee6004efedd69c")[..]);
    let h = Skein1024::<U7>::digest(s);
    assert_eq!(h[..], hex!("a2808b638681c6")[..]);
}
