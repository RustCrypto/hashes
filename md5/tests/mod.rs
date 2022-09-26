use digest::dev::{feed_rand_16mib, fixed_reset_test};
use hex_literal::hex;
use md5::{Digest, Md5};

digest::new_test!(md5_main, "md5", md5::Md5, fixed_reset_test);

#[test]
fn md5_rand() {
    let mut h = Md5::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize()[..],
        hex!("61aec26f1b909578ef638ae02dac0977")[..]
    );
}

#[rustfmt::skip]
digest::hash_serialization_test!(
    md5_serialization,
    Md5,
    hex!("
        9522cae5ddd693db0f99ab079e21d2ca
        01000000000000000113000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        000000000000000000
    ")
);
