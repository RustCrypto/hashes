use digest::dev::{feed_rand_16mib, fixed_reset_test};
use hex_literal::hex;
use md4::{Digest, Md4};

digest::new_test!(md4_main, "md4", Md4, fixed_reset_test);

#[test]
fn md4_rand() {
    let mut h = Md4::new();
    feed_rand_16mib(&mut h);
    assert_eq!(h.finalize(), hex!("07345abfb6192d85bf6a211381926120"));
}

#[rustfmt::skip]
digest::hash_serialization_test!(
    md4_serialization,
    Md4,
    hex!("
        b87358479b721dbccae8eefb4831451d
        01000000000000000113000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        000000000000000000
    ")
);
