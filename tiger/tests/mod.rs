use digest::dev::{feed_rand_16mib, fixed_reset_test};
use digest::{hash_serialization_test, new_test};
use hex_literal::hex;
use tiger::{Digest, Tiger, Tiger2};

new_test!(tiger, "tiger", tiger::Tiger, fixed_reset_test);
new_test!(tiger2, "tiger2", tiger::Tiger2, fixed_reset_test);

#[rustfmt::skip]
hash_serialization_test!(
    tiger_serialization,
    Tiger,
    hex!("
        eb0b98618cfb93dd8d0e27b22312c64c
        54528976ae32041f0100000000000000
        01130000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00
    ")
);
#[rustfmt::skip]
hash_serialization_test!(
    tiger2_serialization,
    Tiger2,
    hex!("
        eb0b98618cfb93dd8d0e27b22312c64c
        54528976ae32041f0100000000000000
        01130000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00
    ")
);

#[test]
fn tiger_rand() {
    let mut h = Tiger::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize(),
        hex!("d12f382ecf3250c14aca7726df15b999dfe99f905cf163d2"),
    );
}

#[test]
fn tiger2_rand() {
    let mut h = Tiger2::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize(),
        hex!("1bb7a80144c97f831fdefb635477776dd6c164048ce5895d"),
    );
}
