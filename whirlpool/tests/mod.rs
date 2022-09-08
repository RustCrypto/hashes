use digest::dev::{feed_rand_16mib, fixed_reset_test};
use hex_literal::hex;
use whirlpool::{Digest, Whirlpool};

digest::new_test!(whirlpool_main, "whirlpool", Whirlpool, fixed_reset_test);

#[rustfmt::skip]
digest::hash_serialization_test!(
    whirlpool_serialization,
    Whirlpool,
    hex!("
        44b95aeb60cdf5910f83d556a3382cd8
        58f03d791dfb7675125d6ede083dc917
        47be004f1982289c065eb53491e06729
        f5935532c376541ca78e23ed572516a9
        00000000000000000000000000000000
        00000000000000000002000000000000
        01130000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00000000000000000000000000000000
        00
    ")
);

#[test]
fn whirlpool_rand() {
    let mut h = Whirlpool::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize(),
        hex!(
            "8db0acd78686f8160203b53bfb0c0c1ee2332b856732a311f7de8e4ea4c100cc"
            "dd5267e8b63207e644c96d2ef5cfbb53f2519af1904c48fd2ecf937541998b11"
        ),
    );
}
