use digest::dev::{feed_rand_16mib, fixed_reset_test};
use hex_literal::hex;
use whirlpool::{Digest, Whirlpool};

digest::new_test!(whirlpool_main, "whirlpool", Whirlpool, fixed_reset_test);

#[test]
#[rustfmt::skip]
fn whirlpool_rand() {
    let mut h = Whirlpool::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize()[..],
        hex!("
            8db0acd78686f8160203b53bfb0c0c1ee2332b856732a311f7de8e4ea4c100cc
            dd5267e8b63207e644c96d2ef5cfbb53f2519af1904c48fd2ecf937541998b11
        ")[..]
    );
}
