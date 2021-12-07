use digest::dev::{feed_rand_16mib, fixed_reset_test};
use digest::new_test;
use hex_literal::hex;
use sm3::{Digest, Sm3};

new_test!(sm3_main, "sm3", Sm3, fixed_reset_test);

#[test]
fn sm3_rand() {
    let mut h = Sm3::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize()[..],
        hex!("ad154967b08d636a148dd4c688a6df7add1ed1946af18eb358a9b320de2aca86")[..]
    );
}
