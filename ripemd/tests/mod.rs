use digest::dev::{feed_rand_16mib, fixed_reset_test};
use digest::new_test;
use hex_literal::hex;
use ripemd::{Digest, Ripemd160, Ripemd256, Ripemd320};

// Test vectors from FIPS 180-1 and from the [RIPEMD webpage][1].
//
// [1] https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
new_test!(ripemd160_main, "ripemd160", Ripemd160, fixed_reset_test);
new_test!(ripemd256_main, "ripemd256", Ripemd256, fixed_reset_test);
new_test!(ripemd320_main, "ripemd320", Ripemd320, fixed_reset_test);

#[test]
fn ripemd160_rand() {
    let mut h = Ripemd160::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize()[..],
        hex!("bcd8c672932125776af3c60eeeb58bbaf206f386")[..]
    );
}

#[test]
fn ripemd256_rand() {
    let mut h = Ripemd256::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize()[..],
        hex!("6492ffe075896441b737900bdf58fc960e77477e42a2a61bc02c66fd689b69d0")[..]
    );
}

#[test]
#[rustfmt::skip]
fn ripemd320_rand() {
    let mut h = Ripemd320::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize()[..],
        hex!("
            3a905312162c5c173639f6cc1cdf51d14e8bda02
            865767592e26d9343fbec348ce55ce39b4b4b56f
        ")[..]
    );
}
