//! Test vectors from FIPS 180-1 and from the [RIPEMD webpage][1].
//!
//! [1] https://homes.esat.kuleuven.be/~bosselae/ripemd160.html

use digest::dev::{digest_test, one_million_a};
use digest::new_test;
use hex_literal::hex;
use ripemd::{Ripemd160, Ripemd320};

new_test!(ripemd160_main, "ripemd160", Ripemd160, digest_test);

new_test!(ripemd320_main, "ripemd320", Ripemd320, digest_test);

#[test]
fn ripemd160_1million_a() {
    let expected = hex!("52783243c1697bdbe16d37f97f68f08325dc1528");
    one_million_a::<Ripemd160>(&expected);
}

#[test]
fn ripemd320_1million_a() {
    let expected = hex!(
        "
        bdee37f4371e20646b8b0d862dda16292ae36f40965e8c8509e63d1dbddecc503e2b63eb9245bb66
    "
    );
    one_million_a::<Ripemd320>(&expected);
}
