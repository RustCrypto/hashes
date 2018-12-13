//! Test messages from FIPS 180-1 and from the RIPEMD-160 webpage[1]
//! [1] https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
#![no_std]

#[macro_use]
extern crate digest;
extern crate ripemd320;

use digest::dev::{digest_test, one_million_a};

new_test!(
    ripemd320_main,
    "ripemd320",
    ripemd320::Ripemd320,
    digest_test
);

#[test]
fn ripemd320_1million_a() {
    let output = include_bytes!("data/one_million_a.bin");
    one_million_a::<ripemd320::Ripemd320>(&output[..]);
}
