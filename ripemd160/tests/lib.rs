#![no_std]
#[macro_use]
extern crate crypto_tests;
extern crate ripemd160;

use crypto_tests::hash::{Test, main_test, one_million_a};

#[test]
fn ripemd160_main() {
    // Test messages from FIPS 180-1
    let tests = new_tests!("test1", "test2", "test3", "test4");
    main_test::<ripemd160::Ripemd160>(&tests);
}

#[test]
fn ripemd160_1million_a() {
    let output = include_bytes!("data/one_million_a.output.bin");
    one_million_a::<ripemd160::Ripemd160>(output);
}
