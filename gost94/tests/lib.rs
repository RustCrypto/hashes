#![no_std]
#[macro_use]
extern crate crypto_tests;
extern crate gost94;

use crypto_tests::hash::{Test, main_test, one_million_a};

#[test]
fn gost94_test_main() {
    let tests = new_tests!("test/1", "test/2", "test/3", "test/4", "test/5",
                           "test/6", "test/7", "test/8", "test/9");
    main_test::<gost94::Gost94Test>(&tests);
}

#[test]
fn gost94_cryptopro_main() {
    let tests = new_tests!("cryptopro/1", "cryptopro/2", "cryptopro/3",
                           "cryptopro/4", "cryptopro/5", "cryptopro/6",
                           "cryptopro/7", "cryptopro/8", "cryptopro/9");
    main_test::<gost94::Gost94CryptoPro>(&tests);
}

#[test]
fn gost94_test_1million_a() {
    let output = include_bytes!("data/test/one_million_a.output.bin");
    one_million_a::<gost94::Gost94Test>(output);
}

#[test]
fn gost94_cryptopro_1million_a() {
    let output = include_bytes!("data/cryptopro/one_million_a.output.bin");
    one_million_a::<gost94::Gost94CryptoPro>(output);
}
