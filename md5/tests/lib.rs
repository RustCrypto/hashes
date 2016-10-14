#![no_std]
#[macro_use]
extern crate crypto_tests;
extern crate md5;

use crypto_tests::hash::{Test, main_test, one_million_a};

#[test]
fn md5_main() {
    // Examples from wikipedia
    let tests = new_tests!("test1", "test2", "test3");
    main_test::<md5::Md5>(&tests);
}

#[test]
fn md5_1million_a() {
    let output = include_bytes!("data/one_million_a.output.bin");
    one_million_a::<md5::Md5>(output);
}
