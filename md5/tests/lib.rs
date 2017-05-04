#![no_std]
#[macro_use]
extern crate crypto_tests;
extern crate md_5 as md5;

use crypto_tests::hash::{Test, main_test, one_million_a};

#[test]
fn md5_main() {
    let tests = new_tests!("1", "2", "3", "4", "5", "6");
    main_test::<md5::Md5>(&tests);
}

#[test]
fn md5_1million_a() {
    let output = include_bytes!("data/one_million_a.output.bin");
    one_million_a::<md5::Md5>(output);
}
