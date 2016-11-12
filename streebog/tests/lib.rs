#![no_std]
#[macro_use]
extern crate crypto_tests;
extern crate streebog;

use crypto_tests::hash::{Test, main_test};

#[test]
fn streebog256_main() {
    let tests = new_tests!("256/1");
    main_test::<streebog::Streebog256>(&tests);
}

#[test]
fn streebog512_main() {
    let tests = new_tests!("512/1");
    main_test::<streebog::Streebog512>(&tests);
}
