#![no_std]
#[macro_use]
extern crate digest;
extern crate md4;

use digest::dev::{Test, main_test, one_million_a};

#[test]
fn md4_main() {
    // Examples from wikipedia
    let tests = new_tests!("test1", "test2", "test3");
    main_test::<md4::Md4>(&tests);
}

#[test]
fn md4_1million_a() {
    let output = include_bytes!("data/one_million_a.output.bin");
    one_million_a::<md4::Md4>(output);
}
