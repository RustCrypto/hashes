#![no_std]
#[macro_use]
extern crate digest;
extern crate sha1;

use digest::dev::{Test, main_test, one_million_a};

#[test]
fn sha1_main() {
    // Examples from wikipedia
    let tests = new_tests!("test1", "test2", "test3");
    main_test::<sha1::Sha1>(&tests);
}

#[test]
fn sha1_1million_a() {
    let output = include_bytes!("data/one_million_a.output.bin");
    one_million_a::<sha1::Sha1>(output);
}
