#![no_std]
#[macro_use]
extern crate crypto_tests;
extern crate crc_32 as crc32;

use crypto_tests::hash::{Test, main_test, one_million_a};

#[test]
fn crc32_main() {
    let tests = new_tests!("1", "2", "3", "4", "5", "6");
    main_test::<crc32::CRC32>(&tests);
}

#[test]
fn crc32_1million_a() {
    let output = include_bytes!("data/one_million_a.output.bin");
    one_million_a::<crc32::CRC32>(output);
}
