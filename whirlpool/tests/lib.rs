#![no_std]
#[macro_use]
extern crate crypto_tests;
extern crate whirlpool;

use crypto_tests::hash::{Test, main_test, one_million_a};

#[test]
fn whirlpool_main() {
    let tests = new_tests!("test1", "test2", "test3", "test4", "test5", "test6",
                           "test7", "test8", "test9", "test10", "test11",
                           "test12", "test13", "test14", "test15", "test16",
                           "test17", "test18");
    main_test::<whirlpool::Whirlpool>(&tests);
}

#[test]
fn whirlpool_1million_a() {
    let output = include_bytes!("data/one_million_a.output.bin");
    one_million_a::<whirlpool::Whirlpool>(output);
}
