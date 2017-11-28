#![no_std]
extern crate jh_x86_64;
#[macro_use]
extern crate digest;

use digest::dev::{main_test, Test};

#[test]
fn jh_224_0() {
    let tests = new_tests!("jh_224/test_0");
    main_test::<jh_x86_64::Jh224>(&tests);
}

#[test]
fn jh_224_17() {
    let tests = new_tests!("jh_224/test_17");
    main_test::<jh_x86_64::Jh224>(&tests);
}

#[test]
fn jh_224_64() {
    let tests = new_tests!("jh_224/test_64");
    main_test::<jh_x86_64::Jh224>(&tests);
}

#[test]
fn jh_224_123() {
    let tests = new_tests!("jh_224/test_123");
    main_test::<jh_x86_64::Jh224>(&tests);
}

#[test]
fn jh_256() {
    let tests = new_tests!("jh_256/test_0", "jh_256/test_17",
                           "jh_256/test_64", "jh_256/test_123");
    main_test::<jh_x86_64::Jh256>(&tests);
}

#[test]
fn jh_384() {
    let tests = new_tests!("jh_384/test_0", "jh_384/test_17",
                           "jh_384/test_64", "jh_384/test_123");
    main_test::<jh_x86_64::Jh384>(&tests);
}

#[test]
fn jh_512() {
    let tests = new_tests!("jh_512/test_0", "jh_512/test_17",
                           "jh_512/test_64", "jh_512/test_123");
    main_test::<jh_x86_64::Jh512>(&tests);
}
