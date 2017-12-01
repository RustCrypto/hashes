#![no_std]
extern crate blake;
#[macro_use]
extern crate digest;

use digest::dev::{main_test, Test};

#[test]
fn blake_224() {
    let tests = new_tests!("blake_224/test1", "blake_224/test2");
    main_test::<blake::Blake224>(&tests);
}

#[test]
fn blake_256() {
    let tests = new_tests!("blake_256/test1", "blake_256/test2");
    main_test::<blake::Blake256>(&tests);
}

#[test]
fn blake_384() {
    let tests = new_tests!("blake_384/test1", "blake_384/test2");
    main_test::<blake::Blake384>(&tests);
}

#[test]
fn blake_512() {
    let tests = new_tests!("blake_512/test1", "blake_512/test2");
    main_test::<blake::Blake512>(&tests);
}
