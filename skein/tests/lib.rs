#![no_std]
#[macro_use]
extern crate digest;
extern crate skein;

use digest::dev::{main_test, Test};
use digest::generic_array::typenum::{U32, U64};

#[test]
fn skein_256_32_0() {
    let tests = new_tests!("skein_256/test32_0");
    main_test::<skein::Skein256<U32>>(&tests);
}

#[test]
fn skein_256_32_17() {
    let tests = new_tests!("skein_256/test32_17");
    main_test::<skein::Skein256<U32>>(&tests);
}

#[test]
fn skein_256_32_64() {
    let tests = new_tests!("skein_256/test32_64");
    main_test::<skein::Skein256<U32>>(&tests);
}

#[test]
fn skein_256_64_0() {
    let tests = new_tests!("skein_256/test64_0");
    main_test::<skein::Skein256<U64>>(&tests);
}

#[test]
fn skein_256_64_17() {
    let tests = new_tests!("skein_256/test64_17");
    main_test::<skein::Skein256<U64>>(&tests);
}

#[test]
fn skein_256_64_64() {
    let tests = new_tests!("skein_256/test64_64");
    main_test::<skein::Skein256<U64>>(&tests);
}

#[test]
fn skein_512_32() {
    let tests = new_tests!(
        "skein_512/test32_0",
        "skein_512/test32_17",
        "skein_512/test32_64",
    );
    main_test::<skein::Skein512<U32>>(&tests);
}

#[test]
fn skein_512_64() {
    let tests = new_tests!(
        "skein_512/test64_0",
        "skein_512/test64_17",
        "skein_512/test64_64",
    );
    main_test::<skein::Skein512<U64>>(&tests);
}

#[test]
fn skein_1024_32() {
    let tests = new_tests!(
        "skein_1024/test32_0",
        "skein_1024/test32_17",
        "skein_1024/test32_64",
    );
    main_test::<skein::Skein1024<U32>>(&tests);
}

#[test]
fn skein_1024_64() {
    let tests = new_tests!(
        "skein_1024/test64_0",
        "skein_1024/test64_17",
        "skein_1024/test64_64",
    );
    main_test::<skein::Skein1024<U64>>(&tests);
}
