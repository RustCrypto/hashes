#![no_std]
#[macro_use]
extern crate crypto_tests;
extern crate generic_array;
extern crate groestl;

use crypto_tests::hash::{Test, main_test};

#[test]
fn groestl_224_main() {
    let tests = new_tests!("groestl224/test1");
    main_test::<groestl::Groestl224>(&tests);
}

#[test]
fn groestl_256_main() {
    let tests = new_tests!(
        "groestl256/test1",
        "groestl256/test2",
        "groestl256/test3",
    );
    main_test::<groestl::Groestl256>(&tests);
}

#[test]
fn groestl_384_main() {
    let tests = new_tests!("groestl384/test1");
    main_test::<groestl::Groestl384>(&tests);
}

#[test]
fn groestl_512_main() {
    let tests = new_tests!("groestl512/test1");
    main_test::<groestl::Groestl512>(&tests);
}
