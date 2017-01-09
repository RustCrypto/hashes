#![no_std]
#[macro_use]
extern crate crypto_tests;
extern crate md2;

use crypto_tests::hash::{Test, main_test};

#[test]
fn md2_main() {
    // Examples from wikipedia
    let tests = new_tests!("test1", "test2", "test3");
    main_test::<md2::Md2>(&tests);
}
