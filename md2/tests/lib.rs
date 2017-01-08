#![no_std]
#[macro_use]
extern crate crypto_tests;
extern crate md2;

use crypto_tests::hash::{Test, main_test};//, one_million_a};

#[test]
fn md2_main() {
    // Examples from wikipedia
    let tests = new_tests!("test1", "test2", "test3");
    main_test::<md2::Md2>(&tests);
}

// #[test]
// fn md2_1million_a() {
//     let output = include_bytes!("data/one_million_a.output.bin");
//     one_million_a::<md2::Md2>(output);
// }
