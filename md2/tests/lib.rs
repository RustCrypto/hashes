#![no_std]
#[macro_use]
extern crate digest;
extern crate md2;

use digest::dev::{one_million_a, digest_test};

new_test!(md2_main, "md2", md2::Md2, digest_test);

#[test]
fn md2_1million_a() {
    let output = include_bytes!("data/one_million_a.bin");
    one_million_a::<md2::Md2>(output);
}
