#![no_std]
#[macro_use]
extern crate digest;
extern crate md4;

use digest::dev::{one_million_a, digest_test};

new_test!(md4_main, "md4", md4::Md4, digest_test);

#[test]
fn md4_1million_a() {
    let output = include_bytes!("data/one_million_a.bin");
    one_million_a::<md4::Md4>(output);
}
