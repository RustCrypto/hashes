#![no_std]

use digest::dev::{digest_test, one_million_a};
use digest::new_test;

new_test!(md4_main, "md4", md4::Md4, digest_test);

#[test]
fn md4_1million_a() {
    let output = include_bytes!("data/one_million_a.bin");
    one_million_a::<md4::Md4>(output);
}
