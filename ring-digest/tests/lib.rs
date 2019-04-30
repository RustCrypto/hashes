#![no_std]
#[macro_use]
extern crate digest;
extern crate ring_digest;

use digest::dev::{one_million_a, digest_test};
use ring_digest::*;

new_test!(sha1_main, "sha1", Sha1, digest_test);
new_test!(sha256_main, "sha256", Sha256, digest_test);
new_test!(sha384_main, "sha384", Sha384, digest_test);
new_test!(sha512_main, "sha512", Sha512, digest_test);
new_test!(sha512_256_main, "sha512_256", Sha512Trunc256, digest_test);

#[test]
fn sha1_1million_a() {
    let output = include_bytes!("data/one_million_a.bin");
    one_million_a::<Sha1>(output);
}

#[test]
fn sha256_1million_a() {
    let output = include_bytes!("data/sha256_one_million_a.bin");
    one_million_a::<Sha256>(output);
}

#[test]
fn sha512_1million_a() {
    let output = include_bytes!("data/sha512_one_million_a.bin");
    one_million_a::<Sha512>(output);
}
