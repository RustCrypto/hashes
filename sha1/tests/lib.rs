#![no_std]

use digest::dev::{digest_test, one_million_a};
use digest::new_test;

new_test!(sha1_main, "sha1", sha1::Sha1, digest_test);

#[test]
fn sha1_1million_a() {
    let output = include_bytes!("data/one_million_a.bin");
    one_million_a::<sha1::Sha1>(output);
}

#[test]
fn foo() {
    use digest::Digest;
    let msg = [0x10; 64];
    let res = sha1::Sha1::digest(&msg);
    assert_eq!(res.as_slice(), &[
        168, 179, 203, 62, 143, 158, 186, 31, 28, 98, 170, 152, 153, 17, 169, 72, 151, 49, 99, 53
    ]);
}