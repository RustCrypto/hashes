#![no_std]

use digest::dev::{digest_test, one_million_a};
use digest::new_test;

new_test!(shabal192_main, "shabal192", shabal::Shabal192, digest_test);
new_test!(shabal224_main, "shabal224", shabal::Shabal224, digest_test);
new_test!(shabal256_main, "shabal256", shabal::Shabal256, digest_test);
new_test!(shabal384_main, "shabal384", shabal::Shabal384, digest_test);
new_test!(shabal512_main, "shabal512", shabal::Shabal512, digest_test);

#[test]
fn sha192_1million_a() {
    let output = include_bytes!("data/shabal192_one_million_a.bin");
    one_million_a::<shabal::Shabal192>(output);
}

#[test]
fn sha224_1million_a() {
    let output = include_bytes!("data/shabal224_one_million_a.bin");
    one_million_a::<shabal::Shabal224>(output);
}

#[test]
fn sha256_1million_a() {
    let output = include_bytes!("data/shabal256_one_million_a.bin");
    one_million_a::<shabal::Shabal256>(output);
}

#[test]
fn sha384_1million_a() {
    let output = include_bytes!("data/shabal384_one_million_a.bin");
    one_million_a::<shabal::Shabal384>(output);
}

#[test]
fn sha512_1million_a() {
    let output = include_bytes!("data/shabal512_one_million_a.bin");
    one_million_a::<shabal::Shabal512>(output);
}
