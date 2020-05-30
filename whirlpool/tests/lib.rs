#![no_std]

use digest::dev::{digest_test, one_million_a};
use digest::new_test;

new_test!(
    whirlpool_main,
    "whirlpool",
    whirlpool::Whirlpool,
    digest_test
);

#[test]
fn whirlpool_1million_a() {
    let output = include_bytes!("data/one_million_a.bin");
    one_million_a::<whirlpool::Whirlpool>(output);
}
