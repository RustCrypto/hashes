#![no_std]
#[macro_use]
extern crate crypto_tests;
extern crate blake2;
extern crate digest;

use blake2::{Blake2b512, Blake2s256};
use crypto_tests::hash::{Test, main_test};
use digest::Digest;

#[test]
fn blake2b() {
    let tests = new_tests!("blake2b/1", "blake2b/2");
    // Tests without key
    main_test::<Blake2b512>(&tests);
    // Test with key
    let input = include_bytes!("data/blake2b/3.input.bin");
    let output = include_bytes!("data/blake2b/3.output.bin");
    let key = include_bytes!("data/blake2b/3.key.bin");

    let mut sh = Blake2b512::new_keyed(key);
    sh.input(input);
    assert_eq!(&sh.result()[..], &output[..]);
}

#[test]
fn blake2s() {
    let input = include_bytes!("data/blake2s/1.input.bin");
    let output = include_bytes!("data/blake2s/1.output.bin");
    let key = include_bytes!("data/blake2s/1.key.bin");

    let mut sh = Blake2s256::new_keyed(key);
    sh.input(input);
    assert_eq!(&sh.result()[..], output);
}
