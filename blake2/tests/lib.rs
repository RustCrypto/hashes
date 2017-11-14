#![no_std]
#[macro_use]
extern crate digest;
extern crate blake2;

use blake2::{Blake2b, Blake2s};
use digest::dev::{Test, variable_test};
use digest::Digest;

#[test]
fn blake2b() {
    let tests = new_tests!("blake2b/1", "blake2b/1_var", "blake2b/2");
    // Tests without key
    variable_test::<Blake2b>(&tests);
    // Test with key
    let input = include_bytes!("data/blake2b/3.input.bin");
    let output = include_bytes!("data/blake2b/3.output.bin");
    let key = include_bytes!("data/blake2b/3.key.bin");

    let mut sh = Blake2b::new_keyed(key, 64);
    sh.input(input);
    assert_eq!(&sh.result()[..], &output[..]);
}

#[test]
fn blake2s() {
    let input = include_bytes!("data/blake2s/1.input.bin");
    let output = include_bytes!("data/blake2s/1.output.bin");
    let key = include_bytes!("data/blake2s/1.key.bin");

    let mut sh = Blake2s::new_keyed(key, 32);
    sh.input(input);
    assert_eq!(&sh.result()[..], output);

    let tests = new_tests!("blake2s/2");
    // Tests without key
    variable_test::<Blake2s>(&tests);
}
