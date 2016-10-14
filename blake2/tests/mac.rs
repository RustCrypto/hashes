/*
#![no_std]
#[macro_use]
extern crate blake2;
extern crate crypto_mac;

use blake2::{Blake2b512, Blake2s256};
use crypto_mac::Mac;

#[test]
fn blake2b_mac() {
    let key = include_bytes!("data/blake2b/mac.key.bin");
    let input = include_bytes!("data/blake2b/mac.input.bin");
    let output = include_bytes!("data/blake2b/mac.output.bin");
    let mut d = Blake2b512::new_keyed(key);
    d.input(input);
    assert_eq!(d.result().code(), &output[..]);
}

#[test]
fn blake2s_mac() {
    let key = include_bytes!("data/blake2s/mac.key.bin");
    let input = include_bytes!("data/blake2s/mac.input.bin");
    let output = include_bytes!("data/blake2s/mac.output.bin");
    let mut d = Blake2s256::new_keyed(key);
    d.input(input);
    assert_eq!(d.result().code(), &output[..]);
}
*/