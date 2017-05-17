#![no_std]
extern crate blake2;
extern crate crypto_mac;

use blake2::{Blake2b, Blake2s};
use crypto_mac::Mac;

#[test]
fn blake2b_mac() {
    let key = include_bytes!("data/blake2b/mac.key.bin");
    let input = include_bytes!("data/blake2b/mac.input.bin");
    let output = include_bytes!("data/blake2b/mac.output.bin");
    let mut d = Blake2b::new(key);
    d.input(input);
    assert!(d.verify(output));
}

#[test]
fn blake2s_mac() {
    let key = include_bytes!("data/blake2s/mac.key.bin");
    let input = include_bytes!("data/blake2s/mac.input.bin");
    let output = include_bytes!("data/blake2s/mac.output.bin");
    let mut d = Blake2s::new(key);
    d.input(input);
    assert!(d.verify(output));
}
