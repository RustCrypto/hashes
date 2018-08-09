#![no_std]
#[macro_use]
extern crate crypto_mac;
extern crate blake2;

new_test!(blake2b_mac, "blake2b/mac", blake2::Blake2b);
new_test!(blake2s_mac, "blake2s/mac", blake2::Blake2s);
