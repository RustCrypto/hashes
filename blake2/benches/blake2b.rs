#![no_std]
#![feature(test)]
#[macro_use]
extern crate crypto_tests;
extern crate blake2;

bench_digest!(blake2::Blake2b512);