#![no_std]
#![feature(test)]
#[macro_use]
extern crate crypto_tests;
extern crate sha3;

bench_digest!(sha3::Sha3_256);
