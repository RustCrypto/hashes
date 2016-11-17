#![no_std]
#![feature(test)]
#[macro_use]
extern crate crypto_tests;
extern crate ripemd160;

bench_digest!(ripemd160::Ripemd160);
