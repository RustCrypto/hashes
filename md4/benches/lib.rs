#![no_std]
#![feature(test)]
#[macro_use]
extern crate crypto_tests;
extern crate md4;

bench_digest!(md4::Md4);
