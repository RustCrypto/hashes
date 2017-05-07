#![no_std]
#![feature(test)]
#[macro_use]
extern crate crypto_tests;
extern crate sha2_asm as sha2;

bench_digest!(sha2::Sha256);
