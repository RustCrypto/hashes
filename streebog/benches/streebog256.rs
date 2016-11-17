#![no_std]
#![feature(test)]
#[macro_use]
extern crate crypto_tests;
extern crate streebog;

bench_digest!(streebog::Streebog256);
