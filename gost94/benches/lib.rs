#![no_std]
#![feature(test)]
#[macro_use]
extern crate crypto_tests;
extern crate gost94;

bench_digest!(gost94::Gost94Test);