#![no_std]
#![feature(test)]

#[macro_use]
extern crate crypto_tests;
extern crate groestl;

bench_digest!(groestl::Groestl512);
