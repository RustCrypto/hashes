#![no_std]
#![feature(test)]
#[macro_use]
extern crate crypto_tests;
extern crate md_5 as md5;

bench_digest!(md5::Md5);
