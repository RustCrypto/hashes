#![no_std]
#![feature(test)]
#[macro_use]
extern crate crypto_tests;
extern crate whirlpool_asm as whirlpool;

bench_digest!(whirlpool::Whirlpool);
