#![no_std]
#![feature(test)]
#[macro_use]
extern crate digest;
extern crate ripemd160;

bench!(ripemd160::Ripemd160);
