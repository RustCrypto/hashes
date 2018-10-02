#![no_std]
#![feature(test)]
#[macro_use]
extern crate digest;
extern crate blake2;

bench!(blake2::Blake2b);