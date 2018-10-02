#![no_std]
#![feature(test)]
#[macro_use]
extern crate digest;
extern crate md4;

bench!(md4::Md4);
