#![no_std]
#![feature(test)]
#[macro_use]
extern crate digest;
use md4;

bench!(md4::Md4);
