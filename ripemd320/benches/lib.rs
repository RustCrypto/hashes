#![no_std]
#![feature(test)]
#[macro_use]
extern crate digest;
extern crate ripemd320;

bench!(ripemd320::Ripemd320);
