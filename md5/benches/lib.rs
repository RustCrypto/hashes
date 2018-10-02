#![no_std]
#![feature(test)]
#[macro_use]
extern crate digest;
extern crate md5;

bench!(md5::Md5);
