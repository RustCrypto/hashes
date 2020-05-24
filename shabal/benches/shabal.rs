#![no_std]
#![feature(test)]
#[macro_use]
extern crate digest;
extern crate shabal;

bench!(shabal::Shabal256);
