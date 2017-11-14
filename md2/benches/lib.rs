#![no_std]
#![feature(test)]
#[macro_use]
extern crate digest;
extern crate md2;

bench_digest!(md2::Md2);
