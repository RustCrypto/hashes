#![no_std]
#![feature(test)]
#[macro_use]
extern crate digest;
extern crate gost94;

bench_digest!(gost94::Gost94Test);