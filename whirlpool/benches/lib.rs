#![no_std]
#![feature(test)]
#[macro_use]
extern crate digest;
extern crate whirlpool;

bench!(whirlpool::Whirlpool);
