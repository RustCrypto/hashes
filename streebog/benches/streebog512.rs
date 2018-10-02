#![no_std]
#![feature(test)]
#[macro_use]
extern crate digest;
extern crate streebog;

bench!(streebog::Streebog512);
