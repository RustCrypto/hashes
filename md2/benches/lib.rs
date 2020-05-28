#![no_std]
#![feature(test)]
#[macro_use]
extern crate digest;
use md2;

bench!(md2::Md2);
