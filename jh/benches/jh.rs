#![no_std]
#![feature(test)]
#[macro_use]
extern crate digest;
extern crate jh_x86_64;

bench!(jh_x86_64::Jh256);
