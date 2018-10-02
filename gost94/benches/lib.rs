#![no_std]
#![feature(test)]
#[macro_use]
extern crate digest;
extern crate gost94;

bench!(gost94::Gost94Test);