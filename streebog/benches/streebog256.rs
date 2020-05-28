#![no_std]
#![feature(test)]
#[macro_use]
extern crate digest;
use streebog;

bench!(streebog::Streebog256);
