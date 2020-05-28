#![no_std]
#![feature(test)]

use digest::bench;
bench!(sha3::Sha3_256);
