#![no_std]
#![feature(test)]

use digest::bench;
bench!(blake2::Blake2s);
