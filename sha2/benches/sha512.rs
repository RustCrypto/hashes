#![no_std]
#![feature(test)]

use digest::bench;
bench!(sha2::Sha512);
