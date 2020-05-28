#![no_std]
#![feature(test)]

use digest::bench;
bench!(whirlpool::Whirlpool);
