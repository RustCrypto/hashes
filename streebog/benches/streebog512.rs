#![no_std]
#![feature(test)]

use digest::bench;
bench!(streebog::Streebog512);
