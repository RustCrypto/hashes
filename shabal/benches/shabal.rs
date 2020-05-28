#![no_std]
#![feature(test)]

use digest::bench;
bench!(shabal::Shabal256);
