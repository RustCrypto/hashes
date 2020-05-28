#![no_std]
#![feature(test)]

use digest::bench;
bench!(gost94::Gost94Test);
