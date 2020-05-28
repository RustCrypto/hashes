#![no_std]
#![feature(test)]

use digest::bench;
bench!(groestl::Groestl512);
