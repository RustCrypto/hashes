#![no_std]
#![feature(test)]

use digest::bench;
bench!(sha1::Sha1);
