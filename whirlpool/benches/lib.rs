#![no_std]
#![feature(test)]
extern crate test;
extern crate whirlpool;

use test::Bencher;
use whirlpool::{Whirlpool, Digest};

#[bench]
pub fn whirlpool_10(bh: &mut Bencher) {
    let mut sh = Whirlpool::new();
    let bytes = [1u8; 10];
    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn whirlpool_1k(bh: &mut Bencher) {
    let mut sh = Whirlpool::new();
    let bytes = [1u8; 1024];
    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn whirlpool_64k(bh: &mut Bencher) {
    let mut sh = Whirlpool::new();
    let bytes = [1u8; 65536];
    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}
