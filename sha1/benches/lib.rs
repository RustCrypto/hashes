#![no_std]
#![feature(test)]
extern crate test;
extern crate sha1;

use test::Bencher;
use sha1::{Sha1, Digest};

#[bench]
pub fn sha1_10(bh: &mut Bencher) {
    let mut sh = Sha1::new();
    let bytes = [1u8; 10];
    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn sha1_1k(bh: &mut Bencher) {
    let mut sh = Sha1::new();
    let bytes = [1u8; 1024];
    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn sha1_64k(bh: &mut Bencher) {
    let mut sh = Sha1::new();
    let bytes = [1u8; 65536];
    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}
