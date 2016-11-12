#![no_std]
#![feature(test)]
extern crate test;
extern crate streebog;
extern crate digest;

use test::Bencher;
use digest::Digest;
use streebog::{Streebog256, Streebog512};


#[bench]
pub fn streebog256_10(bh: &mut Bencher) {
    let mut sh = Streebog256::new();
    let bytes = [1u8; 10];
    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn streebog256_1k(bh: &mut Bencher) {
    let mut sh = Streebog256::new();
    let bytes = [1u8; 1024];
    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn streebog256_64k(bh: &mut Bencher) {
    let mut sh = Streebog256::new();
    let bytes = [1u8; 65536];
    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn streebog512_10(bh: &mut Bencher) {
    let mut sh = Streebog512::new();
    let bytes = [1u8; 10];
    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn streebog512_1k(bh: &mut Bencher) {
    let mut sh = Streebog512::new();
    let bytes = [1u8; 1024];
    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn streebog512_64k(bh: &mut Bencher) {
    let mut sh = Streebog512::new();
    let bytes = [1u8; 65536];
    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}
