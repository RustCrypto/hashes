#![no_std]
#![feature(test)]
extern crate test;
extern crate blake2;
extern crate digest;

use test::Bencher;
use digest::Digest;
use blake2::{Blake2b512, Blake2s256};

#[bench]
pub fn blake2b_10(bh: &mut Bencher) {
    let mut sh = Blake2b512::new();
    let bytes = [1u8; 10];
    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn blake2b_1k(bh: &mut Bencher) {
    let mut sh = Blake2b512::new();
    let bytes = [1u8; 1024];
    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn blake2b_64k(bh: &mut Bencher) {
    let mut sh = Blake2b512::new();
    let bytes = [1u8; 65536];
    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn blake2s_10(bh: &mut Bencher) {
    let mut sh = Blake2s256::new();
    let bytes = [1u8; 10];
    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn blake2s_1k(bh: &mut Bencher) {
    let mut sh = Blake2s256::new();
    let bytes = [1u8; 1024];
    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn blake2s_64k(bh: &mut Bencher) {
    let mut sh = Blake2s256::new();
    let bytes = [1u8; 65536];
    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}
