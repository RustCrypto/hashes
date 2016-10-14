#![no_std]
#![feature(test)]
extern crate test;
extern crate sha2;

use test::Bencher;
use sha2::{Digest, Sha256, Sha512};

#[bench]
pub fn sha256_10(bh: &mut Bencher) {
    let mut sh = Sha256::new();
    let bytes = [1u8; 10];
    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn sha256_1k(bh: &mut Bencher) {
    let mut sh = Sha256::new();
    let bytes = [1u8; 1024];
    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn sha256_64k(bh: &mut Bencher) {
    let mut sh = Sha256::new();
    let bytes = [1u8; 65536];
    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn sha512_10(bh: &mut Bencher) {
    let mut sh = Sha512::new();
    let bytes = [1u8; 10];
    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn sha512_1k(bh: &mut Bencher) {
    let mut sh = Sha512::new();
    let bytes = [1u8; 1024];
    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn sha512_64k(bh: &mut Bencher) {
    let mut sh = Sha512::new();
    let bytes = [1u8; 65536];
    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}
