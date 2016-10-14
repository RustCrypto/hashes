#![no_std]
#![feature(test)]
extern crate test;
extern crate sha3;

use sha3::{Digest, Sha3_256, Sha3_512};
use test::Bencher;

#[bench]
pub fn sha3_256_10(bh: &mut Bencher) {
    let mut hasher = Sha3_256::new();
    let bytes = [1u8; 10];
    bh.iter(|| {
        hasher.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn sha3_256_1k(bh: &mut Bencher) {
    let mut hasher = Sha3_256::new();
    let bytes = [1u8; 1024];
    bh.iter(|| {
        hasher.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn sha3_256_64k(bh: &mut Bencher) {
    let mut hasher = Sha3_256::new();
    let bytes = [1u8; 65536];
    bh.iter(|| {
        hasher.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn sha3_512_10(bh: &mut Bencher) {
    let mut hasher = Sha3_512::new();
    let bytes = [1u8; 10];
    bh.iter(|| {
        hasher.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn sha3_512_1k(bh: &mut Bencher) {
    let mut hasher = Sha3_512::new();
    let bytes = [1u8; 1024];
    bh.iter(|| {
        hasher.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn sha3_512_64k(bh: &mut Bencher) {
    let mut hasher = Sha3_512::new();
    let bytes = [1u8; 65536];
    bh.iter(|| {
        hasher.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}
