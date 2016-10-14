#![no_std]
#![feature(test)]
extern crate test;
extern crate md4;
extern crate digest;

use test::Bencher;
use digest::Digest;
use md4::Md4;


#[bench]
pub fn md4_10(bh: &mut Bencher) {
    let mut sh = Md4::new();
    let bytes = [1u8; 10];
    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn md4_1k(bh: &mut Bencher) {
    let mut sh = Md4::new();
    let bytes = [1u8; 1024];
    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn md4_64k(bh: &mut Bencher) {
    let mut sh = Md4::new();
    let bytes = [1u8; 65536];
    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}
