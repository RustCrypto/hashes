#![no_std]
#![feature(test)]
extern crate test;
extern crate md5;
extern crate digest;

use test::Bencher;
use digest::Digest;
use md5::Md5;


#[bench]
pub fn md5_10(bh: &mut Bencher) {
    let mut sh = Md5::new();
    let bytes = [1u8; 10];
    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn md5_1k(bh: &mut Bencher) {
    let mut sh = Md5::new();
    let bytes = [1u8; 1024];
    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}

#[bench]
pub fn md5_64k(bh: &mut Bencher) {
    let mut sh = Md5::new();
    let bytes = [1u8; 65536];
    bh.iter(|| {
        sh.input(&bytes);
    });
    bh.bytes = bytes.len() as u64;
}
