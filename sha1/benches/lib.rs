#![no_std]
#![feature(test)]
extern crate test;
extern crate sha1_asm;

use test::Bencher;

#[bench]
fn bench_compress(b: &mut Bencher) {
    let mut state = Default::default();
    let data = [0u8; 64];

    b.iter(|| {
        sha1_asm::compress(&mut state, &data);
    });

    b.bytes = data.len() as u64;
}
