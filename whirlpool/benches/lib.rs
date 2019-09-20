#![no_std]
#![feature(test)]
extern crate test;
extern crate whirlpool_asm;

use test::Bencher;

#[bench]
fn bench_compress(b: &mut Bencher) {
    let mut state = [0u8; 64];
    let data = [0u8; 64];

    b.iter(|| {
        whirlpool_asm::compress(&mut state, &data);
    });

    b.bytes = data.len() as u64;
}
