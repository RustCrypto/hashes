#![feature(test)]
extern crate test;

use digest::{array::typenum::U64, bench_update};
use skein::Skein512;
use test::Bencher;

bench_update!(
    Skein512::<U64>::default();
    skein_512_10 10;
    skein_512_100 100;
    skein_512_1000 1000;
    skein_512_10000 10000;
);
