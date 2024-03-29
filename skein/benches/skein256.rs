#![feature(test)]
extern crate test;

use digest::{array::typenum::U32, bench_update};
use skein::Skein256;
use test::Bencher;

bench_update!(
    Skein256::<U32>::default();
    skein_256_10 10;
    skein_256_100 100;
    skein_256_1000 1000;
    skein_256_10000 10000;
);
