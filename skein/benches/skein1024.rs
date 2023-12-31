#![feature(test)]
extern crate test;

use digest::{array::typenum::U128, bench_update};
use skein::Skein1024;
use test::Bencher;

bench_update!(
    Skein1024::<U128>::default();
    skein_1024_10 10;
    skein_1024_100 100;
    skein_1024_1000 1000;
    skein_1024_10000 10000;
);
