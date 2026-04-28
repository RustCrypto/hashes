#![feature(test)]
extern crate test;

use test::Bencher;

digest::bench_update!(
    k12::Kt128::default();
    kt128_1_10 10;
    kt128_2_100 100;
    kt128_3_1k 1000;
    kt128_4_10k 10_000;
    kt128_5_100k 100_000;
    kt128_6_1m 1_000_000;
);
