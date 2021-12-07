#![feature(test)]
extern crate test;

use digest::bench_update;
use shabal::Shabal256;
use test::Bencher;

bench_update!(
    Shabal256::default();
    shabal256_10 10;
    shabal256_100 100;
    shabal256_1000 1000;
    shabal256_10000 10000;
);
