#![feature(test)]
extern crate test;

use digest::bench_update;
use jh::Jh256;
use test::Bencher;

bench_update!(
    Jh256::default();
    jh_256_10 10;
    jh_256_100 100;
    jh_256_1000 1000;
    jh_256_10000 10000;
);
