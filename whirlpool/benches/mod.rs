#![feature(test)]
extern crate test;

use digest::bench_update;
use test::Bencher;
use whirlpool::Whirlpool;

bench_update!(
    Whirlpool::default();
    whirlpool_10 10;
    whirlpool_100 100;
    whirlpool_1000 1000;
    whirlpool_10000 10000;
);
