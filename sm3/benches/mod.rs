#![feature(test)]
extern crate test;

use digest::bench_update;
use sm3::Sm3;
use test::Bencher;

bench_update!(
    Sm3::default();
    sm3_10 10;
    sm3_100 100;
    sm3_1000 1000;
    sm3_10000 10000;
);
