#![feature(test)]
extern crate test;

use digest::bench_update;
use md4::Md4;
use test::Bencher;

bench_update!(
    Md4::default();
    md4_10 10;
    md4_100 100;
    md4_1000 1000;
    md4_10000 10000;
);
