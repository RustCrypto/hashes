#![feature(test)]
extern crate test;

use digest::bench_update;
use md2::Md2;
use test::Bencher;

bench_update!(
    Md2::default();
    md2_10 10;
    md2_100 100;
    md2_1000 1000;
    md2_10000 10000;
);
