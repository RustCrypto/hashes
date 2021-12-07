#![feature(test)]
extern crate test;

use digest::bench_update;
use gost94::Gost94Test;
use test::Bencher;

bench_update!(
    Gost94Test::default();
    md2_10 10;
    md2_100 100;
    md2_1000 1000;
    md2_10000 10000;
);
