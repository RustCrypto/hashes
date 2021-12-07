#![feature(test)]
extern crate test;

use digest::bench_update;
use test::Bencher;

bench_update!(
    k12::KangarooTwelve::default();
    k12_10 10;
    k12_100 100;
    // the bigger sizes result in OOM
    // k12_1000 1000;
    // k12_10000 10000;
);
