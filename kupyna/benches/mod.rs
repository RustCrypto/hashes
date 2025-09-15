#![feature(test)]
extern crate test;

use digest::bench_update;
use kupyna::{Kupyna256, Kupyna512};
use test::Bencher;

bench_update!(
    Kupyna256::default();
    kupyna256_10 10;
    kupyna256_100 100;
    kupyna256_1000 1000;
    kupyna256_10000 10000;
);

bench_update!(
    Kupyna512::default();
    kupyna512_10 10;
    kupyna512_100 100;
    kupyna512_1000 1000;
    kupyna512_10000 10000;
);
