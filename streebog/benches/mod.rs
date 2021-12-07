#![feature(test)]
extern crate test;

use digest::bench_update;
use streebog::{Streebog256, Streebog512};
use test::Bencher;

bench_update!(
    Streebog256::default();
    streebog256_10 10;
    streebog256_100 100;
    streebog256_1000 1000;
    streebog256_10000 10000;
);

bench_update!(
    Streebog512::default();
    streebog512_10 10;
    streebog512_100 100;
    streebog512_1000 1000;
    streebog512_10000 10000;
);
