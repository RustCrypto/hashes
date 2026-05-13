#![feature(test)]
extern crate test;

use digest::bench_update;
use test::Bencher;

bench_update!(
    shake::Shake128::default();
    shake128_10 10;
    shake128_100 100;
    shake128_1000 1000;
    shake128_10000 10000;
);

bench_update!(
    shake::Shake256::default();
    shake256_10 10;
    shake256_100 100;
    shake256_1000 1000;
    shake256_10000 10000;
);
