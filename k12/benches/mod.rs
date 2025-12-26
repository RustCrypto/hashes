#![feature(test)]
extern crate test;

use digest::bench_update;
use test::Bencher;

bench_update!(
    k12::Kt128::default();
    kt128_10 10;
    kt128_100 100;
    // the bigger sizes result in OOM
    // kt128_1000 1000;
    // kt128_10000 10000;
);

bench_update!(
    k12::Kt256::default();
    kt256_10 10;
    kt256_100 100;
    // the bigger sizes result in OOM
    // kt256_1000 1000;
    // kt256_10000 10000;
);
