#![feature(test)]
extern crate test;

use digest::bench_update;
use test::Bencher;

bench_update!(
    cshake::CShake128::default();
    cshake128_10 10;
    cshake128_100 100;
    cshake128_1000 1000;
    cshake128_10000 10000;
);

bench_update!(
    cshake::CShake256::default();
    cshake256_10 10;
    cshake256_100 100;
    cshake256_1000 1000;
    cshake256_10000 10000;
);
