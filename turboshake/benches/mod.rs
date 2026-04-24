#![feature(test)]
extern crate test;

use digest::bench_update;
use test::Bencher;
use turboshake::{TurboShake128, TurboShake256};

bench_update!(
    <TurboShake128>::default();
    turboshake128_10 10;
    turboshake128_100 100;
    turboshake128_1000 1000;
    turboshake128_10000 10000;
);

bench_update!(
    <TurboShake256>::default();
    turboshake256_10 10;
    turboshake256_100 100;
    turboshake256_1000 1000;
    turboshake256_10000 10000;
);
