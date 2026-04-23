#![feature(test)]
extern crate test;

use digest::bench_update;
use test::Bencher;

bench_update!(
    ascon_xof128::AsconXof128::default();
    ascon_xof128_10 10;
    ascon_xof128_100 100;
    ascon_xof128_1000 1000;
    ascon_xof128_10000 10000;
);
