#![feature(test)]
extern crate test;

use digest::bench_update;
use groestl::{Groestl256, Groestl512};
use test::Bencher;

bench_update!(
    Groestl256::default();
    groestl256_10 10;
    groestl256_100 100;
    groestl256_1000 1000;
    groestl256_10000 10000;
);

bench_update!(
    Groestl512::default();
    groestl512_10 10;
    groestl512_100 100;
    groestl512_1000 1000;
    groestl512_10000 10000;
);
