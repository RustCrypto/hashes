#![feature(test)]
extern crate test;

use belt_hash::BeltHash;
use digest::bench_update;
use test::Bencher;

bench_update!(
    BeltHash::default();
    belt_hash_10 10;
    belt_hash_100 100;
    belt_hash_1000 1000;
    belt_hash_10000 10000;
);
