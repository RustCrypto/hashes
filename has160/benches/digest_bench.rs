#![feature(test)]
extern crate test;

use digest::bench_update;
use has160::Has160;
use test::Bencher;

bench_update!(
    Has160::default();
    has160_10      10;
    has160_100     100;
    has160_1000    1000;
    has160_10000   10000;
    has160_100000  100000;
);
