#![feature(test)]
extern crate test;

use digest::bench_update;
use test::Bencher;
use tiger::{Tiger, Tiger2};

bench_update!(
    Tiger::default();
    tiger_10 10;
    tiger_100 100;
    tiger_1000 1000;
    tiger_10000 10000;
);

bench_update!(
    Tiger2::default();
    tiger2_10 10;
    tiger2_100 100;
    tiger2_1000 1000;
    tiger2_10000 10000;
);
