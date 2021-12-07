#![feature(test)]
extern crate test;

use digest::bench_update;
use fsb::{Fsb160, Fsb224, Fsb256, Fsb384, Fsb512};
use test::Bencher;

bench_update!(
    Fsb160::default();
    fsb160_10 10;
    fsb160_100 100;
    fsb160_1000 1000;
    fsb160_10000 10000;
);

bench_update!(
    Fsb224::default();
    fsb224_10 10;
    fsb224_100 100;
    fsb224_1000 1000;
    fsb224_10000 10000;
);

bench_update!(
    Fsb256::default();
    fsb256_10 10;
    fsb256_100 100;
    fsb256_1000 1000;
    fsb256_10000 10000;
);

bench_update!(
    Fsb384::default();
    fsb384_10 10;
    fsb384_100 100;
    fsb384_1000 1000;
    fsb384_10000 10000;
);

bench_update!(
    Fsb512::default();
    fsb512_10 10;
    fsb512_100 100;
    fsb512_1000 1000;
    fsb512_10000 10000;
);
