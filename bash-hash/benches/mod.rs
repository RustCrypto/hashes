#![feature(test)]
extern crate test;

use bash_hash::{BashHash256, BashHash384, BashHash512};
use digest::bench_update;
use test::Bencher;

bench_update!(
    BashHash256::default();
    bash_hash256_10 10;
    bash_hash256_100 100;
    bash_hash256_1000 1000;
    bash_hash256_10000 10000;
);

bench_update!(
    BashHash384::default();
    bash_hash384_10 10;
    bash_hash384_100 100;
    bash_hash384_1000 1000;
    bash_hash384_10000 10000;
);

bench_update!(
    BashHash512::default();
    bash_hash512_10 10;
    bash_hash512_100 100;
    bash_hash512_1000 1000;
    bash_hash512_10000 10000;
);
