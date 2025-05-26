#![feature(test)]
extern crate test;
use test::Bencher;

digest::bench_update!(
    skein::Skein256_256::default();
    skein_256_10 10;
    skein_256_100 100;
    skein_256_1000 1000;
    skein_256_10000 10000;
);
digest::bench_update!(
    skein::Skein512_512::default();
    skein_512_10 10;
    skein_512_100 100;
    skein_512_1000 1000;
    skein_512_10000 10000;
);
digest::bench_update!(
    skein::Skein1024_1024::default();
    skein_1024_10 10;
    skein_1024_100 100;
    skein_1024_1000 1000;
    skein_1024_10000 10000;
);
