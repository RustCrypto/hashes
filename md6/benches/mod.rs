#![feature(test)]
extern crate test;

use digest::bench_update;
use md6::{Md6_128, Md6_224, Md6_256, Md6_384, Md6_512, Md6_64};
use test::Bencher;

bench_update!(
    Md6_64::default();
    md6_64_10 10;
    md6_64_100 100;
    md6_64_1000 1000;
    md6_64_10000 10000;
);

bench_update!(
    Md6_128::default();
    md6_128_10 10;
    md6_128_100 100;
    md6_128_1000 1000;
    md6_128_10000 10000;
);

bench_update!(
    Md6_224::default();
    md6_224_10 10;
    md6_224_100 100;
    md6_224_1000 1000;
    md6_224_10000 10000;
);

bench_update!(
    Md6_256::default();
    md6_256_10 10;
    md6_256_100 100;
    md6_256_1000 1000;
    md6_256_10000 10000;
);

bench_update!(
    Md6_384::default();
    md6_384_10 10;
    md6_384_100 100;
    md6_384_1000 1000;
    md6_384_10000 10000;
);

bench_update!(
    Md6_512::default();
    md6_512_10 10;
    md6_512_100 100;
    md6_512_1000 1000;
    md6_512_10000 10000;
);
