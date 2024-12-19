#![feature(test)]
extern crate test;

use digest::bench_update;
use digest::crypto_common::KeyInit;
use multimixer_128::Multimixer;
use test::Bencher;
//Multimixer::from_core(MultimixerCore::dummy_bencher());
bench_update!(
    Multimixer::new(&[0u8;32].into());
    multimixer_10 10;
    multimixer_100 100;
    multimixer_1000 1000;
    multimixer_10000 10000;
);
