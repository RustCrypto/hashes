#![no_std]
#![feature(test)]

extern crate test;

use digest::Update;
use test::Bencher;

digest::bench!(bench1_10, k12::KangarooTwelve, 10);
digest::bench!(bench2_100, k12::KangarooTwelve, 100);
digest::bench!(bench3_1000, k12::KangarooTwelve, 1000);
digest::bench!(bench4_10000, k12::KangarooTwelve, 10000);
