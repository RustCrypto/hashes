#![feature(test)]
extern crate test;

use bash_prg_hash::{BashPrgHash1282, BashPrgHash1921, BashPrgHash2562};
use digest::bench_update;
use test::Bencher;

bench_update!(
    BashPrgHash1282::default();
    bash_prg_hash1282_10 10;
    bash_prg_hash1282_100 100;
    bash_prg_hash1282_1000 1000;
    bash_prg_hash1282_10000 10000;
);

bench_update!(
    BashPrgHash1921::default();
    bash_prg_hash1921_10 10;
    bash_prg_hash1921_100 100;
    bash_prg_hash1921_1000 1000;
    bash_prg_hash1921_10000 10000;
);

bench_update!(
    BashPrgHash2562::default();
    bash_prg_hash2562_10 10;
    bash_prg_hash2562_100 100;
    bash_prg_hash2562_1000 1000;
    bash_prg_hash2562_10000 10000;
);
